//! macOS mDNS discovery via the Bonjour DNS-SD API (`dns_sd.h`).
//!
//! ## Why this file exists
//!
//! On macOS, the system daemon `mDNSResponder` registers itself as the sole
//! handler for the mDNS multicast group (224.0.0.251:5353) on every physical
//! network interface (WiFi, Ethernet).  Because `mDNSResponder` does **not**
//! set `SO_REUSEPORT` on its socket, the kernel only delivers incoming
//! multicast packets to it — any raw UDP socket we open on the same interface
//! receives nothing, even if we join the same multicast group with
//! `SO_REUSEPORT`.  The raw-socket path in `mdns.rs` therefore works on
//! loopback (where `mDNSResponder` does not interfere) but silently produces
//! no responses on WiFi or Ethernet.
//!
//! Apple's documented solution is the `dns_sd.h` API (also called Bonjour or
//! DNS-SD), which lets applications submit queries directly to
//! `mDNSResponder` and receive answers via callbacks.  This module wraps that
//! API and exposes the same `Stream<Item = Result<Response, Error>>` surface
//! that the rest of the crate expects.
//!
//! ## DNS-SD query sequence
//!
//! A full service lookup requires three chained operations:
//!
//! 1. **`DNSServiceBrowse`** — find all instances of a service type on the
//!    network (e.g. `_rpc._tcp`).  For each instance found, the callback
//!    receives the instance name, service type, and domain.
//!
//! 2. **`DNSServiceResolve`** — for a specific instance, retrieve its fully-
//!    qualified name, target hostname, port, and TXT records.
//!
//! 3. **`DNSServiceGetAddrInfo`** — resolve the target hostname to an IPv4
//!    address.
//!
//! Each operation has its own `DNSServiceRef` and file descriptor.  We poll
//! each fd with `select(2)` and call `DNSServiceProcessResult` when data is
//! available, which drives the callbacks synchronously on the calling thread.
//!
//! ## Threading model
//!
//! All DNS-SD polling runs on a dedicated `std::thread` so it never blocks
//! the async runtime.  Results are forwarded to the caller via an
//! `async_std::channel`, whose sender is written from the thread using
//! `async_std::task::block_on` (safe here because we are not inside an async
//! executor — we are in a plain `std::thread::spawn` context, and the channel
//! is unbounded so the send completes immediately without suspending).

use crate::{Record, RecordKind, Response};
use async_std::channel;
use dns_parser::Class;
use futures_core::Stream;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::os::raw::{c_char, c_int, c_void};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// DNS-SD constants
// ---------------------------------------------------------------------------

/// Returned by DNS-SD functions on success.
const NO_ERR: i32 = 0;
/// Pass as `interfaceIndex` to search all interfaces.
const IF_ANY: u32 = 0;
/// Request only IPv4 addresses from `DNSServiceGetAddrInfo`.
const PROTO_V4: u32 = 0x01;
/// Set in the `flags` argument of a browse callback when a service is being
/// added (as opposed to removed).
const FLAGS_ADD: u32 = 0x2;

// Opaque handle returned by all DNS-SD operations.
type Ref = *mut c_void;
type Flags = u32;
type Err = i32;

// ---------------------------------------------------------------------------
// Raw sockaddr representation
// ---------------------------------------------------------------------------

/// Opaque buffer large enough for any `sockaddr` variant.
///
/// On macOS, the layout is:
/// - byte 0: `sa_len`
/// - byte 1: `sa_family` (2 = `AF_INET`, 30 = `AF_INET6`)
/// - bytes 4–7: IPv4 address (when `sa_family == 2`)
#[repr(C)]
struct RawSockaddr {
    _bytes: [u8; 128],
}

// ---------------------------------------------------------------------------
// FFI declarations
// ---------------------------------------------------------------------------

#[link(name = "System", kind = "dylib")]
extern "C" {
    /// Begin browsing for instances of a service type.  The callback fires
    /// once per discovered (or removed) instance and continues until the ref
    /// is deallocated.
    fn DNSServiceBrowse(
        sd: *mut Ref,
        fl: Flags,
        iface: u32,
        regtype: *const c_char, // e.g. "_rpc._tcp"
        domain: *const c_char,  // e.g. "local." — NULL defaults to local
        cb: unsafe extern "C" fn(Ref, Flags, u32, Err, *const c_char, *const c_char, *const c_char, *mut c_void),
        ctx: *mut c_void,
    ) -> Err;

    /// Resolve a specific service instance to a hostname, port, and TXT record.
    /// The callback fires once (or a few times) then can be deallocated.
    fn DNSServiceResolve(
        sd: *mut Ref,
        fl: Flags,
        iface: u32,
        name: *const c_char,    // instance name from browse callback
        regtype: *const c_char,
        domain: *const c_char,
        cb: unsafe extern "C" fn(Ref, Flags, u32, Err, *const c_char, *const c_char, u16, u16, *const u8, *mut c_void),
        ctx: *mut c_void,
    ) -> Err;

    /// Resolve a hostname to an IP address.  The callback may fire multiple
    /// times (once per address family / interface) until deallocated.
    fn DNSServiceGetAddrInfo(
        sd: *mut Ref,
        fl: Flags,
        iface: u32,
        proto: u32,             // PROTO_V4 to request only IPv4
        host: *const c_char,
        cb: unsafe extern "C" fn(Ref, Flags, u32, Err, *const c_char, *const RawSockaddr, u32, *mut c_void),
        ctx: *mut c_void,
    ) -> Err;

    /// Returns the Unix file descriptor associated with a `DNSServiceRef`.
    /// Call `select(2)` on this fd to wait for available data, then call
    /// `DNSServiceProcessResult` to dispatch pending callbacks.
    fn DNSServiceRefSockFD(sd: Ref) -> c_int;

    /// Read one result from the daemon and invoke the corresponding callback.
    /// Must only be called when the fd returned by `DNSServiceRefSockFD` is
    /// readable.
    fn DNSServiceProcessResult(sd: Ref) -> Err;

    /// Cancel an operation and release its resources.  For shared connections
    /// this cancels only the sub-operation; for standalone refs it closes the
    /// connection.
    fn DNSServiceRefDeallocate(sd: Ref);
}

// ---------------------------------------------------------------------------
// Callback implementations
// ---------------------------------------------------------------------------

/// Browse callback.  Appends newly-added service instances to the `Vec`
/// passed as `ctx`.  Removal events (flag `FLAGS_ADD` not set) are ignored.
unsafe extern "C" fn on_browse(
    _: Ref,
    fl: Flags,
    _: u32,
    err: Err,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    ctx: *mut c_void,
) {
    if err != NO_ERR || fl & FLAGS_ADD == 0 {
        return;
    }
    let v = &mut *(ctx as *mut Vec<(String, String, String)>);
    v.push((cstr(name), cstr(regtype), cstr(domain)));
}

/// Data collected from a successful `DNSServiceResolve` callback.
struct Resolved {
    /// Fully-qualified service instance name, e.g. `myrobot._rpc._tcp.local.`
    fullname: String,
    /// Target hostname to pass to `DNSServiceGetAddrInfo`, e.g. `myrobot.local.`
    host: String,
    /// Service port in host byte order.
    port: u16,
    /// Parsed TXT record strings (e.g. `["grpc=true"]`).
    txt: Vec<String>,
}

/// Resolve callback.  Writes the result into the `Option<Resolved>` pointed
/// to by `ctx`.  Only the first successful call is recorded.
unsafe extern "C" fn on_resolve(
    _: Ref,
    _: Flags,
    _: u32,
    err: Err,
    fullname: *const c_char,
    host: *const c_char,
    port: u16,       // network byte order
    txtlen: u16,
    txtrec: *const u8,
    ctx: *mut c_void,
) {
    if err != NO_ERR {
        return;
    }
    *(ctx as *mut Option<Resolved>) = Some(Resolved {
        fullname: cstr(fullname),
        host: cstr(host),
        port: u16::from_be(port),
        txt: parse_txt(txtrec, txtlen as usize),
    });
}

/// AddrInfo callback.  Records the first non-unspecified IPv4 address into
/// the `Option<Ipv4Addr>` pointed to by `ctx`.
unsafe extern "C" fn on_addr(
    _: Ref,
    _: Flags,
    _: u32,
    err: Err,
    _: *const c_char,
    addr: *const RawSockaddr,
    _: u32,
    ctx: *mut c_void,
) {
    if err != NO_ERR || addr.is_null() {
        return;
    }
    let b = (*addr)._bytes;
    // sa_family is byte 1; AF_INET == 2 on macOS
    if b[1] != 2 {
        return;
    }
    let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
    if !ip.is_unspecified() {
        *(ctx as *mut Option<Ipv4Addr>) = Some(ip);
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Convert a nul-terminated C string pointer to a Rust `String`.
///
/// # Safety
/// `p` must be a valid, nul-terminated pointer for the duration of this call.
unsafe fn cstr(p: *const c_char) -> String {
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// Parse a DNS TXT record from its wire format.
///
/// The wire format is a sequence of length-prefixed strings:
/// `[len][data][len][data]...` where each `len` is a single byte.
fn parse_txt(data: *const u8, len: usize) -> Vec<String> {
    if data.is_null() || len == 0 {
        return vec![];
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let mut out = vec![];
    let mut i = 0;
    while i < bytes.len() {
        let n = bytes[i] as usize;
        i += 1;
        if i + n > bytes.len() {
            break;
        }
        if n > 0 {
            out.push(String::from_utf8_lossy(&bytes[i..i + n]).into_owned());
        }
        i += n;
    }
    out
}

/// Block until `fd` is readable or `timeout` elapses.  Returns `true` if the
/// fd became readable.
///
/// We implement the `select(2)` call directly to avoid adding a `libc`
/// dependency.  On macOS (little-endian), the `fd_set` bit layout makes the
/// byte `read_fds[fd/8]` hold bit `fd%8` for fd < 1024, which matches the
/// kernel's `FD_SET` macro behaviour.
fn wait_readable(fd: c_int, timeout: Duration) -> bool {
    if fd < 0 || fd >= 1024 {
        return false;
    }
    unsafe {
        let mut fds = [0u8; 128]; // fd_set: 128 bytes = 1024 bits
        fds[(fd / 8) as usize] |= 1 << (fd % 8);

        // struct timeval on macOS 64-bit: { long tv_sec; int tv_usec; }
        #[repr(C)]
        struct TV {
            sec: i64,
            usec: i32,
        }
        extern "C" {
            fn select(n: c_int, r: *mut u8, w: *mut u8, e: *mut u8, t: *mut TV) -> c_int;
        }
        let mut tv = TV {
            sec: timeout.as_secs() as i64,
            usec: timeout.subsec_micros() as i32,
        };
        select(
            fd + 1,
            fds.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        ) > 0
    }
}

/// Poll `sd`'s fd with a 100 ms granularity until `done()` returns `true`
/// or `timeout` elapses.
fn poll_until(sd: Ref, done: impl Fn() -> bool, timeout: Duration) {
    let fd = unsafe { DNSServiceRefSockFD(sd) };
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            break;
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            break;
        }
        if wait_readable(fd, rem.min(Duration::from_millis(100))) {
            if unsafe { DNSServiceProcessResult(sd) } != NO_ERR {
                break;
            }
        }
    }
}

/// Split a combined service name like `"_rpc._tcp.local"` into the
/// `(regtype, domain)` pair that `DNSServiceBrowse` expects: `("_rpc._tcp",
/// "local.")`.
fn split_svc(svc: &str) -> (String, String) {
    let s = svc.trim_end_matches('.');
    match s.rfind('.') {
        Some(p) => (s[..p].to_string(), format!("{}.", &s[p + 1..])),
        None => (s.to_string(), "local.".to_string()),
    }
}

/// Strip a trailing dot from a DNS name (DNS-SD returns fully-qualified names
/// with a trailing dot; our `Response` types do not use them).
fn nodot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

fn cstring(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

// ---------------------------------------------------------------------------
// DNS-SD operations (synchronous, called from the browse thread)
// ---------------------------------------------------------------------------

/// Run `DNSServiceResolve` for the given instance and wait up to 2 seconds
/// for the callback to fire.
fn do_resolve(name: &str, rt: &str, dom: &str) -> Option<Resolved> {
    let mut res: Option<Resolved> = None;
    unsafe {
        let mut sd: Ref = std::ptr::null_mut();
        if DNSServiceResolve(
            &mut sd,
            0,
            IF_ANY,
            cstring(name)?.as_ptr(),
            cstring(rt)?.as_ptr(),
            cstring(dom)?.as_ptr(),
            on_resolve,
            &mut res as *mut _ as *mut c_void,
        ) != NO_ERR
        {
            return None;
        }
        poll_until(sd, || res.is_some(), Duration::from_secs(2));
        DNSServiceRefDeallocate(sd);
    }
    if res.is_none() {
        log::debug!("mDNS(DNS-SD): resolve timed out for {name}");
    }
    res
}

/// Run `DNSServiceGetAddrInfo` for the given hostname and wait up to 2 seconds
/// for the first IPv4 address callback.
fn do_addr(host: &str) -> Option<Ipv4Addr> {
    let mut res: Option<Ipv4Addr> = None;
    unsafe {
        let mut sd: Ref = std::ptr::null_mut();
        if DNSServiceGetAddrInfo(
            &mut sd,
            0,
            IF_ANY,
            PROTO_V4,
            cstring(host)?.as_ptr(),
            on_addr,
            &mut res as *mut _ as *mut c_void,
        ) != NO_ERR
        {
            return None;
        }
        poll_until(sd, || res.is_some(), Duration::from_secs(2));
        DNSServiceRefDeallocate(sd);
    }
    if res.is_none() {
        log::debug!("mDNS(DNS-SD): addrinfo timed out for {host}");
    }
    res
}

/// Build a `Response` whose record layout matches what the rest of this crate
/// and callers in `rust-utils` expect:
///
/// - **answers**: one `PTR` record with `name == service_name`.  The stream
///   filter in `discover.rs` requires at least one such record, and
///   `Response::hostname()` returns its value, which `get_addr_from_interface`
///   uses to match the robot name against candidate URIs.
/// - **additional**: `A` record (IP), `SRV` record (port), `TXT` record
///   (capability flags such as `"grpc"` / `"webrtc"`).
fn build_response(svc: &str, fullname: &str, ip: Ipv4Addr, port: u16, txt: &[String]) -> Response {
    Response {
        answers: vec![Record {
            name: svc.to_string(),
            class: Class::IN,
            ttl: 120,
            kind: RecordKind::PTR(fullname.to_string()),
        }],
        nameservers: vec![],
        additional: vec![
            Record {
                name: fullname.to_string(),
                class: Class::IN,
                ttl: 120,
                kind: RecordKind::A(ip),
            },
            Record {
                name: fullname.to_string(),
                class: Class::IN,
                ttl: 120,
                kind: RecordKind::SRV {
                    priority: 0,
                    weight: 0,
                    port,
                    target: fullname.to_string(),
                },
            },
            Record {
                name: fullname.to_string(),
                class: Class::IN,
                ttl: 120,
                kind: RecordKind::TXT(txt.to_vec()),
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Browse thread
// ---------------------------------------------------------------------------

/// Main loop for the browse thread.  Runs `DNSServiceBrowse` indefinitely,
/// resolving each newly-discovered instance and forwarding a `Response` to
/// the caller's channel.
///
/// Already-seen instance names are tracked in `seen` to avoid emitting
/// duplicate responses for the same device.  If the channel's receiver is
/// dropped (caller went away), the thread exits cleanly.
fn run_browse(svc: String, tx: channel::Sender<Response>) {
    let (rt, dom) = split_svc(&svc);
    let c_rt = match cstring(&rt) {
        Some(s) => s,
        None => return,
    };
    let c_dom = match cstring(&dom) {
        Some(s) => s,
        None => return,
    };

    // Browse results accumulate here inside the DNS-SD callbacks.
    let mut pending: Vec<(String, String, String)> = vec![];
    // Deduplication: skip instances we've already resolved and sent.
    let mut seen: HashSet<String> = HashSet::new();

    unsafe {
        let mut sd: Ref = std::ptr::null_mut();
        if DNSServiceBrowse(
            &mut sd,
            0,
            IF_ANY,
            c_rt.as_ptr(),
            c_dom.as_ptr(),
            on_browse,
            &mut pending as *mut Vec<(String, String, String)> as *mut c_void,
        ) != NO_ERR
        {
            log::debug!("mDNS(DNS-SD): DNSServiceBrowse failed");
            return;
        }

        let fd = DNSServiceRefSockFD(sd);

        loop {
            // Poll for new browse events with a short timeout so we can also
            // process any instances that arrived while we were resolving.
            if wait_readable(fd, Duration::from_millis(100))
                && DNSServiceProcessResult(sd) != NO_ERR
            {
                break;
            }

            // For each newly found instance, run the resolve + addrinfo chain.
            // We do this inline (blocking the browse poll briefly) because
            // resolve and addrinfo against a local mDNSResponder typically
            // complete in well under 100 ms.
            for (name, nrt, ndom) in pending.drain(..) {
                if seen.contains(&name) {
                    continue;
                }
                seen.insert(name.clone());

                let r = match do_resolve(&name, &nrt, &ndom) {
                    Some(r) => r,
                    None => continue,
                };
                let ip = match do_addr(&r.host) {
                    Some(ip) => ip,
                    None => continue,
                };

                let fullname = nodot(&r.fullname).to_string();
                log::debug!("mDNS(DNS-SD): resolved {name} → {ip}:{}", r.port);

                let resp = build_response(&svc, &fullname, ip, r.port, &r.txt);
                // block_on is safe: we are in a std::thread::spawn context.
                if async_std::task::block_on(tx.send(resp)).is_err() {
                    // Receiver dropped — caller is done; clean up and exit.
                    DNSServiceRefDeallocate(sd);
                    return;
                }
            }
        }

        DNSServiceRefDeallocate(sd);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns an async stream of mDNS `Response` objects for `svc` (e.g.
/// `"_rpc._tcp.local"`) using the Bonjour DNS-SD API.
///
/// This replaces the raw-socket path used on other platforms and works
/// correctly on macOS even when WiFi is active.  The `_interval` parameter
/// is accepted for API compatibility but is ignored — `mDNSResponder` handles
/// re-querying internally.
pub fn macos_listen(svc: String, _interval: Duration) -> impl Stream<Item = Result<Response, crate::Error>> {
    let (tx, rx) = channel::unbounded::<Response>();
    std::thread::spawn(move || run_browse(svc, tx));
    async_stream::stream! {
        while let Ok(resp) = rx.recv().await {
            yield Ok(resp);
        }
    }
}
