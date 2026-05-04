//! Utilities for discovering devices on the LAN.
//!
//! Examples
//!
//! ```rust,no_run
//! use futures_util::{pin_mut, stream::StreamExt};
//! use mdns::{Error, Record, RecordKind};
//! use std::time::Duration;
//!
//! const SERVICE_NAME: &'static str = "_googlecast._tcp.local";
//!
//! #[async_std::main]
//! async fn main() -> Result<(), Error> {
//!     let stream = mdns::discover::all(SERVICE_NAME, Duration::from_secs(15))?.listen();
//!     pin_mut!(stream);
//!
//!     while let Some(Ok(response)) = stream.next().await {
//!         println!("{:?}", response);
//!     }
//!
//!     Ok(())
//! }
//! ```

use crate::{Error, Response};
use crate::mdns::{mDNSListener, mDNSSender, mdns_interface, mdns_interface_with_loopback};
use futures_core::Stream;
use futures_util::{stream::select, StreamExt};
use std::net::Ipv4Addr;
use std::time::Duration;

/// A multicast DNS discovery request.
///
/// This represents a single lookup of a single service name.
///
/// This object can be iterated over to yield the received mDNS responses.
pub struct Discovery {
    service_name: String,

    /// Whether we should ignore empty responses.
    ignore_empty: bool,

    /// The interval we should send mDNS queries.
    send_request_interval: Duration,

    /// Raw UDP socket backend.
    ///
    /// On non-macOS: always `Some`.
    ///
    /// On macOS: `Some` only when `interface_addr` is loopback (127.0.0.1).
    /// mDNSResponder does not interfere with loopback multicast, so the raw
    /// socket path works there.  For physical interfaces (WiFi, Ethernet),
    /// mDNSResponder intercepts multicast and raw sockets receive nothing; in
    /// that case `raw` is `None` and [`listen`] uses the DNS-SD path instead.
    raw: Option<(mDNSSender, mDNSListener)>,
}

/// Gets an iterator over all responses for a given service on all interfaces.
pub fn all<S>(service_name: S, mdns_query_interval: Duration) -> Result<Discovery, Error>
where
    S: AsRef<str>,
{
    interface(service_name, mdns_query_interval, Ipv4Addr::new(0, 0, 0, 0))
}

/// Gets an iterator over all responses for a given service on all interfaces with loopback
/// functionality.
pub fn all_with_loopback<S>(
    service_name: S,
    mdns_query_interval: Duration,
) -> Result<Discovery, Error>
where
    S: AsRef<str>,
{
    interface_with_loopback(service_name, mdns_query_interval, Ipv4Addr::new(0, 0, 0, 0))
}

/// Gets an iterator over all responses for a given service on a given interface.
///
/// On macOS with a non-loopback interface the `interface_addr` is accepted for
/// API compatibility but is unused — the Bonjour DNS-SD backend searches all
/// physical interfaces.
pub fn interface<S>(
    service_name: S,
    mdns_query_interval: Duration,
    interface_addr: Ipv4Addr,
) -> Result<Discovery, Error>
where
    S: AsRef<str>,
{
    let service_name = service_name.as_ref().to_string();
    let raw = make_raw_socket(&service_name, interface_addr, false)?;
    Ok(Discovery { service_name, raw, ignore_empty: true, send_request_interval: mdns_query_interval })
}

/// Gets an iterator over all responses for a given service on a given interface with loopback
/// functionality.
///
/// On macOS with a non-loopback interface the `interface_addr` is accepted for
/// API compatibility but is unused — the Bonjour DNS-SD backend searches all
/// physical interfaces.
pub fn interface_with_loopback<S>(
    service_name: S,
    mdns_query_interval: Duration,
    interface_addr: Ipv4Addr,
) -> Result<Discovery, Error>
where
    S: AsRef<str>,
{
    let service_name = service_name.as_ref().to_string();
    let raw = make_raw_socket(&service_name, interface_addr, true)?;
    Ok(Discovery { service_name, raw, ignore_empty: true, send_request_interval: mdns_query_interval })
}

/// Create the raw UDP socket backend for `interface_addr`.
///
/// On macOS, the raw socket is only created for the loopback interface
/// (127.0.0.1) because `mDNSResponder` intercepts multicast on physical
/// interfaces.  For any other address on macOS, `None` is returned and the
/// caller should fall back to DNS-SD.
///
/// On all other platforms a raw socket is always created.
fn make_raw_socket(
    service_name: &str,
    interface_addr: Ipv4Addr,
    with_loopback: bool,
) -> Result<Option<(mDNSSender, mDNSListener)>, Error> {
    #[cfg(target_os = "macos")]
    if !interface_addr.is_loopback() {
        // Physical interface on macOS: mDNSResponder owns the multicast group.
        // Return None to signal that the caller should use DNS-SD instead.
        return Ok(None);
    }

    let (listener, sender) = if with_loopback {
        mdns_interface_with_loopback(service_name.to_string(), interface_addr)?
    } else {
        mdns_interface(service_name.to_string(), interface_addr)?
    };
    Ok(Some((sender, listener)))
}

impl Discovery {
    /// Sets whether or not we should ignore empty responses.
    ///
    /// Defaults to `true`.
    pub fn ignore_empty(mut self, ignore: bool) -> Self {
        self.ignore_empty = ignore;
        self
    }

    /// Returns a stream of mDNS responses for this discovery request.
    ///
    /// The implementation is chosen at runtime based on the interface type:
    ///
    /// - **Raw socket** (all platforms for loopback; non-macOS for all
    ///   interfaces): sends periodic mDNS queries and yields every DNS
    ///   response that contains an answer record matching the service name.
    ///
    /// - **Bonjour DNS-SD** (macOS non-loopback only): queries
    ///   `mDNSResponder` directly, bypassing the raw socket restriction on
    ///   physical interfaces.  See [`crate::macos`] for details.
    pub fn listen(self) -> impl Stream<Item = Result<Response, Error>> {
        let ignore_empty = self.ignore_empty;
        let service_name = self.service_name.clone();
        let send_request_interval = self.send_request_interval;

        // Use an internal channel so both the raw-socket path and the DNS-SD
        // path produce the same Stream type regardless of platform.
        let (tx, rx) = async_std::channel::unbounded::<Result<Response, Error>>();

        if let Some((sender, listener)) = self.raw {
            // Raw socket path.
            let svc = service_name.clone();
            async_std::task::spawn(raw_socket_task(
                sender, listener, svc, ignore_empty, send_request_interval, tx,
            ));
        } else {
            // DNS-SD path (macOS physical interfaces only).
            #[cfg(target_os = "macos")]
            {
                let inner = crate::macos::macos_listen(service_name, send_request_interval);
                async_std::task::spawn(async move {
                    futures_util::pin_mut!(inner);
                    while let Some(item) = inner.next().await {
                        if tx.send(item).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }

        async_stream::stream! {
            while let Ok(item) = rx.recv().await {
                yield item;
            }
        }
    }
}

/// Drive the raw socket sender/listener pair and forward matching responses to `tx`.
async fn raw_socket_task(
    sender: mDNSSender,
    listener: mDNSListener,
    service_name: String,
    ignore_empty: bool,
    send_request_interval: Duration,
    tx: async_std::channel::Sender<Result<Response, Error>>,
) {
    let response_stream = listener.listen().map(StreamResult::Response);

    let interval_stream = async_std::stream::interval(send_request_interval).map(move |_| {
        let mut s = sender.clone();
        async_std::task::spawn(async move {
            let _ = s.send_request().await;
        });
        StreamResult::Interval
    });

    let stream = select(response_stream, interval_stream);
    futures_util::pin_mut!(stream);

    while let Some(result) = stream.next().await {
        let response = match result {
            StreamResult::Interval => continue,
            StreamResult::Response(r) => r,
        };
        let should_send = match &response {
            Ok(resp) => {
                (!resp.is_empty() || !ignore_empty)
                    && resp.answers.iter().any(|record| record.name == service_name)
            }
            Err(_) => true,
        };
        if should_send && tx.send(response).await.is_err() {
            break;
        }
    }
}

enum StreamResult {
    Interval,
    Response(Result<Response, Error>),
}
