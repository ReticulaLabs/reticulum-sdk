//! Regression guards for the interface / FD leak on the production router
//!
//! A leaked interface is one whose `stop` token is never cancelled on
//! disconnect, so it stays "active" forever (holding a socket FD) even
//! though its peer is gone.  These tests exercise the *clean* disconnect
//! path for per-connection child interfaces spawned by a TCP server and a
//! Backbone server: a peer connects, the server spawns a child interface,
//! the peer disconnects, and the child's `stop` must be cancelled so the
//! interface is reclaimed (removed from `active_interface_addresses`).

use std::net::TcpListener;
use std::sync::Once;
use std::time::Duration;

use getrandom::SysRng;
use rand_core::UnwrapErr;
use reticulum_sdk::{
    identity::PrivateIdentity,
    iface::{backbone::BackboneServer, tcp_server::TcpServer},
    transport::{Transport, TransportConfig},
};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    });
}

fn local_tcp_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(listener.local_addr().unwrap().port() >= 1024);
    listener
}

/// Poll the number of *active* (non-cancelled) interfaces until it reaches
/// `expected`, or until `timeout` elapses.  Active count is derived from
/// `active_interface_addresses()`, which already filters out interfaces
/// whose `stop` token has been cancelled, so a leaked interface keeps the
/// count inflated.
async fn wait_for_iface_count(
    transport: &Transport,
    expected: usize,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let count = transport
            .iface_manager()
            .lock()
            .await
            .active_interface_addresses()
            .len();
        if count == expected {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            log::warn!(
                "wait_for_iface_count: timeout waiting for {} active ifaces (currently {})",
                expected,
                count
            );
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn disconnected_tcp_clients_do_not_leak_interfaces() {
    setup();

    let listener = local_tcp_listener();
    let server_addr = listener.local_addr().unwrap().to_string();

    let mut rng = UnwrapErr(SysRng);
    let server_transport = Transport::new(TransportConfig::new(
        "tcp-leak-server",
        &PrivateIdentity::new_from_rand(&mut rng),
        true,
    ));
    server_transport
        .iface_manager()
        .lock()
        .await
        .spawn(
            TcpServer::new_from_listener(
                server_addr.clone(),
                listener,
                server_transport.iface_manager(),
            ),
            TcpServer::spawn,
        );

    // Baseline: only the configured server interface is active.
    assert!(wait_for_iface_count(&server_transport, 1, Duration::from_secs(5)).await);

    // A peer connects: the server spawns a per-connection child interface.
    let peer = std::net::TcpStream::connect(server_addr.as_str()).unwrap();
    assert!(
        wait_for_iface_count(&server_transport, 2, Duration::from_secs(5)).await,
        "server did not spawn a child interface for the new connection"
    );

    // Peer disconnects.  The child's rx task reads EOF, cancels its `stop`,
    // and the interface is reclaimed — it must not linger as a leak.
    drop(peer);
    assert!(
        wait_for_iface_count(&server_transport, 1, Duration::from_secs(5)).await,
        "disconnected TCP client leaked an interface (active count did not return to baseline)"
    );
}

#[tokio::test]
async fn disconnected_backbone_clients_do_not_leak_interfaces() {
    setup();

    let listener = local_tcp_listener();
    let server_addr = listener.local_addr().unwrap().to_string();

    let mut rng = UnwrapErr(SysRng);
    let server_transport = Transport::new(TransportConfig::new(
        "backbone-leak-server",
        &PrivateIdentity::new_from_rand(&mut rng),
        true,
    ));
    server_transport
        .iface_manager()
        .lock()
        .await
        .spawn(
            BackboneServer::new_from_listener(
                server_addr.clone(),
                listener,
                server_transport.iface_manager(),
            ),
            BackboneServer::spawn,
        );

    // Baseline: only the configured server interface is active.
    assert!(wait_for_iface_count(&server_transport, 1, Duration::from_secs(5)).await);

    // A peer connects: the server spawns a per-connection child interface.
    let peer = std::net::TcpStream::connect(server_addr.as_str()).unwrap();
    assert!(
        wait_for_iface_count(&server_transport, 2, Duration::from_secs(5)).await,
        "backbone server did not spawn a child interface for the new connection"
    );

    // Peer disconnects.  The child's rx task reads EOF, cancels its `stop`,
    // and the interface is reclaimed — it must not linger as a leak.
    drop(peer);
    assert!(
        wait_for_iface_count(&server_transport, 1, Duration::from_secs(5)).await,
        "disconnected backbone client leaked an interface (active count did not return to baseline)"
    );
}
