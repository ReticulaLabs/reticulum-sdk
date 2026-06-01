use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum_sdk::{
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    transport::{DiscoveryInterfaceConfig, Transport, TransportConfig},
};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    });
}

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str]) -> (Transport, reticulum_sdk::hash::AddressHash) {
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

    let server_iface = transport.iface_manager().lock().await.spawn(
        TcpServer::new(server_addr, transport.iface_manager()),
        TcpServer::spawn,
    );

    for &addr in client_addr {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(addr), TcpClient::spawn);
    }

    (transport, server_iface)
}

#[tokio::test]
async fn discovery_announce_roundtrip() {
    setup();

    let (transport_a, server_iface_a) = build_transport("a", "127.0.0.1:8581", &[]).await;
    let (transport_b, _server_iface_b) =
        build_transport("b", "127.0.0.1:8582", &["127.0.0.1:8581"]).await;

    transport_a
        .register_discoverable_interface(
            server_iface_a,
            DiscoveryInterfaceConfig::tcp_server("Rust Test Node", "127.0.0.1", 8581),
        )
        .await;

    let mut discovery_rx = transport_b.recv_discovery();

    time::sleep(Duration::from_secs(2)).await;
    transport_a
        .send_discovery_announce(&server_iface_a)
        .await
        .unwrap();

    let discovered = time::timeout(Duration::from_secs(10), discovery_rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(discovered.interface_type, "TCPServerInterface");
    assert_eq!(discovered.name, "Rust Test Node");
    assert_eq!(discovered.reachable_on.as_deref(), Some("127.0.0.1"));
    assert_eq!(discovered.port, Some(8581));
    assert!(discovered.stamp_value >= 14);
    assert!(discovered.config_entry.is_some());
}
