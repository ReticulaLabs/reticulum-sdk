use std::net::{SocketAddr, TcpListener};
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

fn free_local_addrs(count: usize) -> Vec<SocketAddr> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();

    listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect()
}

async fn build_transport(
    name: &str,
    server_addr: &str,
    client_addr: &[&str],
) -> (Transport, reticulum_sdk::hash::AddressHash) {
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

    let addrs = free_local_addrs(2);
    let addr_a = addrs[0].to_string();
    let addr_b = addrs[1].to_string();
    let port_a = addrs[0].port();

    let (transport_a, server_iface_a) = build_transport("a", &addr_a, &[]).await;
    let (transport_b, _server_iface_b) = build_transport("b", &addr_b, &[addr_a.as_str()]).await;

    transport_a
        .register_discoverable_interface(
            server_iface_a,
            DiscoveryInterfaceConfig::tcp_server("Rust Test Nøde 測試", "127.0.0.1", port_a),
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
    assert_eq!(discovered.name, "Rust Test Nøde 測試");
    assert_eq!(discovered.reachable_on.as_deref(), Some("127.0.0.1"));
    assert_eq!(discovered.port, Some(port_a));
    assert!(discovered.stamp_value >= 14);
    assert!(discovered.config_entry.is_some());
}

#[tokio::test]
async fn shared_instance_client_receives_network_discovery_announces() {
    setup();

    let addrs = free_local_addrs(4);
    let shared_port = addrs[0].port();
    let server_addr = addrs[1].to_string();
    let remote_addr = addrs[2].to_string();
    let remote_port = addrs[2].port();
    let control_port = addrs[3].port();

    let mut server_config = TransportConfig::new(
        "shared-server",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    );
    server_config.set_share_instance(true);
    server_config.set_shared_instance_port(shared_port);
    server_config.set_instance_control_port(control_port);
    let server = Transport::new(server_config);
    server.iface_manager().lock().await.spawn(
        TcpServer::new(&server_addr, server.iface_manager()),
        TcpServer::spawn,
    );

    let mut client_config = TransportConfig::new(
        "shared-client",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    );
    client_config.set_share_instance(true);
    client_config.set_shared_instance_port(shared_port);
    let client = Transport::new(client_config);
    let mut discovery_rx = client.recv_discovery();

    let (remote, remote_server_iface) =
        build_transport("remote", &remote_addr, &[server_addr.as_str()]).await;
    remote
        .register_discoverable_interface(
            remote_server_iface,
            DiscoveryInterfaceConfig::tcp_server("Remote Discovery", "127.0.0.1", remote_port),
        )
        .await;

    time::sleep(Duration::from_secs(2)).await;
    remote
        .send_discovery_announce(&remote_server_iface)
        .await
        .unwrap();

    let discovered = time::timeout(Duration::from_secs(10), discovery_rx.recv())
        .await
        .expect("shared-instance client did not receive discovery announce")
        .unwrap();

    assert_eq!(discovered.name, "Remote Discovery");
    assert_eq!(discovered.reachable_on.as_deref(), Some("127.0.0.1"));
    assert_eq!(discovered.port, Some(remote_port));
}
