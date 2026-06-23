use std::net::TcpListener;
use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum_sdk::{
    destination::DestinationName,
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

fn local_tcp_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(listener.local_addr().unwrap().port() >= 1024);
    listener
}

async fn build_transport(
    name: &str,
    server_listener: TcpListener,
    client_addr: &[&str],
) -> (Transport, reticulum_sdk::hash::AddressHash) {
    let server_addr = server_listener.local_addr().unwrap().to_string();
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

    let server_iface = transport.iface_manager().lock().await.spawn(
        TcpServer::new_from_listener(server_addr, server_listener, transport.iface_manager()),
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

    let listener_a = local_tcp_listener();
    let listener_b = local_tcp_listener();
    let addr_a = listener_a.local_addr().unwrap().to_string();
    let port_a = listener_a.local_addr().unwrap().port();

    let (transport_a, server_iface_a) = build_transport("a", listener_a, &[]).await;
    let (transport_b, _server_iface_b) = build_transport("b", listener_b, &[addr_a.as_str()]).await;

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

    let shared_listener = local_tcp_listener();
    let server_listener = local_tcp_listener();
    let remote_listener = local_tcp_listener();
    let control_listener = local_tcp_listener();
    let shared_port = shared_listener.local_addr().unwrap().port();
    let server_addr = server_listener.local_addr().unwrap().to_string();
    let remote_port = remote_listener.local_addr().unwrap().port();
    let control_port = control_listener.local_addr().unwrap().port();
    drop(shared_listener);
    drop(control_listener);

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
        TcpServer::new_from_listener(server_addr.clone(), server_listener, server.iface_manager()),
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
        build_transport("remote", remote_listener, &[server_addr.as_str()]).await;
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

#[tokio::test]
async fn shared_instance_client_receives_passive_destination_announces() {
    setup();

    let shared_listener = local_tcp_listener();
    let server_listener = local_tcp_listener();
    let remote_listener = local_tcp_listener();
    let control_listener = local_tcp_listener();
    let shared_port = shared_listener.local_addr().unwrap().port();
    let server_addr = server_listener.local_addr().unwrap().to_string();
    let control_port = control_listener.local_addr().unwrap().port();
    drop(shared_listener);
    drop(control_listener);

    let mut server_config = TransportConfig::new(
        "shared-server-passive",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    );
    server_config.set_share_instance(true);
    server_config.set_shared_instance_port(shared_port);
    server_config.set_instance_control_port(control_port);
    let server = Transport::new(server_config);
    server.iface_manager().lock().await.spawn(
        TcpServer::new_from_listener(server_addr.clone(), server_listener, server.iface_manager()),
        TcpServer::spawn,
    );

    let mut client_config = TransportConfig::new(
        "shared-client-passive",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    );
    client_config.set_share_instance(true);
    client_config.set_shared_instance_port(shared_port);
    let client = Transport::new(client_config);
    let mut announce_rx = client.recv_announces().await;

    let (mut remote, _remote_server_iface) =
        build_transport("remote-passive", remote_listener, &[server_addr.as_str()]).await;
    let destination = remote
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("test", "passive_announce"),
        )
        .await;
    let destination_hash = destination.lock().await.desc.address_hash;

    time::sleep(Duration::from_secs(2)).await;
    remote.send_announce(&destination, None).await;

    let announce = time::timeout(Duration::from_secs(10), announce_rx.recv())
        .await
        .expect("shared-instance client did not receive passive destination announce")
        .unwrap();

    assert_eq!(
        announce.destination.lock().await.desc.address_hash,
        destination_hash
    );
}
