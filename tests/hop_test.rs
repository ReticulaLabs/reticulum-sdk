use std::sync::Once;
use std::time::Duration;

use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use rand_core::OsRng;
use reticulum_sdk::{
    destination::{DestinationDesc, DestinationName, SingleOutputDestination},
    destination::link::LinkEvent,
    hash::{AddressHash, HASH_SIZE},
    identity::Identity,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::{Packet, PacketContext, PacketType},
    transport::{Transport, TransportConfig},
};
use tokio::time;
use tokio::sync::broadcast;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("trace")
        ).init()
    });
}

fn free_local_addr() -> String {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

async fn build_transport_full(
    name: &str,
    server_addr: &str,
    client_addr: &[&str],
    retransmit: bool
) -> Transport {
    let mut config = TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        true
    );

    if retransmit {
        config.set_retransmit(true);
    }

    let transport = Transport::new(config);

    transport.iface_manager().lock().await.spawn(
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

    log::info!("test: transport {} created", name);

    transport
}

async fn build_transport_probe(
    name: &str,
    server_addr: &str,
    client_addr: &[&str],
    broadcast: bool,
    retransmit: bool,
    respond_to_probes: bool,
) -> Transport {
    let mut config = TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        broadcast
    );

    if retransmit {
        config.set_retransmit(true);
    }

    if respond_to_probes {
        config.set_respond_to_probes(true);
    }

    let transport = Transport::new(config);

    transport.iface_manager().lock().await.spawn(
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

    log::info!("test: transport {} created", name);

    transport
}

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str]) -> Transport {
    build_transport_full(name, server_addr, client_addr, false).await
}

#[tokio::test]
async fn calculate_hop_distance() {
    setup();

    let addr_a = free_local_addr();
    let addr_b = free_local_addr();
    let addr_c = free_local_addr();

    let mut transport_a = build_transport("a", &addr_a, &[]).await;
    let transport_b = build_transport("b", &addr_b, &[&addr_a]).await;
    let transport_c = build_transport("c", &addr_c, &[&addr_a, &addr_b]).await;

    let id_a = PrivateIdentity::new_from_name("a");

    let dest_a = transport_a
        .add_destination(id_a, DestinationName::new("test", "hop"))
        .await;

    time::sleep(Duration::from_secs(2)).await;

    println!("======");
    transport_a.send_announce(&dest_a, None).await;

    transport_b.recv_announces().await;
    transport_c.recv_announces().await;

    time::sleep(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn direct_path_request_and_response() {
    setup();

    let addr_a = free_local_addr();
    let addr_b = free_local_addr();

    let transport_a = build_transport("a", &addr_a, &[]).await;
    let mut transport_b = build_transport("b", &addr_b, &[&addr_a]).await;

    let id_b = PrivateIdentity::new_from_name("b");

    let dest_b = transport_b
        .add_destination(id_b, DestinationName::new("test", "hop"))
        .await;
    let dest_b_hash = dest_b.lock().await.desc.address_hash;

    time::sleep(Duration::from_secs(2)).await;

    transport_a.request_path(&dest_b_hash, None, None).await;

    time::sleep(Duration::from_secs(2)).await;

    assert!(transport_a.knows_destination(&dest_b_hash).await);
}

#[tokio::test]
async fn remote_path_request_and_response() {
    setup();

    let addr_a = free_local_addr();
    let addr_b = free_local_addr();
    let addr_c = free_local_addr();

    let transport_a = build_transport("a", &addr_a, &[]).await;
    let mut transport_b = build_transport_full(
        "b",
        &addr_b,
        &[&addr_a],
        true,
    ).await;
    let mut transport_c = build_transport("c", &addr_c, &[&addr_b]).await;

    let id_c = PrivateIdentity::new_from_name("c");
    let dest_c = transport_c
        .add_destination(id_c, DestinationName::new("test", "hop"))
        .await;
    let dest_c_hash = dest_c.lock().await.desc.address_hash;

    let id_b = PrivateIdentity::new_from_name("b");
    let dest_b = transport_b
        .add_destination(id_b, DestinationName::new("test", "hop"))
        .await;

    time::sleep(Duration::from_secs(2)).await;

    transport_c.send_announce(&dest_c, None).await;
    transport_b.recv_announces().await;

    time::sleep(Duration::from_secs(2)).await;

    // Advance time past the announce timeout, so the regular announce of
    // destination c is not propagated to a and we can test if a's path
    // request is successful.
    time::pause();
    time::advance(time::Duration::from_secs(3600)).await;

    transport_b.send_announce(&dest_b, None).await;
    transport_a.recv_announces().await;
    transport_a.request_path(&dest_c_hash, None, None).await;

    assert!(transport_a.knows_destination(&dest_c_hash).await);
}

#[tokio::test]
async fn message_proof_over_remote_link() {
    setup();

    let addr_a = free_local_addr();
    let addr_b = free_local_addr();
    let addr_c = free_local_addr();

    let transport_a = build_transport("a", &addr_a, &[]).await;
    let _transport_b =
        build_transport_full("b", &addr_b, &[&addr_a], true)
        .await;
    let mut transport_c = build_transport("c", &addr_c, &[&addr_b]).await;

    let id_c = PrivateIdentity::new_from_name("c");
    let dest_c = transport_c
        .add_destination(id_c, DestinationName::new("test", "link_to"))
        .await;
    let dest_c_hash = dest_c.lock().await.desc.address_hash;

    let mut announces_a = transport_a.recv_announces().await;

    time::sleep(Duration::from_secs(2)).await;
    transport_c.send_announce(&dest_c, None).await;

    tokio::select! {
        _ = announces_a.recv() => {},
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("Timeout. Expected announce was not received");
        },
    }
    let link = transport_a.link(dest_c.lock().await.desc).await;
    let link_id = link.lock().await.id().clone();

    time::sleep(Duration::from_secs(5)).await;

    let in_link = transport_c.find_in_link(&link_id).await.unwrap();

    let mut out_link_events = transport_a.out_link_events();

    in_link.lock().await.prove_messages(true);

    let message = "foo";

    let sent = transport_a.send_to_out_links(&dest_c_hash, message.as_bytes()).await;
    let expected_hash = sent[0];

    tokio::select! {
        event = out_link_events.recv() => {
            match event.unwrap().event {
                LinkEvent::Proof(hash) => assert_eq!(hash, expected_hash),
                _ => unreachable!("unexpected event instead of LinkEvent::Proof"),
            };
        },
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("Timeout. Expected LinkEvent::Proof was not emitted");
        },
    }
}

fn create_probe_packet(destination: DestinationDesc, payload: &[u8]) -> Packet {
    SingleOutputDestination::new_from_desc(destination)
        .data_packet(payload)
        .expect("encrypted probe packet")
}

fn assert_valid_packet_proof(
    proof_packet: &Packet,
    expected_hash: &[u8],
    proving_identity: Identity,
) {
    assert_eq!(proof_packet.header.packet_type, PacketType::Proof);
    assert_eq!(proof_packet.context, PacketContext::None);
    assert_eq!(proof_packet.data.len(), HASH_SIZE + SIGNATURE_LENGTH);
    assert_eq!(&proof_packet.data.as_slice()[..HASH_SIZE], expected_hash);

    let signature = Signature::from_slice(&proof_packet.data.as_slice()[HASH_SIZE..]).unwrap();
    proving_identity.verify(expected_hash, &signature).unwrap();
}

async fn recv_expected_proof(
    iface_rx: &mut broadcast::Receiver<reticulum_sdk::iface::RxMessage>,
    expected_destination: AddressHash,
) -> Packet {
    loop {
        match iface_rx.recv().await.unwrap().packet {
            packet if packet.header.packet_type == PacketType::Proof
                && packet.destination == expected_destination =>
            {
                return packet;
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn probe_destination_returns_direct_packet_proof() {
    setup();

    let addr_a = free_local_addr();
    let addr_b = free_local_addr();

    let transport_a = build_transport("a", &addr_a, &[]).await;
    let transport_b = build_transport_probe(
        "b",
        &addr_b,
        &[&addr_a],
        true,
        false,
        true,
    ).await;

    let probe_destination = transport_b.probe_destination().await.unwrap();
    let probe_destination = probe_destination.lock().await;
    let probe_desc = probe_destination.desc;
    let probe_identity = probe_desc.identity;
    drop(probe_destination);

    time::sleep(Duration::from_secs(2)).await;

    let probe = create_probe_packet(probe_desc, b"probe-direct");
    let expected_hash = probe.hash();
    let expected_destination = AddressHash::new_from_hash(&expected_hash);

    let mut iface_rx = transport_a.iface_rx();
    transport_a.send_packet(probe).await;

    tokio::select! {
        proof_packet = recv_expected_proof(&mut iface_rx, expected_destination) => {
            assert_eq!(proof_packet.destination, expected_destination);
            assert_eq!(proof_packet.header.hops, 0);
            assert_valid_packet_proof(&proof_packet, expected_hash.as_slice(), probe_identity);
        },
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("Timeout. Expected direct probe proof was not received");
        },
    }
}

#[tokio::test]
async fn probe_destination_returns_multihop_packet_proof() {
    setup();

    let addr_a = free_local_addr();
    let addr_b = free_local_addr();
    let addr_c = free_local_addr();

    let transport_a = build_transport("a", &addr_a, &[]).await;
    let _transport_b = build_transport_probe(
        "b",
        &addr_b,
        &[&addr_a],
        false,
        true,
        false,
    ).await;
    let transport_c = build_transport_probe(
        "c",
        &addr_c,
        &[&addr_b],
        false,
        false,
        true,
    ).await;

    let probe_destination = transport_c.probe_destination().await.unwrap();
    let probe_destination = probe_destination.lock().await;
    let probe_desc = probe_destination.desc;
    let probe_identity = probe_desc.identity;
    drop(probe_destination);

    let probe_destination = transport_c.probe_destination().await.unwrap();

    let mut announces_a = transport_a.recv_announces().await;

    time::sleep(Duration::from_secs(2)).await;
    transport_c.send_announce(&probe_destination, None).await;

    tokio::select! {
        _ = announces_a.recv() => {},
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("Timeout. Expected probe announce was not received");
        },
    }

    let probe = create_probe_packet(probe_desc, b"probe-remote");
    let expected_hash = probe.hash();
    let expected_destination = AddressHash::new_from_hash(&expected_hash);

    let mut iface_rx = transport_a.iface_rx();
    transport_a.send_packet(probe).await;

    tokio::select! {
        proof_packet = recv_expected_proof(&mut iface_rx, expected_destination) => {
            assert_eq!(proof_packet.destination, expected_destination);
            assert!(proof_packet.header.hops >= 1);
            assert_valid_packet_proof(&proof_packet, expected_hash.as_slice(), probe_identity);
        },
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("Timeout. Expected multihop probe proof was not received");
        },
    }
}
