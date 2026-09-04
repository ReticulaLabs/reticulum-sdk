//! Regression test for single-input destination delivery.
//!
//! A registered single-input destination must be reachable at its
//! *name-derived* destination hash (the hash peers compute from
//! `name + identity hash`, matching the Python reference).  Inbound link
//! requests and data packets addressed to that hash must be delivered to the
//! destination.  Peers never address a destination by the raw identity hash,
//! so no alias registration is required (or desirable — it would diverge from
//! the reference implementation).

use std::net::TcpListener;
use std::sync::Once;
use std::time::Duration;

use getrandom::SysRng;
use rand_core::UnwrapErr;
use reticulum_sdk::{
    destination::DestinationName,
    destination::link::LinkEvent,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    transport::{Transport, TransportConfig},
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
) -> Transport {
    let server_addr = server_listener.local_addr().unwrap().to_string();
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(&mut UnwrapErr(SysRng)),
        true,
    ));

    transport.iface_manager().lock().await.spawn(
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

    transport
}

#[tokio::test]
async fn inbound_delivery_addressed_to_name_derived_hash() {
    setup();

    let listener_a = local_tcp_listener();
    let listener_b = local_tcp_listener();
    let addr_a = listener_a.local_addr().unwrap().to_string();

    let mut transport_a = build_transport("a", listener_a, &[]).await;
    let transport_b = build_transport("b", listener_b, &[addr_a.as_str()]).await;

    // Transport A registers a delivery-style destination, exactly as an
    // LXMF client would ("lxmf.delivery"), and announces it.
    let dest_a = transport_a
        .add_destination(
            PrivateIdentity::new_from_name("delivery-a"),
            DestinationName::new("lxmf", "delivery"),
        )
        .await;
    let dest_a_hash = dest_a.lock().await.desc.address_hash;
    let identity_hash = dest_a.lock().await.desc.identity.address_hash;

    // The destination hash is derived from the destination name and the
    // identity hash; it is never equal to the bare identity hash.
    assert_ne!(dest_a_hash, identity_hash);

    let mut in_link_rx = transport_a.in_link_events();
    let mut data_rx = transport_a.received_data_events();

    time::sleep(Duration::from_secs(2)).await;
    transport_a.send_announce(&dest_a, None).await;

    // Transport B hears the announce and establishes a link to the
    // announced (name-derived) destination hash.
    let mut announce_rx = transport_b.recv_announces().await;
    let announce = time::timeout(Duration::from_secs(10), announce_rx.recv())
        .await
        .expect("transport b never heard the announce")
        .expect("announce channel closed");
    let peer_desc = announce.destination.lock().await.desc;
    assert_eq!(peer_desc.address_hash, dest_a_hash);

    let link = transport_b.link(peer_desc).await;
    let link_id = *link.lock().await.id();
    let mut out_link_rx = transport_b.out_link_events();

    // Wait for the initiator out-link to activate before sending data.
    tokio::select! {
        event = out_link_rx.recv() => {
            match event.expect("out-link event channel closed").event {
                LinkEvent::Activated => {}
                _ => unreachable!("expected LinkEvent::Activated on initiator, got something else"),
            }
        }
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("timeout: outbound link never activated");
        }
    }

    // Wait for the inbound link to activate on A.
    tokio::select! {
        event = in_link_rx.recv() => {
            match event.expect("in-link event channel closed").event {
                LinkEvent::Activated => {}
                _ => unreachable!("expected LinkEvent::Activated, got something else"),
            }
        }
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("timeout: inbound link never activated");
        }
    }

    // Sanity check that A actually tracks the in-link.
    assert!(
        transport_a.find_in_link(&link_id).await.is_some(),
        "transport a does not track the inbound link"
    );

    // B sends a data packet over the link.
    let payload = b"hello over the link";
    let packet = link
        .lock()
        .await
        .data_packet(payload)
        .expect("link data packet");
    transport_b.send_packet(packet).await;

    // A must receive the data over the link.
    tokio::select! {
        event = in_link_rx.recv() => {
            match event.expect("in-link event channel closed").event {
                LinkEvent::Data(p) => assert_eq!(p.as_slice(), payload),
                _ => unreachable!("expected LinkEvent::Data, got something else"),
            }
        }
        _ = time::sleep(Duration::from_secs(10)) => {
            unreachable!("timeout: inbound link data never delivered");
        }
    }

    // B also sends a direct (link-less) data packet addressed to the
    // name-derived destination hash.
    let direct = announce
        .destination
        .lock()
        .await
        .data_packet(b"direct single packet")
        .expect("single data packet");
    transport_b.send_packet(direct).await;

    // A must receive it on its received-data channel.
    let received = time::timeout(Duration::from_secs(10), data_rx.recv())
        .await
        .expect("timeout: direct data packet never delivered")
        .expect("received data channel closed");
    assert_eq!(received.destination, dest_a_hash);
    assert_eq!(received.data.as_slice(), b"direct single packet");
}

#[tokio::test]
async fn identity_hash_is_not_an_alias_for_delivery() {
    setup();

    let listener_a = local_tcp_listener();
    let listener_b = local_tcp_listener();
    let addr_a = listener_a.local_addr().unwrap().to_string();

    let mut transport_a = build_transport("a", listener_a, &[]).await;
    let transport_b = build_transport("b", listener_b, &[addr_a.as_str()]).await;

    let dest_a = transport_a
        .add_destination(
            PrivateIdentity::new_from_name("delivery-b"),
            DestinationName::new("lxmf", "delivery"),
        )
        .await;
    let _dest_a_hash = dest_a.lock().await.desc.address_hash;
    let identity_hash = dest_a.lock().await.desc.identity.address_hash;

    let mut data_rx = transport_a.received_data_events();

    time::sleep(Duration::from_secs(2)).await;
    transport_a.send_announce(&dest_a, None).await;

    // Let B hear the announce so it has a valid identity to encrypt with.
    let mut announce_rx = transport_b.recv_announces().await;
    time::timeout(Duration::from_secs(10), announce_rx.recv())
        .await
        .expect("transport b never heard the announce")
        .expect("announce channel closed");

    // Address a data packet to the identity hash instead of the destination
    // hash.  The reference implementation does not register destinations
    // under the identity hash, so this packet must NOT be delivered to the
    // local destination.
    let mut desc = dest_a.lock().await.desc;
    desc.address_hash = identity_hash;
    let stray = {
        use reticulum_sdk::destination::SingleOutputDestination;
        SingleOutputDestination::new_from_desc(desc)
            .data_packet(b"stray packet")
            .expect("single data packet")
    };
    transport_b.send_packet(stray).await;

    // The stray packet must not be delivered to the destination within a
    // generous window.
    let mut received: Option<reticulum_sdk::transport::ReceivedData> = None;
    let mut saw_stray = false;
    let deadline = time::Instant::now() + Duration::from_secs(8);
    while time::Instant::now() < deadline {
        match time::timeout(Duration::from_millis(200), data_rx.recv()).await {
            Ok(Ok(d)) => {
                if d.destination == identity_hash {
                    saw_stray = true;
                }
                received = Some(d);
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    assert!(
        !saw_stray,
        "a packet addressed to the identity hash must not be delivered to a local destination"
    );
    assert!(
        received.is_none(),
        "unexpected data delivery for identity-hash-addressed packet"
    );
}
