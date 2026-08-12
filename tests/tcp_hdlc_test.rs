use std::io::Read;
use std::net::TcpListener;
use std::sync::Once;
use std::time::Duration;

use getrandom::SysRng;
use rand_core::UnwrapErr;
use reticulum_sdk::{
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::Packet,
    transport::{Transport, TransportConfig},
};
use tokio_util::sync::CancellationToken;

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
    let mut rng = UnwrapErr(SysRng);
    let server_addr = server_listener.local_addr().unwrap().to_string();
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(&mut rng),
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

    log::info!("test: transport {} created", name);

    transport
}

#[tokio::test]
async fn packet_overload() {
    setup();

    let listener_a = local_tcp_listener();
    let listener_b = local_tcp_listener();
    let addr_a = listener_a.local_addr().unwrap().to_string();

    let transport_a = build_transport("a", listener_a, &[]).await;
    let transport_b = build_transport("b", listener_b, &[addr_a.as_str()]).await;

    let stop = CancellationToken::new();

    let producer_task = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut tx_counter = 0;

            let mut payload_size = 0;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => {
                            break;
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_micros(1)) => {

                        let mut packet = Packet::default();

                        packet.data.resize(payload_size);

                        payload_size += 1;
                        if payload_size >= 3072 {
                            payload_size = 0;
                        }

                        transport_a.send_packet(packet).await;
                        tx_counter += 1;
                    },
                };
            }

            return tx_counter;
        })
    };

    let consumer_task = {
        let stop = stop.clone();
        let mut messages = transport_b.iface_rx();
        tokio::spawn(async move {
            let mut rx_counter = 0;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => {
                            break;
                    },
                    Ok(_) = messages.recv() => {
                        rx_counter += 1;
                    },
                };
            }

            return rx_counter;
        })
    };

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    stop.cancel();

    let tx_counter = producer_task.await.unwrap();
    let rx_counter = consumer_task.await.unwrap();

    log::info!("TX: {}, RX: {}", tx_counter, rx_counter);
}

#[tokio::test]
async fn unavailable_tcp_client_does_not_block_server_traffic() {
    setup();

    let listener_a = local_tcp_listener();
    let listener_b = local_tcp_listener();
    let unavailable_listener = local_tcp_listener();
    let server_addr_a = listener_a.local_addr().unwrap().to_string();
    let unavailable_addr = unavailable_listener.local_addr().unwrap().to_string();
    drop(unavailable_listener);

    let transport_a = build_transport("a", listener_a, &[&unavailable_addr]).await;
    let transport_b = build_transport("b", listener_b, &[&server_addr_a]).await;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let sender = tokio::spawn(async move {
        for counter in 0..3u8 {
            let mut packet = Packet::default();
            packet.data.write(&[counter]);
            transport_a.send_packet(packet).await;
        }
    });

    tokio::time::timeout(Duration::from_secs(2), sender)
        .await
        .expect("send_packet stalled behind an unavailable TCP client")
        .unwrap();

    let mut iface_rx = transport_b.iface_rx();
    let mut received = 0usize;

    tokio::time::timeout(Duration::from_secs(2), async {
        while received < 3 {
            iface_rx.recv().await.unwrap();
            received += 1;
        }
    })
    .await
    .expect("TCP server traffic stopped after another TCP client failed to connect");
}

/// Fill a listener's accept backlog so a fresh connect to `addr` is
/// genuinely in flight (blocked) until a slot is freed. Returns the
/// filler connections that must be kept alive to hold the backlog open.
fn fill_accept_backlog(addr: std::net::SocketAddr) -> Vec<std::net::TcpStream> {
    let mut fillers = Vec::new();
    loop {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Ok(stream) => fillers.push(stream),
            Err(_) => break,
        }
    }
    assert!(
        fillers.len() >= 2,
        "could not fill the listen backlog (only {} fillers)",
        fillers.len()
    );
    fillers
}

#[tokio::test]
async fn outbound_traffic_does_not_abort_in_flight_connect() {
    setup();

    // A listener whose accept backlog we fill, so a fresh connect to it is
    // blocked until a slot is freed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let fillers = fill_accept_backlog(addr);
    // Spawn a TcpClient towards the backlogged address.
    let mut rng = UnwrapErr(SysRng);
    let transport = Transport::new(TransportConfig::new(
        "abort-test",
        &PrivateIdentity::new_from_rand(&mut rng),
        true,
    ));
    transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new(addr.to_string()), TcpClient::spawn);

    // Give the client time to get its connect stuck in flight.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Outbound traffic now arrives while the connect is in flight.
    let mut packet = Packet::default();
    packet.data.write(&[0xAA, 0xBB, 0xCC]);
    transport.send_packet(packet).await;

    // Free one backlog slot so the client's pending connect completes,
    // then close the backlog fillers and drain the accept queue, reading
    // from each connection until the client's data arrives. Stale filler
    // connections (closed via RST) return 0 bytes and are skipped.
    let _slot = listener.accept().unwrap();
    drop(fillers);
    listener.set_nonblocking(true).unwrap();

    let mut buf = [0u8; 256];
    let mut got_data = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !got_data && std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((mut conn, _)) => {
                conn.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
                match conn.read(&mut buf) {
                    Ok(n) if n > 0 => got_data = true,
                    _ => {}
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => break,
        }
    }

    assert!(
        got_data,
        "client connected but no outbound data arrived: message was dropped"
    );
}
