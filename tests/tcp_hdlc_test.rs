use std::net::TcpListener;
use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
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
    let server_addr = server_listener.local_addr().unwrap().to_string();
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
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
            packet.data.write(&[counter]).unwrap();
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
