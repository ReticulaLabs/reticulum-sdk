use std::sync::Once;
use std::time::{Duration, Instant};

use rand_core::OsRng;
use reticulum_sdk::{
    destination::{DestinationName, SingleInputDestination, SingleOutputDestination},
    hash::AddressHash,
    identity::PrivateIdentity,
    iface::RxMessage,
    packet::{DestinationType, HeaderType, Packet, PacketType, PropagationType},
    transport::{Transport, TransportConfig},
};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    });
}

const BENCH_DURATION: Duration = Duration::from_secs(3);
const TX_CHANNEL_CAP: usize = 65_536;

// ---------------------------------------------------------------------------
// Helper: create a transport with one virtual channel interface
// ---------------------------------------------------------------------------
async fn setup_transport() -> (Transport, reticulum_sdk::iface::InterfaceChannel) {
    let transport = Transport::new(TransportConfig::default());
    let im = transport.iface_manager();
    let channel = im.lock().await.new_channel(TX_CHANNEL_CAP);
    (transport, channel)
}

// ---------------------------------------------------------------------------
// Benchmark: outbound send_packet with a known route in the path table.
//
// Routes through: path_table handle_packet -> packet_cache update ->
//   iface_manager send -> try_send to virtual channel TX queue.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bench_send_packet_routed() {
    setup();

    let (transport, channel) = setup_transport().await;
    let iface_addr = *channel.address();

    let remote = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("bench", "routed"),
    );
    let mut announce = remote.announce(OsRng, None).unwrap();
    announce.header.header_type = HeaderType::Type2;
    announce.header.propagation_type = PropagationType::Transport;
    announce.header.hops = 1;
    announce.transport = Some(AddressHash::new_from_slice(b"next-hop"));
    let dest_addr = announce.destination;

    channel
        .rx_channel
        .send(RxMessage {
            address: iface_addr,
            packet: announce,
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(transport.path_table_len().await, 1);

    let _drain = {
        let mut tx = channel.tx_channel;
        tokio::spawn(async move { while tx.recv().await.is_some() {} })
    };

    let mut packet = Packet::default();
    packet.destination = dest_addr;
    packet.header.destination_type = DestinationType::Single;
    packet.header.packet_type = PacketType::Data;
    packet.data.resize(100);

    let start = Instant::now();
    let mut count = 0u64;

    while start.elapsed() < BENCH_DURATION {
        transport.send_packet(packet.clone()).await;
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = count as f64 / elapsed;

    log::info!(
        "BENCH send_packet_routed: {} pkts in {:.2}s = {:.0} pkt/s",
        count,
        elapsed,
        rate,
    );
}

// ---------------------------------------------------------------------------
// Benchmark: outbound send_packet without a known route (broadcast).
//
// Routes through: path_table handle_packet (miss) -> packet_cache update ->
//   iface_manager send -> try_send to ALL virtual channel TX queues.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bench_send_packet_broadcast() {
    setup();

    let (transport, channel) = setup_transport().await;

    let _drain = {
        let mut tx = channel.tx_channel;
        tokio::spawn(async move { while tx.recv().await.is_some() {} })
    };

    let mut packet = Packet::default();
    packet.data.resize(100);

    let start = Instant::now();
    let mut count = 0u64;

    while start.elapsed() < BENCH_DURATION {
        transport.send_packet(packet.clone()).await;
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = count as f64 / elapsed;

    log::info!(
        "BENCH send_packet_broadcast: {} pkts in {:.2}s = {:.0} pkt/s",
        count,
        elapsed,
        rate,
    );
}

// ---------------------------------------------------------------------------
// Benchmark: inbound data packet decryption and dispatch.
//
// Injects pre-encrypted data packets through the virtual interface's rx
// channel.  Each packet goes through: manage_transport dispatch ->
//   duplicate filter -> handle_data -> decrypt -> ReceivedData event.
//
// Packets are pre-created with unique ciphertexts so the duplicate cache
// does not reject them.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bench_inbound_data_decryption() {
    setup();

    let mut transport = Transport::new(TransportConfig::default());
    let im = transport.iface_manager();
    let channel = im.lock().await.new_channel(TX_CHANNEL_CAP);
    let iface_addr = *channel.address();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let dest = transport
        .add_destination(identity, DestinationName::new("bench", "inbound"))
        .await;
    let desc = dest.lock().await.desc;
    let output = SingleOutputDestination::new_from_desc(desc);
    let payload = b"benchmark payload";

    let packets: Vec<Packet> = (0..5_000)
        .map(|_| output.data_packet(payload).unwrap())
        .collect();

    let start = Instant::now();
    let mut count = 0u64;

    while start.elapsed() < BENCH_DURATION {
        let idx = (count as usize) % packets.len();
        channel
            .rx_channel
            .send(RxMessage {
                address: iface_addr,
                packet: packets[idx].clone(),
            })
            .await
            .unwrap();
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = count as f64 / elapsed;

    log::info!(
        "BENCH inbound_data_decryption: {} pkts in {:.2}s = {:.0} pkt/s",
        count,
        elapsed,
        rate,
    );
}
