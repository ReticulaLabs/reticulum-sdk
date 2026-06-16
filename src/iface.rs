pub mod hdlc;
pub mod kiss;
pub mod rnode;
pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

use std::sync::Arc;
use std::sync::Mutex;

use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task;
use tokio::time::{self, Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::hash::ADDRESS_HASH_SIZE;
use crate::packet::{HeaderType, Packet, PacketType};

pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

// Python Reticulum keeps hardware/interface MTU distinct from the fixed
// interoperable Reticulum packet MTU. Fast interfaces can negotiate higher
// effective transfer sizes later, but the base packet wire format remains 500
// bytes. These constants model interface capacity rather than packet format.
pub const DEFAULT_HW_MTU: usize = 2048;
pub const MAX_AUTOCONFIGURED_HW_MTU: usize = 524_288;
const DEFAULT_ANNOUNCE_CAP: f64 = 0.02;
const DEFAULT_INTERFACE_TX_QUEUE_CAP: usize = 128;
const MAX_QUEUED_ANNOUNCES: usize = 16_384;
const INTERFACE_SEND_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TxMessageType {
    Broadcast(Option<AddressHash>),
    Direct(AddressHash),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxMessage {
    pub tx_type: TxMessageType,
    pub packet: Packet,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RxMessage {
    pub address: AddressHash, // Address of source interface
    pub packet: Packet,       // Received packet
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
}

impl InterfaceChannel {
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    pub fn new(
        rx_channel: InterfaceRxSender,
        tx_channel: InterfaceTxReceiver,
        address: AddressHash,
        stop: CancellationToken,
    ) -> Self {
        Self {
            address,
            rx_channel,
            tx_channel,
            stop,
        }
    }

    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

pub trait Interface {
    fn hw_mtu() -> usize;

    fn bitrate(&self) -> Option<f64> {
        None
    }

    fn announce_cap(&self) -> f64 {
        DEFAULT_ANNOUNCE_CAP
    }
}

struct LocalInterface {
    address: AddressHash,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    announce_pacer: Option<AnnouncePacer>,
    shared_instance_client: bool,
}

#[derive(Clone)]
struct AnnouncePacer {
    bitrate: f64,
    announce_cap: f64,
    state: Arc<tokio::sync::Mutex<AnnouncePacerState>>,
}

struct AnnouncePacerState {
    announce_allowed_at: Instant,
    announce_queue: VecDeque<TxMessage>,
    timer_active: bool,
}

impl AnnouncePacer {
    fn new(bitrate: f64, announce_cap: f64) -> Self {
        Self {
            bitrate,
            announce_cap,
            state: Arc::new(tokio::sync::Mutex::new(AnnouncePacerState {
                announce_allowed_at: Instant::now(),
                announce_queue: VecDeque::new(),
                timer_active: false,
            })),
        }
    }

    fn wait_time(&self, packet: &Packet) -> Option<Duration> {
        if self.bitrate <= 0.0 || self.announce_cap <= 0.0 {
            return None;
        }

        let transport_len = match packet.header.header_type {
            HeaderType::Type1 => 0,
            HeaderType::Type2 => {
                packet.transport.as_ref()?;
                ADDRESS_HASH_SIZE
            }
        };
        let packet_len = 2 + transport_len + ADDRESS_HASH_SIZE + 1 + packet.data.len();
        let tx_time = (packet_len as f64 * 8.0) / self.bitrate;

        Some(Duration::from_secs_f64(tx_time / self.announce_cap))
    }

    fn should_pace(message: &TxMessage) -> bool {
        message.packet.header.packet_type == PacketType::Announce && message.packet.header.hops > 0
    }

    async fn send(&self, tx_send: InterfaceTxSender, stop: CancellationToken, message: TxMessage) {
        let Some(wait_time) = self.wait_time(&message.packet) else {
            send_or_drop(&tx_send, message).await;
            return;
        };

        let mut state = self.state.lock().await;
        let now = Instant::now();
        if state.announce_queue.is_empty() && now >= state.announce_allowed_at {
            state.announce_allowed_at = now + wait_time;
            drop(state);

            send_or_drop(&tx_send, message).await;
            return;
        }

        if let Some(existing) = state
            .announce_queue
            .iter_mut()
            .find(|entry| entry.packet.destination == message.packet.destination)
        {
            *existing = message;
        } else if state.announce_queue.len() < MAX_QUEUED_ANNOUNCES {
            state.announce_queue.push_back(message);
        }

        if !state.timer_active {
            state.timer_active = true;
            task::spawn(process_announce_queue(self.clone(), tx_send, stop));
        }
    }
}

async fn process_announce_queue(
    pacer: AnnouncePacer,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
) {
    loop {
        if stop.is_cancelled() {
            let mut state = pacer.state.lock().await;
            state.timer_active = false;
            return;
        }

        let next_message = {
            let mut state = pacer.state.lock().await;
            let now = Instant::now();
            if now < state.announce_allowed_at {
                let wait_time = state.announce_allowed_at - now;
                drop(state);
                time::sleep(wait_time).await;
                continue;
            }

            match state.announce_queue.pop_front() {
                Some(message) => {
                    if let Some(wait_time) = pacer.wait_time(&message.packet) {
                        state.announce_allowed_at = now + wait_time;
                    }
                    Some(message)
                }
                None => {
                    state.timer_active = false;
                    None
                }
            }
        };

        let Some(message) = next_message else {
            return;
        };

        send_or_drop(&tx_send, message).await;
    }
}

async fn send_or_drop(tx_send: &InterfaceTxSender, message: TxMessage) {
    match tx_send.try_send(message) {
        Ok(()) => {}
        Err(TrySendError::Full(message)) => {
            let tx_type = message.tx_type;
            if time::timeout(INTERFACE_SEND_TIMEOUT, tx_send.send(message))
                .await
                .is_err()
            {
                log::warn!(
                    "iface: dropping outbound packet for saturated interface queue tx_type={:?}",
                    tx_type
                );
            }
        }
        Err(TrySendError::Closed(_)) => {
            log::trace!("iface: dropping outbound packet for closed interface queue");
        }
    }
}

pub struct InterfaceContext<T: Interface> {
    pub inner: Arc<Mutex<T>>,
    pub channel: InterfaceChannel,
    pub cancel: CancellationToken,
}

pub struct InterfaceManager {
    counter: usize,
    rx_recv: Arc<tokio::sync::Mutex<InterfaceRxReceiver>>,
    rx_send: InterfaceRxSender,
    cancel: CancellationToken,
    ifaces: Vec<LocalInterface>,
}

impl InterfaceManager {
    pub fn new(rx_cap: usize) -> Self {
        let (rx_send, rx_recv) = InterfaceChannel::make_rx_channel(rx_cap);
        let rx_recv = Arc::new(tokio::sync::Mutex::new(rx_recv));

        Self {
            counter: 0,
            rx_recv,
            rx_send,
            cancel: CancellationToken::new(),
            ifaces: Vec::new(),
        }
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_with_pacer(tx_cap, None, false)
    }

    fn new_channel_with_pacer(
        &mut self,
        tx_cap: usize,
        announce_pacer: Option<AnnouncePacer>,
        shared_instance_client: bool,
    ) -> InterfaceChannel {
        self.counter += 1;

        let counter_bytes = self.counter.to_le_bytes();
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&counter_bytes[..]));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!("iface: create channel {}", address);

        let stop = CancellationToken::new();

        self.ifaces.push(LocalInterface {
            address,
            tx_send,
            stop: stop.clone(),
            announce_pacer,
            shared_instance_client,
        });

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
        }
    }

    pub fn new_context<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        self.new_context_with_options(inner, false)
    }

    fn new_context_with_options<T: Interface>(
        &mut self,
        inner: T,
        shared_instance_client: bool,
    ) -> InterfaceContext<T> {
        let bitrate = inner.bitrate();
        let announce_cap = inner.announce_cap();
        let announce_pacer = bitrate
            .filter(|bitrate| *bitrate > 0.0 && announce_cap > 0.0)
            .map(|bitrate| AnnouncePacer::new(bitrate, announce_cap));
        let channel = self.new_channel_with_pacer(
            DEFAULT_INTERFACE_TX_QUEUE_CAP,
            announce_pacer,
            shared_instance_client,
        );

        let inner = Arc::new(Mutex::new(inner));

        let context = InterfaceContext::<T> {
            inner: inner.clone(),
            channel,
            cancel: self.cancel.clone(),
        };

        context
    }

    pub fn spawn<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context(inner);
        let address = context.channel.address().clone();

        task::spawn(worker(context));

        address
    }

    pub fn spawn_shared_instance_client<T: Interface, F, R>(
        &mut self,
        inner: T,
        worker: F,
    ) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context_with_options(inner, true);
        let address = context.channel.address().clone();

        task::spawn(worker(context));

        address
    }

    pub fn receiver(&self) -> Arc<tokio::sync::Mutex<InterfaceRxReceiver>> {
        self.rx_recv.clone()
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    pub fn shared_instance_clients_except(&self, address: AddressHash) -> Vec<AddressHash> {
        self.ifaces
            .iter()
            .filter(|iface| iface.shared_instance_client && !iface.stop.is_cancelled())
            .filter(|iface| iface.address != address)
            .map(|iface| iface.address)
            .collect()
    }

    pub async fn send(&self, message: TxMessage) {
        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }

                    should_send
                }
                TxMessageType::Direct(address) => address == iface.address,
            };

            if should_send && !iface.stop.is_cancelled() {
                if let Some(pacer) = iface
                    .announce_pacer
                    .as_ref()
                    .filter(|_| AnnouncePacer::should_pace(&message))
                {
                    pacer
                        .send(iface.tx_send.clone(), iface.stop.clone(), message.clone())
                        .await;
                } else {
                    send_or_drop(&iface.tx_send, message.clone()).await;
                }
            }
        }
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;
    use crate::packet::{
        ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PacketContext,
        PacketDataBuffer, PropagationType,
    };

    fn announce(destination: u8, hops: u8, data: &[u8]) -> TxMessage {
        TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet: Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type1,
                    context_flag: ContextFlag::Unset,
                    propagation_type: PropagationType::Broadcast,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                    hops,
                },
                ifac: None,
                destination: AddressHash::new([destination; 16]),
                transport: None,
                context: PacketContext::None,
                data: PacketDataBuffer::new_from_slice(data),
            },
        }
    }

    #[tokio::test(start_paused = true)]
    async fn local_announces_bypass_announce_pacer() {
        let mut manager = InterfaceManager::new(1);
        let pacer = AnnouncePacer::new(10_000.0, DEFAULT_ANNOUNCE_CAP);
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 0, &[1])).await;
        manager.send(announce(2, 0, &[2])).await;

        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([1; 16])
        );
        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([2; 16])
        );
    }

    #[tokio::test]
    async fn saturated_interface_queue_drops_instead_of_blocking() {
        let mut manager = InterfaceManager::new(1);
        let channel = manager.new_channel(1);
        let iface = channel.address;
        let _receiver = channel.tx_channel;

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            })
            .await;

        time::timeout(
            Duration::from_millis(500),
            manager.send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            }),
        )
        .await
        .expect("send blocked behind a saturated interface queue");
    }

    #[tokio::test]
    async fn spawned_interface_tx_queue_handles_short_bursts() {
        struct TestInterface;

        impl Interface for TestInterface {
            fn hw_mtu() -> usize {
                DEFAULT_HW_MTU
            }
        }

        let mut manager = InterfaceManager::new(1);
        let context = manager.new_context(TestInterface);
        let mut receiver = context.channel.tx_channel;

        for _ in 0..DEFAULT_INTERFACE_TX_QUEUE_CAP {
            manager
                .send(TxMessage {
                    tx_type: TxMessageType::Broadcast(None),
                    packet: Packet::default(),
                })
                .await;
        }

        for _ in 0..DEFAULT_INTERFACE_TX_QUEUE_CAP {
            assert!(receiver.try_recv().is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn forwarded_announces_are_paced_on_bitrate_limited_interfaces() {
        let mut manager = InterfaceManager::new(1);
        let pacer = AnnouncePacer::new(10_000.0, DEFAULT_ANNOUNCE_CAP);
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 1, &[1])).await;
        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([1; 16])
        );

        manager.send(announce(2, 1, &[2])).await;
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        time::advance(Duration::from_secs(1)).await;
        task::yield_now().await;

        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([2; 16])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_announces_keep_only_latest_packet_for_destination() {
        let mut manager = InterfaceManager::new(1);
        let pacer = AnnouncePacer::new(10_000.0, DEFAULT_ANNOUNCE_CAP);
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 1, &[0])).await;
        assert_eq!(receiver.try_recv().unwrap().packet.data.as_slice(), &[0]);

        manager.send(announce(2, 1, &[1])).await;
        manager.send(announce(2, 1, &[2])).await;

        time::advance(Duration::from_secs(1)).await;
        task::yield_now().await;

        assert_eq!(receiver.try_recv().unwrap().packet.data.as_slice(), &[2]);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }
}
