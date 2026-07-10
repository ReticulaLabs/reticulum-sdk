pub mod backbone;
pub mod hdlc;
pub mod ifac;
pub mod kiss;
pub mod modem73;
pub mod rnode;
pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task;
use tokio::time::{self, Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::buffer::InputBuffer;
use crate::hash::ADDRESS_HASH_SIZE;
use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::iface::ifac::IfacConfig;
use crate::packet::{HeaderType, Packet, PacketType};

pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

// Python Reticulum keeps hardware/interface MTU distinct from the fixed
// interoperable Reticulum packet MTU. Fast interfaces can negotiate higher
// effective transfer sizes later, but the base packet wire format remains 500
// bytes. These constants model interface capacity rather than packet format.
//
// TODO: some of these (such as INTERFACE_TX_QUEUE_CAP could become
// configuration items as reticulum grows. The unlimited max of the Python
// implementation isn't great from a security standpoint.
pub const DEFAULT_HW_MTU: usize = 2048;
pub const MAX_AUTOCONFIGURED_HW_MTU: usize = 524_288;
const DEFAULT_ANNOUNCE_CAP: f64 = 0.02;
const DEFAULT_INTERFACE_TX_QUEUE_CAP: usize = 16_384;
const MAX_QUEUED_ANNOUNCES: usize = 16_384;
const INTERFACE_SEND_TIMEOUT: Duration = Duration::from_millis(100);
const SATURATED_QUEUE_LOG_INTERVAL: Duration = Duration::from_secs(10);

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

#[derive(Debug, Clone)]
pub struct RxMessage {
    pub address: AddressHash, // Address of source interface
    pub snr: Option<f32>,     // Signal-to-noise ratio (RNode only)
    pub rssi: Option<i16>,    // Received signal strength (RNode only)
    pub packet: Packet,       // Received packet
}

/// Queue length snapshot for a single interface.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InterfaceQueueLength {
    /// Interface address the queue lengths belong to.
    pub address: AddressHash,
    /// Number of outbound packets currently queued for the interface worker.
    pub tx: usize,
    /// Number of forwarded announces waiting in the interface announce pacer.
    pub announce: usize,
}

/// Queue length snapshot for the interface manager.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct InterfaceQueueLengths {
    /// Number of inbound packets queued from interface workers to transport.
    pub rx: usize,
    /// Per-interface outbound queue lengths.
    pub interfaces: Vec<InterfaceQueueLength>,
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
    pub ifac_config: Option<IfacConfig>,
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
            ifac_config: None,
        }
    }

    /// Deserialize a received packet buffer and verify the IFAC if this
    /// channel has IFAC configured.
    ///
    /// Returns the parsed `Packet` with the IFAC field still attached
    /// (the transport layer does not inspect the IFAC, so it can be
    /// forwarded as-is).
    pub fn receive(&self, data: &[u8]) -> Result<Packet, crate::error::RnsError> {
        match &self.ifac_config {
            Some(config) => {
                let packet = Packet::deserialize_with_ifac_len(
                    &mut InputBuffer::new(data),
                    config.ifac_len(),
                )?;
                config.verify_packet(&packet)?;
                Ok(packet)
            }
            None => Packet::deserialize(&mut InputBuffer::new(data)),
        }
    }

    pub fn set_ifac_config(&mut self, config: Option<IfacConfig>) {
        self.ifac_config = config;
    }

    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

pub trait Interface {
    fn hw_mtu(&self) -> usize;

    fn bitrate(&self) -> Option<f64> {
        None
    }

    fn announce_cap(&self) -> f64 {
        DEFAULT_ANNOUNCE_CAP
    }

    /// Whether this interface should auto-size its HW_MTU from the bitrate
    /// and participate in link MTU discovery / upgrades.
    fn autoconfigure_mtu(&self) -> bool {
        false
    }

    /// Whether this interface has a user-configured fixed MTU and should
    /// participate in link MTU discovery / upgrades.
    fn fixed_mtu(&self) -> bool {
        false
    }

    /// Returns a shared MTU atomic for live updates. If the interface
    /// updates its HW_MTU at runtime (e.g. Modem73), it should return
    /// `Some(arc)` pointing to the same `Arc<AtomicUsize>` used by
    /// `hw_mtu()`. The default returns `None`, causing the registration
    /// path to snapshot the value returned by `hw_mtu()`.
    fn hw_mtu_source(&self) -> Option<Arc<AtomicUsize>> {
        None
    }
}

pub(crate) fn configured_bitrate(bitrate: f64) -> Option<f64> {
    if bitrate.is_finite() && bitrate > 0.0 {
        Some(bitrate)
    } else {
        None
    }
}

struct LocalInterface {
    address: AddressHash,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    announce_pacer: Option<AnnouncePacer>,
    saturated_queue_logger: SaturatedQueueLogger,
    shared_instance_client: bool,
    /// Hardware MTU atomic, shared with the interface for live updates.
    /// `None` means the interface does not participate in link MTU
    /// discovery / upgrades.
    hw_mtu: Option<Arc<AtomicUsize>>,
    /// Interface Access Code configuration. When set, outbound packets
    /// will have an Ed25519 IFAC signature attached before transmission.
    ifac_config: Option<IfacConfig>,
}

#[derive(Clone)]
struct SaturatedQueueLogger {
    iface: AddressHash,
    state: Arc<tokio::sync::Mutex<SaturatedQueueLogState>>,
}

struct SaturatedQueueLogState {
    next_log_at: Instant,
    suppressed: usize,
}

impl SaturatedQueueLogger {
    fn new(iface: AddressHash) -> Self {
        Self {
            iface,
            state: Arc::new(tokio::sync::Mutex::new(SaturatedQueueLogState {
                next_log_at: Instant::now(),
                suppressed: 0,
            })),
        }
    }

    async fn warn_drop(&self, tx_type: TxMessageType) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if now < state.next_log_at {
            state.suppressed += 1;
            return;
        }

        let suppressed = state.suppressed;
        state.suppressed = 0;
        state.next_log_at = now + SATURATED_QUEUE_LOG_INTERVAL;
        drop(state);

        if suppressed > 0 {
            log::warn!(
                "iface: dropping outbound packet for saturated interface queue iface={} tx_type={:?} suppressed_drops={}",
                self.iface,
                tx_type,
                suppressed
            );
        } else {
            log::warn!(
                "iface: dropping outbound packet for saturated interface queue iface={} tx_type={:?}",
                self.iface,
                tx_type
            );
        }
    }
}

#[derive(Clone)]
struct AnnouncePacer {
    bitrate: f64,
    announce_cap: f64,
    state: Arc<tokio::sync::Mutex<AnnouncePacerState>>,
}

struct AnnouncePacerState {
    announce_allowed_at: Instant,
    announce_queue: VecDeque<AddressHash>,
    announce_data: HashMap<AddressHash, TxMessage>,
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
                announce_data: HashMap::new(),
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

    async fn queue_len(&self) -> usize {
        self.state.lock().await.announce_data.len()
    }

    async fn send(
        &self,
        tx_send: InterfaceTxSender,
        stop: CancellationToken,
        saturated_queue_logger: SaturatedQueueLogger,
        message: TxMessage,
    ) {
        let Some(wait_time) = self.wait_time(&message.packet) else {
            send_or_drop(&tx_send, message, Some(&saturated_queue_logger)).await;
            return;
        };

        let mut state = self.state.lock().await;
        let now = Instant::now();
        if state.announce_queue.is_empty() && now >= state.announce_allowed_at {
            state.announce_allowed_at = now + wait_time;
            drop(state);

            send_or_drop(&tx_send, message, Some(&saturated_queue_logger)).await;
            return;
        }

        let dest = message.packet.destination;
        if state.announce_data.contains_key(&dest) {
            state.announce_data.insert(dest, message);
        } else if state.announce_queue.len() < MAX_QUEUED_ANNOUNCES {
            state.announce_queue.push_back(dest);
            state.announce_data.insert(dest, message);
        }

        if !state.timer_active {
            state.timer_active = true;
            task::spawn(process_announce_queue(
                self.clone(),
                tx_send,
                stop,
                saturated_queue_logger,
            ));
        }
    }
}

async fn process_announce_queue(
    pacer: AnnouncePacer,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    saturated_queue_logger: SaturatedQueueLogger,
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
                Some(dest) => {
                    if let Some(message) = state.announce_data.remove(&dest) {
                        if let Some(wait_time) = pacer.wait_time(&message.packet) {
                            state.announce_allowed_at = now + wait_time;
                        }
                        Some(message)
                    } else {
                        state.timer_active = false;
                        None
                    }
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

        send_or_drop(&tx_send, message, Some(&saturated_queue_logger)).await;
    }
}

async fn send_or_drop(
    tx_send: &InterfaceTxSender,
    message: TxMessage,
    saturated_queue_logger: Option<&SaturatedQueueLogger>,
) {
    match tx_send.try_send(message) {
        Ok(()) => {}
        Err(TrySendError::Full(message)) => {
            let tx_type = message.tx_type;
            if time::timeout(INTERFACE_SEND_TIMEOUT, tx_send.send(message))
                .await
                .is_err()
            {
                if let Some(logger) = saturated_queue_logger {
                    logger.warn_drop(tx_type).await;
                } else {
                    log::warn!(
                        "iface: dropping outbound packet for saturated interface queue tx_type={:?}",
                        tx_type
                    );
                }
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
        self.new_channel_with_pacer(tx_cap, None, false, None, None)
    }

    fn new_channel_with_pacer(
        &mut self,
        tx_cap: usize,
        announce_pacer: Option<AnnouncePacer>,
        shared_instance_client: bool,
        hw_mtu: Option<Arc<AtomicUsize>>,
        ifac_config: Option<IfacConfig>,
    ) -> InterfaceChannel {
        self.counter += 1;

        let counter_bytes = self.counter.to_le_bytes();
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&counter_bytes[..]));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!(
            "iface: create channel {} hw_mtu={:?}",
            address,
            hw_mtu.as_ref().map(|m| m.load(Ordering::Relaxed))
        );

        let stop = CancellationToken::new();

        self.ifaces.push(LocalInterface {
            address,
            tx_send,
            stop: stop.clone(),
            announce_pacer,
            saturated_queue_logger: SaturatedQueueLogger::new(address),
            shared_instance_client,
            hw_mtu,
            ifac_config: ifac_config.clone(),
        });

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
            ifac_config,
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
        let hw_mtu = if inner.autoconfigure_mtu() || inner.fixed_mtu() {
            Some(
                inner
                    .hw_mtu_source()
                    .unwrap_or_else(|| Arc::new(AtomicUsize::new(inner.hw_mtu()))),
            )
        } else {
            None
        };
        let channel = self.new_channel_with_pacer(
            DEFAULT_INTERFACE_TX_QUEUE_CAP,
            announce_pacer,
            shared_instance_client,
            hw_mtu,
            None,
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

    /// Returns current interface queue lengths for metrics collection.
    pub async fn queue_lengths(&self) -> InterfaceQueueLengths {
        let mut interfaces = Vec::with_capacity(self.ifaces.len());

        for iface in &self.ifaces {
            if iface.stop.is_cancelled() {
                continue;
            }

            interfaces.push(InterfaceQueueLength {
                address: iface.address,
                tx: channel_queue_len(&iface.tx_send),
                announce: match &iface.announce_pacer {
                    Some(pacer) => pacer.queue_len().await,
                    None => 0,
                },
            });
        }

        InterfaceQueueLengths {
            rx: channel_queue_len(&self.rx_send),
            interfaces,
        }
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    pub fn active_interface_addresses(&self) -> Vec<AddressHash> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| iface.address)
            .collect()
    }

    pub fn shared_instance_clients_except(&self, address: AddressHash) -> Vec<AddressHash> {
        self.ifaces
            .iter()
            .filter(|iface| iface.shared_instance_client && !iface.stop.is_cancelled())
            .filter(|iface| iface.address != address)
            .map(|iface| iface.address)
            .collect()
    }

    /// Return the hardware MTU registered for the interface at `address`,
    /// or `None` if the interface does not participate in MTU upgrades or
    /// is no longer active.
    pub fn hw_mtu(&self, address: &AddressHash) -> Option<usize> {
        self.ifaces
            .iter()
            .find(|iface| iface.address == *address && !iface.stop.is_cancelled())
            .and_then(|iface| iface.hw_mtu.as_ref().map(|mtu| mtu.load(Ordering::Relaxed)))
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
                let mut message = message.clone();

                // Apply IFAC if configured for this interface
                if let Some(ifac_config) = &iface.ifac_config {
                    if let Err(err) = ifac_config.attach(&mut message.packet) {
                        log::warn!(
                            "iface: failed to attach IFAC for iface={} err={:?}",
                            iface.address,
                            err,
                        );
                        continue;
                    }
                }

                if let Some(pacer) = iface
                    .announce_pacer
                    .as_ref()
                    .filter(|_| AnnouncePacer::should_pace(&message))
                {
                    pacer
                        .send(
                            iface.tx_send.clone(),
                            iface.stop.clone(),
                            iface.saturated_queue_logger.clone(),
                            message,
                        )
                        .await;
                } else {
                    send_or_drop(&iface.tx_send, message, Some(&iface.saturated_queue_logger))
                        .await;
                }
            }
        }
    }

    /// Set or clear the IFAC configuration for a specific interface.
    ///
    /// When set, outbound packets sent through this interface will have an
    /// Ed25519 signature attached as an Interface Access Code.
    pub fn set_ifac_config(&mut self, address: &AddressHash, config: Option<IfacConfig>) {
        for iface in &mut self.ifaces {
            if iface.address == *address {
                iface.ifac_config = config;
                return;
            }
        }
    }

    /// Return the IFAC configuration for a specific interface, if set.
    pub fn get_ifac_config(&self, address: &AddressHash) -> Option<&IfacConfig> {
        self.ifaces
            .iter()
            .find(|iface| iface.address == *address)
            .and_then(|iface| iface.ifac_config.as_ref())
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn channel_queue_len<T>(sender: &mpsc::Sender<T>) -> usize {
    sender.max_capacity().saturating_sub(sender.capacity())
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
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None);
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
    async fn queue_lengths_report_rx_and_per_interface_tx_depths() {
        let mut manager = InterfaceManager::new(4);
        let channel = manager.new_channel(4);
        let iface = channel.address;
        let rx_channel = channel.rx_channel.clone();
        let _receiver = channel.tx_channel;

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            })
            .await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            })
            .await;
        rx_channel
            .send(RxMessage {
                address: iface,
                snr: None,
                rssi: None,
                packet: Packet::default(),
            })
            .await
            .expect("queued rx message");

        let lengths = manager.queue_lengths().await;

        assert_eq!(lengths.rx, 1);
        assert_eq!(lengths.interfaces.len(), 1);
        assert_eq!(lengths.interfaces[0].address, iface);
        assert_eq!(lengths.interfaces[0].tx, 2);
        assert_eq!(lengths.interfaces[0].announce, 0);
    }

    #[tokio::test]
    async fn spawned_interface_tx_queue_handles_short_bursts() {
        struct TestInterface;

        impl Interface for TestInterface {
            fn hw_mtu(&self) -> usize {
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
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None);
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
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 1, &[0])).await;
        assert_eq!(receiver.try_recv().unwrap().packet.data.as_slice(), &[0]);

        manager.send(announce(2, 1, &[1])).await;
        manager.send(announce(2, 1, &[2])).await;

        let lengths = manager.queue_lengths().await;
        assert_eq!(lengths.interfaces[0].announce, 1);

        time::advance(Duration::from_secs(1)).await;
        task::yield_now().await;

        assert_eq!(receiver.try_recv().unwrap().packet.data.as_slice(), &[2]);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }
}
