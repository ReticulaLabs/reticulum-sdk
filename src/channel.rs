use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::{Duration, Instant, interval};
use tokio_util::sync::CancellationToken;

use crate::destination::link::{Link, LinkEvent, LinkEventData, LinkId, LinkStatus};
use crate::error::RnsError;
use crate::hash::Hash;
use crate::packet::{PacketContext, PACKET_MDU};

const CHANNEL_HEADER_SIZE: usize = 6;
const WINDOW: u16 = 2;
const WINDOW_MIN: u16 = 2;
const WINDOW_MIN_LIMIT_MEDIUM: u16 = 5;
const WINDOW_MIN_LIMIT_FAST: u16 = 16;
const WINDOW_MAX_SLOW: u16 = 5;
const WINDOW_MAX_MEDIUM: u16 = 12;
const WINDOW_MAX_FAST: u16 = 48;
const WINDOW_MAX: u16 = WINDOW_MAX_FAST;
const WINDOW_FLEXIBILITY: u16 = 4;
const FAST_RATE_THRESHOLD: u16 = 10;
const RTT_FAST: f32 = 0.18;
const RTT_MEDIUM: f32 = 0.75;
const RTT_SLOW: f32 = 1.45;
const MAX_TRIES: u16 = 5;

/// Maximal payload size of a single channel message.
pub const CHANNEL_MDU: usize = PACKET_MDU - CHANNEL_HEADER_SIZE;

/// Message model for [`Channel`].
pub trait Message: Clone + Send + Sized + Sync + 'static {
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError>;
    fn pack(&self) -> Vec<u8>;
    fn message_type(&self) -> u16;
}

/// Delivery status of a message sent over a [`Channel`].
#[derive(Debug, PartialEq, Eq)]
pub enum MessageStatus {
    Unknown,
    Waiting,
    Sent(u16),
    Delivered,
}

// ─── Envelope ───────────────────────────────────────────────────────────────

fn pack_envelope(msg_type: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut raw = Vec::with_capacity(CHANNEL_HEADER_SIZE + len);
    raw.extend_from_slice(&msg_type.to_be_bytes());
    raw.extend_from_slice(&sequence.to_be_bytes());
    raw.extend_from_slice(&(len as u16).to_be_bytes());
    raw.extend_from_slice(payload);
    raw
}

fn unpack_envelope(raw: &[u8]) -> Result<(u16, u16, Vec<u8>), RnsError> {
    if raw.len() < CHANNEL_HEADER_SIZE {
        return Err(RnsError::PacketError);
    }
    let msg_type = u16::from_be_bytes([raw[0], raw[1]]);
    let sequence = u16::from_be_bytes([raw[2], raw[3]]);
    let payload = raw[CHANNEL_HEADER_SIZE..].to_vec();
    Ok((msg_type, sequence, payload))
}

fn message_bytes<M: Message>(message: &M, sequence: u16) -> Vec<u8> {
    let payload = message.pack();
    pack_envelope(message.message_type(), sequence, &payload)
}

// ─── Adaptive window parameters ────────────────────────────────────────────

struct ChannelParams {
    max_tries: u16,
    fast_rate_rounds: u16,
    medium_rate_rounds: u16,
    window: u16,
    window_max: u16,
    window_min: u16,
}

impl ChannelParams {
    fn new(slow: bool) -> Self {
        Self {
            max_tries: MAX_TRIES,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
            window: if slow { 1 } else { WINDOW },
            window_max: if slow { 1 } else { WINDOW_MAX_SLOW },
            window_min: if slow { 1 } else { WINDOW_MIN },
        }
    }
}

fn adjust_params(params: &mut ChannelParams, rtt: Duration) {
    if params.window < params.window_max {
        params.window += 1;
    }

    let rtt = rtt.as_secs_f32();
    if rtt == 0.0 {
        return;
    }

    if rtt > RTT_FAST {
        params.fast_rate_rounds = 0;
        if rtt > RTT_MEDIUM {
            params.medium_rate_rounds = 0;
        } else {
            params.medium_rate_rounds += 1;
            if params.window_max < WINDOW_MAX_MEDIUM
                && params.medium_rate_rounds == FAST_RATE_THRESHOLD
            {
                params.window_max = WINDOW_MAX_MEDIUM;
                params.window_min = WINDOW_MIN_LIMIT_MEDIUM;
            }
        }
    } else {
        params.fast_rate_rounds += 1;
        if params.window_max < WINDOW_MAX_FAST
            && params.fast_rate_rounds == FAST_RATE_THRESHOLD
        {
            params.window_max = WINDOW_MAX_FAST;
            params.window_min = WINDOW_MIN_LIMIT_FAST;
        }
    }
}

fn timeout_duration(rtt: Duration, ring_len: usize, tries: u16) -> Duration {
    let rtt_f32 = rtt.as_secs_f32();
    let rtt_factor = if rtt_f32 >= 0.01 { 2.5 * rtt_f32 } else { 0.025 };
    let tries_factor = 1.5f32.powi(tries.saturating_sub(1) as i32);
    let total = tries_factor * rtt_factor * (ring_len as f32 + 1.5);
    Duration::from_secs_f32(total)
}

// ─── Sent-message tracking ──────────────────────────────────────────────────

struct SentMessage {
    raw_envelope: Vec<u8>,
    packet_hash: Hash,
    delivered_tx: broadcast::Sender<bool>,
    tries: u16,
    deadline: Instant,
}

// ─── Inbound message reassembly ─────────────────────────────────────────────

struct Inbound<M: Message> {
    on_hold: HashMap<u16, M>,
    incoming_tx: broadcast::Sender<M>,
    next_sequence: u16,
    link_id: LinkId,
}

impl<M: Message> Inbound<M> {
    fn new(link_id: LinkId) -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            on_hold: HashMap::new(),
            incoming_tx: tx,
            next_sequence: 0,
            link_id,
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<M> {
        self.incoming_tx.subscribe()
    }

    fn receive(&mut self, raw: &[u8]) {
        log::trace!("channel({}): received {}B", self.link_id, raw.len());

        let (msg_type, sequence, payload) = match unpack_envelope(raw) {
            Ok(v) => v,
            Err(_) => {
                log::error!("channel({}): error unpacking message", self.link_id);
                return;
            }
        };

        if sequence < self.next_sequence {
            let overflow = sequence.wrapping_add(WINDOW_MAX);
            if overflow < self.next_sequence || sequence > overflow {
                log::trace!(
                    "channel({}): received packet out of sequence window",
                    self.link_id
                );
                return;
            }
        }

        let message = match M::unpack(&payload, msg_type) {
            Ok(msg) => msg,
            Err(_) => {
                log::error!(
                    "channel({}): error deserializing message type {}",
                    self.link_id,
                    msg_type
                );
                return;
            }
        };

        if self.on_hold.insert(sequence, message).is_some() {
            log::trace!("channel({}): duplicate message received", self.link_id);
        }

        while let Some(message) = self.on_hold.remove(&self.next_sequence) {
            let _ = self.incoming_tx.send(message);
            self.next_sequence = self.next_sequence.wrapping_add(1);
        }
    }
}

// ─── Outbound message sender ────────────────────────────────────────────────

struct Outbound {
    transport: crate::transport::Transport,
    link: Arc<Mutex<Link>>,
    link_id: LinkId,
    sent_messages: HashMap<Hash, SentMessage>,
    delivered: HashSet<Hash>,
    next_sequence: u16,
    params: ChannelParams,
    cancel: CancellationToken,
    recalc_tx: mpsc::UnboundedSender<()>,
}

impl Outbound {
    async fn new(
        link: Arc<Mutex<Link>>,
        transport: crate::transport::Transport,
        recalc_tx: mpsc::UnboundedSender<()>,
    ) -> Self {
        let rtt = *link.lock().await.rtt();
        let slow = rtt.as_secs_f32() > RTT_SLOW;
        let link_id = *link.lock().await.id();
        Self {
            transport,
            link,
            link_id,
            sent_messages: HashMap::new(),
            delivered: HashSet::new(),
            next_sequence: 0,
            params: ChannelParams::new(slow),
            cancel: CancellationToken::new(),
            recalc_tx,
        }
    }

    fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    fn link_id(&self) -> LinkId {
        self.link_id
    }

    async fn is_ready_to_send(&self) -> bool {
        if self.cancel.is_cancelled() {
            return false;
        }
        if self.link.lock().await.status() != LinkStatus::Active {
            return false;
        }
        self.sent_messages.len() < self.params.window as usize
    }

    /// Recompute deadlines for all pending messages based on current RTT,
    /// in-flight count, and per-message retry count.
    fn recalculate_all_deadlines(&mut self) {
        let rtt = *self.link.blocking_lock().rtt();
        let ring_len = self.sent_messages.len();
        let now = Instant::now();
        for entry in self.sent_messages.values_mut() {
            entry.deadline = now + timeout_duration(rtt, ring_len, entry.tries);
        }
    }

    async fn enqueue_send(&mut self, message: &impl Message) -> Result<Hash, RnsError> {
        if !self.is_ready_to_send().await {
            return Err(RnsError::ChannelLinkNotReady);
        }

        let reserved_sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);

        let raw_envelope = message_bytes(message, reserved_sequence);
        if raw_envelope.len() > PACKET_MDU {
            // Rollback sequence on failure
            self.next_sequence = reserved_sequence;
            return Err(RnsError::ChannelMessageTooBig);
        }

        let packet = match self.link.lock().await.data_packet(&raw_envelope) {
            Ok(p) => p,
            Err(e) => {
                self.next_sequence = reserved_sequence;
                return Err(e);
            }
        };
        let packet_hash = packet.hash();

        let (delivered_tx, _) = broadcast::channel(1);

        let sent = SentMessage {
            raw_envelope: raw_envelope.clone(),
            packet_hash,
            delivered_tx,
            tries: 0,
            deadline: Instant::now(),
        };
        self.sent_messages.insert(packet_hash, sent);

        let mut packet = packet;
        packet.context = PacketContext::Channel;
        self.transport.send_packet(packet).await;

        // Mark as sent (tries = 1, matching Python where tries is incremented
        // in send before the timeout is set)
        if let Some(entry) = self.sent_messages.get_mut(&packet_hash) {
            entry.tries = 1;
        }

        // Recompute deadlines for all in-flight messages using the updated ring_len
        self.recalculate_all_deadlines();
        let _ = self.recalc_tx.send(());

        Ok(packet_hash)
    }

    fn handle_proof(&mut self, packet_hash: Hash) {
        let sent_message = match self.sent_messages.remove(&packet_hash) {
            Some(m) => m,
            None => {
                log::trace!(
                    "channel({}): ignoring delivery proof for unknown message {}",
                    self.link_id,
                    packet_hash
                );
                return;
            }
        };

        let rtt = *self.link.blocking_lock().rtt();
        adjust_params(&mut self.params, rtt);

        self.delivered.insert(packet_hash);
        let _ = sent_message.delivered_tx.send(true);

        // Remaining in-flight messages now have a smaller ring_len; update deadlines
        self.recalculate_all_deadlines();
        let _ = self.recalc_tx.send(());
    }

    async fn handle_timeout(&mut self, packet_hash: Hash) {
        let tries = match self.sent_messages.get(&packet_hash) {
            Some(e) => e.tries,
            None => return,
        };

        if tries >= self.params.max_tries {
            log::info!(
                "channel({}): message {} timed out after {} tries, tearing down channel",
                self.link_id,
                packet_hash,
                tries
            );
            self.link.lock().await.close();
            return;
        }

        // Python-compatible window decrease on timeout
        if self.params.window > self.params.window_min {
            self.params.window -= 1;
            let flex = core::cmp::min(WINDOW_FLEXIBILITY, self.params.window_max.saturating_sub(self.params.window_min));
            if self.params.window_max > self.params.window_min + flex {
                self.params.window_max -= 1;
            }
        }

        let new_tries = tries + 1;

        let raw_envelope = match self.sent_messages.get(&packet_hash) {
            Some(e) => e.raw_envelope.clone(),
            None => return,
        };

        let packet = match self.link.lock().await.data_packet(&raw_envelope) {
            Ok(p) => p,
            Err(_) => return,
        };
        let new_hash = packet.hash();

        let mut packet = packet;
        packet.context = PacketContext::Channel;
        self.transport.send_packet(packet).await;

        // Transfer tracking to new hash
        if let Some(mut entry) = self.sent_messages.remove(&packet_hash) {
            entry.tries = new_tries;
            entry.packet_hash = new_hash;
            self.sent_messages.insert(new_hash, entry);
        }

        // Recompute deadlines (ring_len unchanged, but this entry's tries changed)
        self.recalculate_all_deadlines();
        let _ = self.recalc_tx.send(());
    }
}

// ─── Background event loop ──────────────────────────────────────────────────

async fn outbound_event_loop(
    outbound: Arc<Mutex<Outbound>>,
    mut link_events: broadcast::Receiver<LinkEventData>,
    mut timeout_rx: mpsc::Receiver<Hash>,
    link_id: LinkId,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            event = link_events.recv() => {
                match event {
                    Ok(ev) => {
                        if ev.id == link_id {
                            if let LinkEvent::Proof(hash) = ev.event {
                                outbound.lock().await.handle_proof(hash);
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("channel({}): proof events lagged by {}", link_id, n);
                    }
                }
            }
            hash = timeout_rx.recv() => {
                match hash {
                    Some(hash) => {
                        outbound.lock().await.handle_timeout(hash).await;
                    }
                    None => break,
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
}

/// Background task that periodically checks for expired message timeouts.
///
/// Replaces the O(n) per-message `tokio::spawn` tasks with a single polling
/// loop, eliminating O(n²) spawn/cancel overhead on every send or retransmission.
async fn timeout_monitor(
    outbound: Arc<Mutex<Outbound>>,
    timeouts_tx: mpsc::Sender<Hash>,
    mut recalc_rx: mpsc::UnboundedReceiver<()>,
    cancel: CancellationToken,
) {
    let mut ticker = interval(Duration::from_millis(100));
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = recalc_rx.recv() => continue,
            _ = ticker.tick() => {
                let now = Instant::now();
                let expired: Vec<Hash> = {
                    let outbound = outbound.lock().await;
                    outbound.sent_messages.iter()
                        .filter(|(_, m)| m.deadline <= now)
                        .map(|(h, _)| *h)
                        .collect()
                };
                for h in expired {
                    let _ = timeouts_tx.send(h).await;
                }
            }
        }
    }
}

// ─── Public Channel API ──────────────────────────────────────────────────────

/// A reliable, ordered channel over a Reticulum [`Link`].
///
/// Messages are delivered in order with retransmission on timeout and
/// adaptive window-based flow control. Delivery proofs are tracked so
/// the sender can be notified when a message is confirmed received.
///
/// Wrapping a [`Link`] into a `Channel` is a local decision; it is not
/// communicated to the remote side. Both sides must wrap their respective
/// ends of the link in a `Channel` for reliable delivery to work.
pub struct Channel<M: Message> {
    /// The underlying link.
    pub link: Arc<Mutex<Link>>,
    incoming_tx: broadcast::Sender<M>,
    outbound: Arc<Mutex<Outbound>>,
    cancel: CancellationToken,
}

impl<M: Message> Channel<M> {
    /// Wrap `link` into a new `Channel`.
    ///
    /// Returns the `Channel` and a receiver for incoming messages.
    /// The receiver delivers messages in the order they were sent.
    pub async fn new(
        link: Arc<Mutex<Link>>,
        transport: &crate::transport::Transport,
    ) -> Result<(Self, broadcast::Receiver<M>), RnsError> {
        let link_id = *link.lock().await.id();
        let channel_rx = link.lock().await.bind_to_channel()?;

        let mut inbound = Inbound::<M>::new(link_id);
        let incoming_tx = inbound.incoming_tx.clone();
        let incoming_rx = inbound.subscribe();

        let (event_timeout_tx, event_timeout_rx) = mpsc::channel(256);
        let (recalc_tx, recalc_rx) = mpsc::unbounded_channel();
        let monitor_timeout_tx = event_timeout_tx.clone();
        let outbound = Outbound::new(
            link.clone(),
            transport.clone(),
            recalc_tx,
        ).await;
        let cancel = outbound.cancel_token();
        let outbound_link_id = outbound.link_id();
        let outbound = Arc::new(Mutex::new(outbound));

        // Spawn timeout monitor (single task replacing per-message spawned timeouts)
        tokio::spawn(timeout_monitor(
            outbound.clone(),
            monitor_timeout_tx,
            recalc_rx,
            cancel.clone(),
        ));

        // Spawn inbound receiver
        let inbound_cancel = cancel.clone();
        let inbound_link_id = link_id;
        tokio::spawn(async move {
            let mut channel_rx = channel_rx;
            loop {
                tokio::select! {
                    result = channel_rx.recv() => {
                        match result {
                            Ok(raw) => inbound.receive(&raw),
                            Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                log::warn!("channel({}): lagged by {} messages", inbound_link_id, n);
                            }
                        }
                    }
                    _ = inbound_cancel.cancelled() => break,
                }
            }
        });

        // Spawn outbound event loop
        let link_events = transport.out_link_events();
        let outbound_clone = outbound.clone();
        let cancel_clone = cancel.clone();
        tokio::spawn(outbound_event_loop(
            outbound_clone,
            link_events,
            event_timeout_rx,
            outbound_link_id,
            cancel_clone,
        ));

        let channel = Self {
            link,
            incoming_tx,
            outbound,
            cancel,
        };

        Ok((channel, incoming_rx))
    }

    /// Send a message over the channel.
    ///
    /// Returns the packet hash that can be used to track delivery status.
    pub async fn send(&self, message: &M) -> Result<Hash, RnsError> {
        self.outbound.lock().await.enqueue_send(message).await
    }

    /// Create an additional receiver for incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<M> {
        self.incoming_tx.subscribe()
    }

    /// Returns `true` if the channel is ready to send another message.
    pub async fn is_ready(&self) -> bool {
        self.outbound.lock().await.is_ready_to_send().await
    }

    /// Query the delivery status of a previously sent message.
    pub async fn message_status(&self, packet_hash: &Hash) -> MessageStatus {
        let outbound = self.outbound.lock().await;
        match outbound.sent_messages.get(packet_hash) {
            Some(sent) => {
                if sent.tries == 0 {
                    MessageStatus::Waiting
                } else {
                    MessageStatus::Sent(sent.tries)
                }
            }
            None => {
                if outbound.delivered.contains(packet_hash) {
                    MessageStatus::Delivered
                } else {
                    MessageStatus::Unknown
                }
            }
        }
    }

    /// Subscribe to delivery notification for a specific message.
    pub async fn watch_delivery(
        &self,
        packet_hash: &Hash,
    ) -> Option<broadcast::Receiver<bool>> {
        self.outbound
            .lock()
            .await
            .sent_messages
            .get(packet_hash)
            .map(|s| s.delivered_tx.subscribe())
    }
}

impl<M: Message> Drop for Channel<M> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
