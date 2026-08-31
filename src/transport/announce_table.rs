use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use getrandom::SysRng;
use rand_core::{Rng, UnwrapErr};
use tokio::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::iface::{TxMessage, TxMessageType};
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType,
    PropagationType,
};

/// Retry grace period (seconds). Matches Python `PATHFINDER_G`.
const PATHFINDER_G: u64 = 5;
/// Random window for announce rebroadcast (seconds). Matches Python `PATHFINDER_RW`.
const PATHFINDER_RW_MILLIS: u64 = 500;
/// Maximum local rebroadcasts before an announce entry is completed.
/// Matches Python `LOCAL_REBROADCASTS_MAX`.
const LOCAL_REBROADCASTS_MAX: u8 = 2;

/// How long completed announces are retained in the archive cache to answer
/// onward path requests.  Bounds the cache so it cannot grow to the full
/// capacity on long-running nodes.
const ANNOUNCE_CACHE_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// Minimum interval between archive-cache prune sweeps.  The prune is
/// triggered from the 1-second retransmit cycle but throttled to this
/// cadence so a large cache is not swept on every tick.
const ANNOUNCE_CACHE_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum number of destinations retained in the archive cache (per bucket).
const ANNOUNCE_CACHE_CAPACITY: usize = 10_000;

fn random_rw_jitter() -> Duration {
    let mut rng = UnwrapErr(SysRng);
    Duration::from_millis(rng.next_u64() % (PATHFINDER_RW_MILLIS + 1))
}

#[derive(Clone)]
pub struct AnnounceEntry {
    pub packet: Packet,
    #[allow(dead_code)]
    pub timestamp: Instant,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub local_rebroadcasts: u8,
    pub hops: u8,
    pub response_to_iface: Option<AddressHash>,
}

pub enum RetransmitOutcome {
    /// Retry limit reached; the entry should be moved to the archive cache.
    Completed,
    /// Timeout has not yet expired; keep the entry and try again next cycle.
    Deferred,
    /// The entry is ready to be sent now.
    Ready(TxMessage),
}

impl AnnounceEntry {
    pub fn retransmit(&mut self, transport_id: &AddressHash) -> RetransmitOutcome {
        if self.retries >= LOCAL_REBROADCASTS_MAX || self.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
            return RetransmitOutcome::Completed;
        }

        if Instant::now() < self.timeout {
            return RetransmitOutcome::Deferred;
        }

        self.retries += 1;
        self.timeout = Instant::now() + Duration::from_secs(PATHFINDER_G) + random_rw_jitter();

        RetransmitOutcome::Ready(self.always_retransmit(transport_id))
    }

    pub fn always_retransmit(&self, transport_id: &AddressHash) -> TxMessage {
        let context = if self.response_to_iface.is_some() {
            PacketContext::PathResponse
        } else {
            // Preserve the original announce's context (e.g. PathResponse
            // from a remote peer) so that outbound mode-based filtering
            // in send_flush can correctly identify solicited responses.
            self.packet.context
        };

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: self.packet.header.context_flag,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: self.hops,
            },
            ifac: None,
            destination: self.packet.destination,
            transport: Some(transport_id.clone()),
            context,
            data: self.packet.data.clone(),
        };

        // Path responses are directed back to the requesting interface.
        // Everything else is rebroadcast on ALL interfaces, including the
        // one the announce was received on. The Python reference
        // implementation does the same (loop prevention relies on packet
        // hash deduplication and echo counting, not on excluding the
        // ingress interface). Excluding the ingress interface would break
        // multi-hop propagation on single-interface nodes, since the
        // announce would never be forwarded to the next hop on the same
        // shared medium.
        let tx_type = match self.response_to_iface {
            Some(iface) => TxMessageType::Direct(iface),
            None => TxMessageType::BroadcastFrom(self.received_from),
        };

        TxMessage { tx_type, packet }
    }
}

struct AnnounceCache {
    newer: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    older: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    capacity: usize,
    last_prune: Instant,
}

impl AnnounceCache {
    fn new(capacity: usize) -> Self {
        Self {
            newer: Some(BTreeMap::new()),
            older: None,
            capacity,
            last_prune: Instant::now(),
        }
    }

    fn insert(&mut self, destination: AddressHash, entry: AnnounceEntry) {
        if self.newer.as_ref().unwrap().len() >= self.capacity {
            self.older = Some(self.newer.take().unwrap());
            self.newer = Some(BTreeMap::new());
        }

        self.newer.as_mut().unwrap().insert(destination, entry);
    }

    fn get(&self, destination: &AddressHash) -> Option<AnnounceEntry> {
        if let Some(ref entry) = self.newer.as_ref().unwrap().get(destination) {
            return Some(AnnounceEntry::clone(entry));
        }

        if let Some(ref older) = self.older {
            return older.get(destination).map(|entry| entry.clone());
        }

        return None;
    }

    /// Drop archive entries whose announce is older than `max_age`.  Kept
    /// throttled by [`ANNOUNCE_CACHE_PRUNE_INTERVAL`] so sweeping a large
    /// cache is amortised over many retransmit cycles.
    fn prune(&mut self, max_age: Duration) {
        let now = Instant::now();
        if now.duration_since(self.last_prune) < ANNOUNCE_CACHE_PRUNE_INTERVAL {
            return;
        }
        self.last_prune = now;

        if let Some(newer) = &mut self.newer {
            newer.retain(|_, entry| now.duration_since(entry.timestamp) <= max_age);
        }
        if let Some(older) = &mut self.older {
            older.retain(|_, entry| now.duration_since(entry.timestamp) <= max_age);
        }
    }

    fn clear(&mut self) {
        self.newer.as_mut().unwrap().clear();
        self.older = None;
    }
}

pub struct AnnounceTable {
    map: BTreeMap<AddressHash, AnnounceEntry>,
    responses: BTreeMap<AddressHash, AnnounceEntry>,
    cache: AnnounceCache,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            responses: BTreeMap::new(),
            cache: AnnounceCache::new(ANNOUNCE_CACHE_CAPACITY),
        }
    }

    pub fn add(&mut self, announce: &Packet, destination: AddressHash, received_from: AddressHash) {
        let now = Instant::now();
        let hops = announce.header.hops;

        let entry = AnnounceEntry {
            packet: announce.clone(),
            timestamp: now,
            timeout: now + random_rw_jitter(),
            received_from,
            retries: 0,
            local_rebroadcasts: 0,
            hops,
            response_to_iface: None,
        };

        self.map.insert(destination, entry);
    }

    fn do_add_response(
        &mut self,
        mut response: AnnounceEntry,
        destination: AddressHash,
        to_iface: AddressHash,
        hops: u8,
        grace: Duration,
    ) {
        response.retries = 0;
        response.local_rebroadcasts = 0;
        response.hops = hops;
        response.timeout = Instant::now() + grace + random_rw_jitter();
        response.response_to_iface = Some(to_iface);

        self.responses.insert(destination, response);
    }

    pub fn add_response(
        &mut self,
        destination: AddressHash,
        to_iface: AddressHash,
        hops: u8,
        grace: Duration,
    ) -> bool {
        if let Some(entry) = self.map.get(&destination) {
            self.do_add_response(entry.clone(), destination, to_iface, hops, grace);
            return true;
        }

        if let Some(entry) = self.cache.get(&destination) {
            self.do_add_response(entry.clone(), destination, to_iface, hops, grace);
            return true;
        }

        false
    }

    pub fn entries_len(&self) -> usize {
        self.map.len() + self.responses.len()
    }

    /// Number of destinations retained in the archive cache used to answer
    /// onward path requests.
    pub fn cache_len(&self) -> usize {
        self.cache
            .newer
            .as_ref()
            .map(|newer| newer.len())
            .unwrap_or(0)
            + self.cache.older.as_ref().map(|older| older.len()).unwrap_or(0)
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.responses.clear();
        self.cache.clear();
    }

    /// Reset all retransmit counters and timeouts so entries are
    /// eligible for retransmission on the next `to_retransmit` call.
    /// Intended for testing only.
    #[cfg(test)]
    pub fn reset_retransmit_timers(&mut self) {
        for entry in self.map.values_mut() {
            entry.retries = 0;
            entry.timeout = Instant::now();
        }
    }

    pub fn contains_key(&self, destination: &AddressHash) -> bool {
        self.map.contains_key(destination)
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, destination: &AddressHash) -> Option<&mut AnnounceEntry> {
        self.map.get_mut(destination)
    }

    #[allow(dead_code)]
    pub fn remove(&mut self, destination: &AddressHash) {
        self.map.remove(destination);
    }

    /// Handle an echo of our own retransmission: increment the
    /// local_rebroadcasts counter and remove the entry if the maximum
    /// has been reached. Returns `true` if the entry was removed
    /// (announce propagation complete).
    ///
    /// Two echo patterns are detected:
    ///
    /// 1. **Direct echo** (`hops - 1 == entry.hops`): a peer retransmitted
    ///    our announce at the same hop count.  Counts toward the
    ///    `local_rebroadcasts` limit.
    ///
    /// 2. **Pass-on** (`hops - 1 == entry.hops + 1`): another node has
    ///    already forwarded our announce before our next scheduled
    ///    retransmission.  The entry is removed immediately (matching
    ///    the Python optimisation at Transport.py:1789-1794).
    pub fn echo_received(&mut self, destination: &AddressHash, hops: u8) -> bool {
        if let Some(entry) = self.map.get_mut(destination) {
            if entry.retries > 0 && hops > 0 {
                if hops - 1 == entry.hops {
                    entry.local_rebroadcasts += 1;
                    if entry.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                        self.map.remove(destination);
                        return true;
                    }
                } else if hops - 1 == entry.hops + 1 && Instant::now() < entry.timeout {
                    log::trace!(
                        "announce_table: {} passed on by another node before our retransmit, completing",
                        destination,
                    );
                    self.map.remove(destination);
                    return true;
                }
            }
        }
        false
    }

    pub fn to_retransmit(&mut self, transport_id: &AddressHash) -> Vec<TxMessage> {
        let mut messages = vec![];
        let mut completed = vec![];

        // Throttled prune of the archive cache so stale announce entries do
        // not accumulate to the capacity cap on long-running nodes.
        self.cache.prune(ANNOUNCE_CACHE_MAX_AGE);

        for (destination, ref mut entry) in &mut self.map {
            if self.responses.contains_key(destination) {
                continue;
            }

            match entry.retransmit(transport_id) {
                RetransmitOutcome::Ready(msg) => messages.push(msg),
                RetransmitOutcome::Completed => completed.push(destination.clone()),
                RetransmitOutcome::Deferred => {}
            }
        }

        let n_announces = messages.len();

        for (_, ref mut entry) in &mut self.responses {
            match entry.retransmit(transport_id) {
                RetransmitOutcome::Ready(msg) => messages.push(msg),
                RetransmitOutcome::Completed | RetransmitOutcome::Deferred => {}
            }
        }

        let n_responses = messages.len() - n_announces;

        // Remove path responses that were actually sent.  Keep any that
        // haven't reached their grace timeout yet — they will be sent on
        // the next `to_retransmit` cycle instead of being silently lost.
        self.responses.retain(|_, entry| entry.retries == 0);

        if !(messages.is_empty() && completed.is_empty()) {
            log::trace!(
                "Announce cache: {} retransmitted, {} path responses, {} dropped",
                n_announces,
                n_responses,
                completed.len(),
            );
        }

        for destination in completed {
            if let Some(announce) = self.map.remove(&destination) {
                self.cache.insert(destination, announce);
            }
        }

        messages
    }

    pub fn to_retransmit_old(&mut self, transport_id: &AddressHash) -> Vec<TxMessage> {
        let mut messages = vec![];

        if let Some(ref cache) = self.cache.newer {
            for (destination, ref entry) in cache {
                if self.responses.contains_key(destination) {
                    continue;
                }

                messages.push(entry.always_retransmit(transport_id));
            }
        }

        if let Some(ref cache) = self.cache.older {
            for (destination, ref entry) in cache {
                if self.responses.contains_key(destination) {
                    continue;
                }

                messages.push(entry.always_retransmit(transport_id));
            }
        }

        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ContextFlag, PacketDataBuffer};
    use tokio::time;

    /// A response added with a very long grace is not sent, and is
    /// retained for a later cycle instead of being silently cleared.
    #[tokio::test(start_paused = true)]
    async fn unsent_path_response_is_retained_across_cycles() {
        let mut table = AnnounceTable::new();
        let transport_id = AddressHash::new([0x01; 16]);
        let dest = AddressHash::new([0xaa; 16]);
        let iface = AddressHash::new([0xbb; 16]);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 1,
            },
            ifac: None,
            destination: dest,
            transport: Some(transport_id.clone()),
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[1, 2, 3]),
        };

        table.add(&packet, dest, iface);
        // Grace is short enough to expire in the second cycle (after
        // advancing 2s) but long enough that the first to_retransmit
        // (at T=0) cannot possibly reach it (100ms + 0..500ms jitter).
        table.add_response(dest, iface, 1, Duration::from_millis(100));

        // First to_retransmit at T=0: neither announce (pending response)
        // nor response (100ms + 0..500ms grace jitter has not expired).
        // BUG: responses.clear() silently deletes the response here.
        // FIX: responses.retain() keeps the unsent response.
        let msgs = table.to_retransmit(&transport_id);
        assert!(msgs.is_empty(), "neither announce nor response ready");

        // Advance past grace + max jitter so the response matures.
        time::advance(Duration::from_secs(2)).await;

        // Second to_retransmit at T=2s:
        // BUG:  response cleared in cycle 1 → announce sends instead
        //       (context=None, not a PathResponse)
        // FIX:  response retained in cycle 1 → now expired → IS sent
        //       (context=PathResponse)
        let msgs = table.to_retransmit(&transport_id);
        assert!(
            msgs.iter().any(|m| m.packet.context == PacketContext::PathResponse),
            "response (not announce) must be sent after grace expiry – it was retained",
        );
    }

    /// A response whose grace timeout expires IS sent on the next cycle.
    #[tokio::test(start_paused = true)]
    async fn expired_path_response_is_sent() {
        let mut table = AnnounceTable::new();
        let transport_id = AddressHash::new([0x01; 16]);
        let dest = AddressHash::new([0xaa; 16]);
        let iface = AddressHash::new([0xbb; 16]);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 1,
            },
            ifac: None,
            destination: dest,
            transport: Some(transport_id.clone()),
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[4, 5, 6]),
        };

        table.add(&packet, dest, iface);
        table.add_response(dest, iface, 1, Duration::from_millis(10));

        // First call — time is frozen, response timeout has not expired.
        let msgs = table.to_retransmit(&transport_id);
        assert!(msgs.is_empty(), "nothing should be sent yet");

        // Advance past the response's grace + jitter (10ms + 0..500ms).
        time::advance(Duration::from_secs(1)).await;

        // Second call — response should now be sent.
        let msgs = table.to_retransmit(&transport_id);
        assert!(
            msgs.iter().any(|m| m.packet.context == PacketContext::PathResponse),
            "response must be sent after grace expiry",
        );
    }

    /// A PathResponse received from a remote peer and added via `add()`
    /// retains its `PathResponse` context through `to_retransmit()` so
    /// that outbound mode-based filtering in `send_flush` recognises it.
    #[tokio::test(start_paused = true)]
    async fn remote_path_response_retains_context_through_retransmit() {
        let mut table = AnnounceTable::new();
        let transport_id = AddressHash::new([0x01; 16]);
        let dest = AddressHash::new([0xcc; 16]);
        let iface = AddressHash::new([0xdd; 16]);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 1,
            },
            ifac: None,
            destination: dest,
            transport: Some(transport_id.clone()),
            // Simulate a PathResponse received from a remote peer
            context: PacketContext::PathResponse,
            data: PacketDataBuffer::new_from_slice(&[7, 8, 9]),
        };

        table.add(&packet, dest, iface);

        // Advance past the initial jitter (0..500ms) so the entry
        // is eligible for retransmission.
        time::advance(Duration::from_secs(1)).await;

        let msgs = table.to_retransmit(&transport_id);

        assert_eq!(msgs.len(), 1, "one announce should be retransmitted");
        assert_eq!(
            msgs[0].packet.context,
            PacketContext::PathResponse,
            "PathResponse context must be preserved through to_retransmit()",
        );
    }

    /// A received announce must be rebroadcast on ALL interfaces, including
    /// the one it was received on. Excluding the ingress interface breaks
    /// multi-hop propagation on single-interface nodes (the announce is
    /// never forwarded to the next hop on the same shared medium). This
    /// matches the Python reference, which rebroadcasts on every interface
    /// and relies on packet-hash dedup + echo counting for loop control.
    #[tokio::test(start_paused = true)]
    async fn announce_rebroadcast_includes_ingress_interface() {
        let mut table = AnnounceTable::new();
        let transport_id = AddressHash::new([0x01; 16]);
        let dest = AddressHash::new([0xee; 16]);
        let ingress_iface = AddressHash::new([0xff; 16]);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 1,
            },
            ifac: None,
            destination: dest,
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[9, 8, 7]),
        };

        table.add(&packet, dest, ingress_iface);

        time::advance(Duration::from_secs(1)).await;

        let msgs = table.to_retransmit(&transport_id);

        assert_eq!(msgs.len(), 1, "one announce should be retransmitted");
        assert_eq!(
            msgs[0].tx_type,
            TxMessageType::BroadcastFrom(ingress_iface),
            "announce must be rebroadcast to all interfaces, carrying the \
             ingress interface as the mode-filtering origin (not excluded)",
        );
    }

    /// The archive cache drops entries whose announce is older than
    /// [`ANNOUNCE_CACHE_MAX_AGE`], preventing it from accumulating to the
    /// capacity cap on long-running nodes.
    #[tokio::test(start_paused = true)]
    async fn archive_cache_prunes_stale_entries() {
        let mut cache = AnnounceCache::new(10);
        let stale_dest = AddressHash::new([0x11; 16]);
        let fresh_dest = AddressHash::new([0x22; 16]);

        let mut stale_entry = make_announce_entry(stale_dest);
        stale_entry.timestamp = time::Instant::now();
        cache.insert(stale_dest, stale_entry);

        // Age the stale entry past the retention window, then add a fresh one.
        time::advance(ANNOUNCE_CACHE_MAX_AGE + Duration::from_secs(1)).await;
        let mut fresh_entry = make_announce_entry(fresh_dest);
        fresh_entry.timestamp = time::Instant::now();
        cache.insert(fresh_dest, fresh_entry);

        // Ensure the throttled prune interval has also elapsed so the sweep
        // actually runs.
        time::advance(ANNOUNCE_CACHE_PRUNE_INTERVAL + Duration::from_secs(1)).await;
        cache.prune(ANNOUNCE_CACHE_MAX_AGE);

        assert!(
            cache.get(&stale_dest).is_none(),
            "archive entries older than the max age must be pruned"
        );
        assert!(
            cache.get(&fresh_dest).is_some(),
            "recent archive entries must be retained"
        );
    }

    /// The archive-cache prune is throttled: sweeps before
    /// [`ANNOUNCE_CACHE_PRUNE_INTERVAL`] leave the cache untouched.
    #[tokio::test(start_paused = true)]
    async fn archive_cache_prune_is_throttled() {
        let mut cache = AnnounceCache::new(10);
        let dest = AddressHash::new([0x33; 16]);

        // An entry whose announce is already older than the max age, inserted
        // immediately after cache construction (so the prune throttle window
        // has not yet elapsed).
        let mut entry = make_announce_entry(dest);
        entry.timestamp = time::Instant::now() - (ANNOUNCE_CACHE_MAX_AGE + Duration::from_secs(1));
        cache.insert(dest, entry);

        // Still inside the throttle window: the sweep is skipped even though
        // the entry is stale.
        cache.prune(ANNOUNCE_CACHE_MAX_AGE);
        assert!(
            cache.get(&dest).is_some(),
            "prune must be throttled to ANNOUNCE_CACHE_PRUNE_INTERVAL"
        );

        // Once the throttle window has elapsed, the stale entry is dropped.
        time::advance(ANNOUNCE_CACHE_PRUNE_INTERVAL + Duration::from_secs(1)).await;
        cache.prune(ANNOUNCE_CACHE_MAX_AGE);
        assert!(
            cache.get(&dest).is_none(),
            "a sweep after the throttle window must prune stale entries"
        );
    }

    fn make_announce_entry(destination: AddressHash) -> AnnounceEntry {
        AnnounceEntry {
            packet: Packet {
                header: Header {
                    packet_type: PacketType::Announce,
                    destination_type: DestinationType::Single,
                    ..Default::default()
                },
                ifac: None,
                destination,
                transport: None,
                context: PacketContext::None,
                data: PacketDataBuffer::new_from_slice(&[1, 2, 3]),
            },
            timestamp: time::Instant::now(),
            timeout: time::Instant::now(),
            received_from: destination,
            retries: 0,
            local_rebroadcasts: 0,
            hops: 0,
            response_to_iface: None,
        }
    }
}
