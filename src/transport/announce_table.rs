use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rand_core::OsRng;
use rand_core::RngCore;
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

fn random_rw_jitter() -> Duration {
    Duration::from_millis(OsRng.next_u64() % (PATHFINDER_RW_MILLIS + 1))
}

#[derive(Clone)]
pub struct AnnounceEntry {
    pub packet: Packet,
    pub timestamp: Instant,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub local_rebroadcasts: u8,
    pub hops: u8,
    pub response_to_iface: Option<AddressHash>,
}

impl AnnounceEntry {
    pub fn retransmit(&mut self, transport_id: &AddressHash) -> Option<TxMessage> {
        if self.retries >= LOCAL_REBROADCASTS_MAX || self.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
            return None;
        }

        if Instant::now() < self.timeout {
            return None;
        }

        self.retries += 1;
        self.timeout = Instant::now() + Duration::from_secs(PATHFINDER_G) + random_rw_jitter();

        Some(self.always_retransmit(transport_id))
    }

    /// Retransmit immediately, bypassing the timeout check.
    /// Used by `new_packet` when a new announce arrives for an already-tracked destination.
    pub fn retransmit_now(&mut self, transport_id: &AddressHash) -> Option<TxMessage> {
        if self.retries >= LOCAL_REBROADCASTS_MAX || self.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
            return None;
        }

        self.retries += 1;
        self.timeout = Instant::now() + Duration::from_secs(PATHFINDER_G) + random_rw_jitter();

        Some(self.always_retransmit(transport_id))
    }

    pub fn always_retransmit(&self, transport_id: &AddressHash) -> TxMessage {
        let context = if self.response_to_iface.is_some() {
            PacketContext::PathResponse
        } else {
            PacketContext::None
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

        let tx_type = match self.response_to_iface {
            Some(iface) => TxMessageType::Direct(iface),
            None => TxMessageType::Broadcast(Some(self.received_from)),
        };

        TxMessage { tx_type, packet }
    }
}

struct AnnounceCache {
    newer: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    older: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    capacity: usize,
}

impl AnnounceCache {
    fn new(capacity: usize) -> Self {
        Self {
            newer: Some(BTreeMap::new()),
            older: None,
            capacity,
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
            cache: AnnounceCache::new(100000), // TODO make capacity configurable
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

    pub fn get_mut(&mut self, destination: &AddressHash) -> Option<&mut AnnounceEntry> {
        self.map.get_mut(destination)
    }

    pub fn remove(&mut self, destination: &AddressHash) {
        self.map.remove(destination);
    }

    /// Handle an echo of our own retransmission: increment the
    /// local_rebroadcasts counter and remove the entry if the maximum
    /// has been reached. Returns `true` if the entry was removed
    /// (announce propagation complete).
    pub fn echo_received(&mut self, destination: &AddressHash, hops: u8) -> bool {
        if let Some(entry) = self.map.get_mut(destination) {
            if entry.retries > 0 && hops > 0 && hops - 1 == entry.hops {
                entry.local_rebroadcasts += 1;
                if entry.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                    self.map.remove(destination);
                    return true;
                }
            }
        }
        false
    }

    pub fn new_packet(
        &mut self,
        dest_hash: &AddressHash,
        transport_id: &AddressHash,
    ) -> Option<TxMessage> {
        self.map
            .get_mut(dest_hash)
            .map_or(None, |e| e.retransmit_now(transport_id))
    }

    pub fn to_retransmit(&mut self, transport_id: &AddressHash) -> Vec<TxMessage> {
        let mut messages = vec![];
        let mut completed = vec![];

        for (destination, ref mut entry) in &mut self.map {
            if self.responses.contains_key(destination) {
                continue;
            }

            if let Some(message) = entry.retransmit(transport_id) {
                messages.push(message);
            } else {
                completed.push(destination.clone());
            }
        }

        let n_announces = messages.len();

        for (_, ref mut entry) in &mut self.responses {
            if let Some(message) = entry.retransmit(transport_id) {
                messages.push(message);
            }
        }

        let n_responses = messages.len() - n_announces;

        self.responses.clear(); // every response is only retransmitted once

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
