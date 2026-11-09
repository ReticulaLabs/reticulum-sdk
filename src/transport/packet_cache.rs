use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::{hash::Hash, packet::Packet};

/// Extra LRU-order entries tolerated beyond 1.5× the live map size before the
/// order queue is compacted.  Stale entries accumulate when a packet is seen
/// more than once (the cache is updated on every sighting), but they are
/// skipped lazily during eviction.
const ORDER_COMPACT_SLACK: usize = 1024;

pub struct PacketTrack {
    pub time: Instant,
    pub min_hops: u8,
    /// Monotonically increasing recency stamp.  Latest sighting wins, so the
    /// smallest live stamp is the least-recently-seen entry.
    seq: u64,
}

pub struct PacketCache {
    map: HashMap<Hash, PacketTrack>,
    /// Recency-ordered `(seq, hash)` queue.  Entries whose stamp no longer
    /// matches `map[hash].seq` are stale (the packet was seen again) and are
    /// skipped when they reach the front.  This replaces a full-map scan to
    /// find the least-recently-seen entry.
    order: VecDeque<(u64, Hash)>,
    next_seq: u64,
    max_entries: usize,
}

impl PacketCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
            #[cfg(not(feature = "embedded"))]
			// 250k seems like a reasonable limit given today's backbone loads
            max_entries: 250_000,
            #[cfg(feature = "embedded")]
            max_entries: 8192,
        }
    }

    #[cfg(test)]
    fn with_max_entries(max_entries: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
            max_entries,
        }
    }

    #[cfg(test)]
    fn contains(&self, packet: &Packet) -> bool {
        self.map.contains_key(&packet.hash())
    }

    pub fn release(&mut self, duration: Duration) {
        // The order queue is sorted by recency stamp, and a stamp is only
        // refreshed when the packet is seen again.  Therefore the queue front
        // is always the oldest live entry, and expiry can stop at the first
        // entry that is still within the retention window instead of sweeping
        // the whole map.
        while let Some(&(seq, hash)) = self.order.front() {
            let expired = {
                let track = match self.map.get(&hash) {
                    Some(track) if track.seq == seq => track,
                    _ => {
                        // Superseded by a later sighting, or already removed.
                        self.order.pop_front();
                        continue;
                    }
                };

                track.time.elapsed() > duration
            };

            if !expired {
                break;
            }

            self.order.pop_front();
            self.map.remove(&hash);
        }

        self.maybe_compact();
    }

    /// Remove a specific packet's hash from the cache so a later
    /// retransmission of the same packet is not treated as a duplicate.
    /// Mirrors Python's `Transport.py:2593-2594`, which removes the hash
    /// from `packet_hashlist`/`packet_hashlist_prev` when a link-associated
    /// packet is dropped on an unexpected interface, so the link can still
    /// receive the packet when it finally arrives over the correct path.
    pub fn release_packet(&mut self, packet: &Packet) {
        self.map.remove(&packet.hash());
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn update(&mut self, packet: &Packet) -> bool {
        let hash = packet.hash();
        let now = Instant::now();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        if let Some(track) = self.map.get_mut(&hash) {
            track.time = now;
            track.min_hops = min(packet.header.hops, track.min_hops);
            track.seq = seq;
            self.order.push_back((seq, hash));
            self.maybe_compact();
            return false;
        }

        if self.map.len() >= self.max_entries {
            // Bounded cache: evict the least-recently-seen entry so a traffic
            // burst on a busy network cannot grow the map without limit.
            self.evict_oldest();
        }

        self.map.insert(
            hash,
            PacketTrack {
                time: now,
                min_hops: packet.header.hops,
                seq,
            },
        );
        self.order.push_back((seq, hash));
        self.maybe_compact();

        true
    }

    /// Evict the oldest live entry from the recency queue.
    fn evict_oldest(&mut self) -> Option<Hash> {
        while let Some((seq, hash)) = self.order.pop_front() {
            if self.map.get(&hash).is_some_and(|track| track.seq == seq) {
                self.map.remove(&hash);
                return Some(hash);
            }
        }

        None
    }

    /// Drop superseded/stale order entries once they outnumber the live map
    /// by a comfortable margin.  Rebuilding is O(n log n) but happens rarely
    /// (roughly once per 1.5× cache churn), keeping steady-state updates
    /// O(1) amortised.
    fn maybe_compact(&mut self) {
        let threshold = self
            .map
            .len()
            .saturating_add(self.map.len() / 2)
            .saturating_add(ORDER_COMPACT_SLACK);
        if self.order.len() > threshold {
            self.rebuild_order();
        }
    }

    fn rebuild_order(&mut self) {
        let mut entries: Vec<(u64, Hash)> = self
            .map
            .iter()
            .map(|(hash, track)| (track.seq, *hash))
            .collect();
        entries.sort_unstable_by_key(|(seq, _)| *seq);
        self.order = entries.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, PacketDataBuffer};
    use std::thread;

    fn packet(data: u8) -> Packet {
        let mut p = Packet::default();
        p.data = PacketDataBuffer::new_from_slice(&[data]);
        p
    }

    /// Distinct packets with strictly increasing timestamps so LRU eviction
    /// order is deterministic regardless of `Instant` resolution.
    fn insert_new(cache: &mut PacketCache, data: u8) {
        assert!(cache.update(&packet(data)), "packet {data} should be new");
        thread::sleep(Duration::from_millis(1));
    }

    #[test]
    fn cache_len_never_exceeds_max_entries() {
        let mut cache = PacketCache::with_max_entries(4);
        for i in 0..64 {
            insert_new(&mut cache, i);
            assert!(cache.len() <= 4, "cache grew beyond its bound");
        }
    }

    #[test]
    fn oldest_entry_is_evicted_when_full() {
        let mut cache = PacketCache::with_max_entries(4);
        for i in 0..8 {
            insert_new(&mut cache, i);
        }

        // Only the newest 4 packets survive eviction.
        assert_eq!(cache.len(), 4);
        for i in 0..4 {
            assert!(
                !cache.contains(&packet(i)),
                "oldest packet {i} must have been evicted"
            );
        }
        for i in 4..8 {
            assert!(
                cache.contains(&packet(i)),
                "newest packet {i} must be retained"
            );
        }
    }

    #[test]
    fn recently_seen_entries_are_not_evicted() {
        let mut cache = PacketCache::with_max_entries(3);
        insert_new(&mut cache, 0);
        insert_new(&mut cache, 1);
        insert_new(&mut cache, 2);

        // Touch packet 0 so it becomes the most recently seen.
        assert!(!cache.update(&packet(0)));

        // A new packet should evict the least-recently-seen entry (1),
        // leaving the refreshed 0 in place.
        insert_new(&mut cache, 3);

        assert!(
            cache.contains(&packet(0)),
            "refreshed packet 0 must survive"
        );
        assert!(
            !cache.contains(&packet(1)),
            "least-recently-seen packet 1 must be evicted"
        );
        assert!(cache.contains(&packet(2)), "packet 2 must survive");
        assert!(cache.contains(&packet(3)), "new packet 3 must be present");
    }

    #[test]
    fn duplicates_do_not_grow_the_cache() {
        let mut cache = PacketCache::with_max_entries(4);
        insert_new(&mut cache, 7);
        insert_new(&mut cache, 8);

        for _ in 0..100 {
            assert!(!cache.update(&packet(7)));
            assert!(!cache.update(&packet(8)));
        }

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn release_packet_allows_retransmission_to_pass_again() {
        let mut cache = PacketCache::with_max_entries(4);

        // First arrival is new and cached.
        assert!(cache.update(&packet(42)));
        // A retransmission would normally be filtered as a duplicate.
        assert!(!cache.update(&packet(42)));

        // After release, the same packet is treated as new again, so a
        // retransmission arriving on the correct interface is processed.
        cache.release_packet(&packet(42));
        assert!(!cache.contains(&packet(42)));
        assert!(cache.update(&packet(42)));
    }

    #[test]
    fn release_packet_of_unknown_packet_is_a_noop() {
        let mut cache = PacketCache::with_max_entries(4);
        insert_new(&mut cache, 1);

        cache.release_packet(&packet(99));

        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&packet(1)));
    }

    #[test]
    fn release_expires_from_front_and_keeps_lru_order() {
        let mut cache = PacketCache::with_max_entries(3);
        insert_new(&mut cache, 0);
        insert_new(&mut cache, 1);
        insert_new(&mut cache, 2);

        // Age the oldest entry past the retention window without touching the
        // other entries, so only the queue front is expired.
        let stale_hash = packet(0).hash();
        cache.map.get_mut(&stale_hash).unwrap().time = Instant::now() - Duration::from_secs(10);

        cache.release(Duration::from_secs(1));

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&packet(0)));
        assert!(cache.contains(&packet(1)));
        assert!(cache.contains(&packet(2)));

        // The LRU order must remain valid after the partial expiry: packet 1
        // is still the oldest live entry and is evicted first.
        insert_new(&mut cache, 3);
        insert_new(&mut cache, 4);

        assert!(!cache.contains(&packet(1)));
        assert!(cache.contains(&packet(2)));
        assert!(cache.contains(&packet(3)));
        assert!(cache.contains(&packet(4)));
    }

    #[test]
    fn release_packet_preserves_lru_order_for_remaining_entries() {
        let mut cache = PacketCache::with_max_entries(3);
        insert_new(&mut cache, 0);
        insert_new(&mut cache, 1);
        insert_new(&mut cache, 2);

        cache.release_packet(&packet(1));

        // Inserting past the cap must skip the removed entry and evict the
        // oldest remaining packet (0), not the newest one.
        insert_new(&mut cache, 3);
        insert_new(&mut cache, 4);

        assert!(!cache.contains(&packet(0)));
        assert!(!cache.contains(&packet(1)));
        assert!(cache.contains(&packet(2)));
        assert!(cache.contains(&packet(3)));
        assert!(cache.contains(&packet(4)));
    }

    #[test]
    fn repeated_updates_do_not_grow_the_order_queue_without_bound() {
        let mut cache = PacketCache::with_max_entries(4);
        insert_new(&mut cache, 7);

        for _ in 0..(ORDER_COMPACT_SLACK + 8) {
            assert!(!cache.update(&packet(7)));
        }

        let threshold = cache
            .map
            .len()
            .saturating_add(cache.map.len() / 2)
            .saturating_add(ORDER_COMPACT_SLACK);
        assert!(
            cache.order.len() <= threshold,
            "stale order entries must be compacted"
        );
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&packet(7)));
    }
}
