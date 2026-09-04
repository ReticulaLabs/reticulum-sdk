use std::{
    cmp::min,
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{hash::Hash, packet::Packet};

pub struct PacketTrack {
    pub time: Instant,
    pub min_hops: u8,
}

pub struct PacketCache {
    map: HashMap<Hash, PacketTrack>,
    max_entries: usize,
}

impl PacketCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
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
            max_entries,
        }
    }

    #[cfg(test)]
    fn contains(&self, packet: &Packet) -> bool {
        self.map.contains_key(&packet.hash())
    }

    pub fn release(&mut self, duration: Duration) {
        self.map.retain(|_, track| track.time.elapsed() <= duration);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn update(&mut self, packet: &Packet) -> bool {
        let hash = packet.hash();

        let mut is_new_packet = false;

        let track = self.map.get_mut(&hash);
        if let Some(track) = track {
            track.time = Instant::now();
            track.min_hops = min(packet.header.hops, track.min_hops);
        } else {
            is_new_packet = true;

            if self.map.len() >= self.max_entries {
                // Bounded cache: evict the oldest entry so a traffic burst on
                // a busy network cannot grow the map without limit.
                let mut oldest: Option<Hash> = None;
                let mut oldest_time = Instant::now();
                for (key, track) in self.map.iter() {
                    if track.time < oldest_time {
                        oldest_time = track.time;
                        oldest = Some(*key);
                    }
                }
                if let Some(key) = oldest {
                    self.map.remove(&key);
                }
            }

            self.map.insert(
                hash,
                PacketTrack {
                    time: Instant::now(),
                    min_hops: packet.header.hops,
                },
            );
        }

        is_new_packet
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
}
