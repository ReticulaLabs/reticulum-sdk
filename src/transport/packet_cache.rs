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
}

impl PacketCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
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
