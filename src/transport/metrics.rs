use super::*;

use crate::destination::link::LinkStatus;
use crate::iface::{InterfaceQueueLengths, NamedReconnectPacerMetrics};

/// Per-type counters for received packets.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct PacketTypeCounters {
    pub announce: u64,
    pub link_request: u64,
    pub proof: u64,
    pub data: u64,
}

/// Snapshot of transport metrics intended for external collection.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TransportMetrics {
    /// Interface queue depth metrics.
    pub interface_queues: InterfaceQueueLengths,
    /// Number of entries currently known in the path table.
    pub path_table_entries: usize,
    /// Count of received packets by type since transport creation.
    pub packets_received_by_type: PacketTypeCounters,
    /// Number of duplicate inbound packets dropped.
    pub packets_dropped_duplicate: u64,
    /// Number of announces blocked by the rate limiter.
    pub announces_rate_limited: u64,
    /// Number of packets that failed decryption.
    pub decryption_failures: u64,
    /// Number of entries in the announce retransmit table.
    pub announce_table_entries: usize,
    /// Number of destinations retained in the announce archive cache.
    pub announce_cache_entries: usize,
    /// Number of distinct destinations cached from validated announces
    /// (bounded by the seven-day single-out destination expiry).
    pub single_out_destinations_entries: usize,
    /// Number of entries in the link forwarding table.
    pub link_table_entries: usize,
    /// Number of entries in the reverse path table.
    pub reverse_table_entries: usize,
    /// Number of entries in the duplicate packet cache.
    pub packet_cache_entries: usize,
    /// Number of outbound links currently in Active state.
    pub active_out_links: usize,
    /// Number of inbound links currently in Active state.
    pub active_in_links: usize,
    /// Total number of outbound link entries.
    pub total_out_links: usize,
    /// Total number of inbound link entries.
    pub total_in_links: usize,
    /// Number of non-cancelled interfaces registered with the manager.
    pub active_interfaces: usize,
    /// Number of pending discovery path requests.
    pub pending_path_requests: usize,
    /// Number of entries in the blackhole table.
    pub blackhole_entries: usize,
    /// Total data packets sent across all interfaces.
    pub total_packets_tx: u64,
    /// Total microseconds spent in pacing waits across all interfaces.
    pub total_pacing_wait_us: u64,
    /// Reconnect-pacer metrics from backbone server interfaces.
    pub reconnect_pacer_metrics: Vec<NamedReconnectPacerMetrics>,
}

impl Transport {
    /// Returns a metrics snapshot for transport-level collectors.
    pub async fn metrics(&self) -> TransportMetrics {
        let path_table_entries = self.path_table_len().await;
        let interface_queues = self.interface_queue_lengths().await;
        let packet_cache_entries = self.send_ctx.packet_cache.lock().unwrap().len();

        let handler = self.handler.lock().await;

        let mut active_out_links: usize = 0;
        let mut active_in_links: usize = 0;
        for link in handler.out_links.values() {
            if link.lock().await.status() == LinkStatus::Active {
                active_out_links += 1;
            }
        }
        for link in handler.in_links.values() {
            if link.lock().await.status() == LinkStatus::Active {
                active_in_links += 1;
            }
        }

        let active_interfaces = self
            .iface_manager
            .lock()
            .await
            .active_interface_addresses()
            .len();

        let total_packets_tx = interface_queues.interfaces.iter().map(|i| i.packets_tx).sum();
        let total_pacing_wait_us = interface_queues.interfaces.iter().map(|i| i.pacing_wait_us).sum();

        let reconnect_pacer_metrics = self.iface_manager.lock().await.reconnect_pacer_metrics();

        TransportMetrics {
            interface_queues,
            path_table_entries,
            packets_received_by_type: handler.packets_received_by_type,
            packets_dropped_duplicate: handler.packets_dropped_duplicate,
            announces_rate_limited: handler.announces_rate_limited,
            decryption_failures: handler.decryption_failures,
            announce_table_entries: handler.announce_table.entries_len(),
            announce_cache_entries: handler.announce_table.cache_len(),
            single_out_destinations_entries: handler.single_out_destinations.len(),
            link_table_entries: handler.link_table.len(),
            reverse_table_entries: handler.reverse_table.len(),
            packet_cache_entries,
            active_out_links,
            active_in_links,
            total_out_links: handler.out_links.len(),
            total_in_links: handler.in_links.len(),
            active_interfaces,
            pending_path_requests: handler.path_requests.pending_discovery_len(),
            blackhole_entries: handler.blackhole_table.len(),
            total_packets_tx,
            total_pacing_wait_us,
            reconnect_pacer_metrics,
        }
    }
}
