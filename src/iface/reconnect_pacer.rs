use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::iface::RECONNECT_REJECTION_BLOCK_THRESHOLD;

/// Per-source-IP reconnect backoff pacer.
///
/// Tracks how recently and how often each client IP address has connected
/// to a server-style interface (e.g. `BackboneServer`).  When the same IP
/// reconnects faster than its current backoff window, the connection is
/// rejected.  The backoff doubles on each accepted connection up to a
/// configurable maximum, preventing rapid reconnect storms from
/// misbehaving or buggy clients.
///
/// Additionally, a source IP that accumulates too many pacer rejections
/// (see [`RECONNECT_REJECTION_BLOCK_THRESHOLD`]) is blocklisted: every
/// subsequent connection from that IP is dropped immediately, before the
/// backoff check, so a connection-flooding client cannot keep consuming
/// accept/backoff work indefinitely.
pub(crate) struct ReconnectPacer {
    entries: HashMap<IpAddr, ReconnectEntry>,
    initial_backoff: Duration,
    max_backoff: Duration,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

struct ReconnectEntry {
    last_connect: Instant,
    backoff: Duration,
    /// Number of rejections this IP has accumulated while in backoff.
    rejections: u32,
    /// Set once `rejections` reaches the block threshold; while true the IP
    /// is blocklisted and all connections are dropped immediately.
    blocked: bool,
}

/// Snapshot of the reconnect pacer state for external metrics collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectPacerMetrics {
    /// Number of source IPs currently within their backoff window
    /// (i.e. would be rejected if they tried to reconnect right now).
    pub entries_in_backoff: usize,
    /// Total number of source IPs currently tracked by the pacer.
    pub total_tracked_ips: usize,
    /// Number of source IPs that have been blocklisted for exceeding the
    /// rejection threshold.
    pub blocked_ips: usize,
    /// Configured initial backoff duration.
    pub initial_backoff_ms: u64,
    /// Configured maximum backoff duration.
    pub max_backoff_ms: u64,
    /// Number of rejections that triggers a blocklist.
    pub block_threshold: usize,
}

impl ReconnectPacer {
    pub(crate) fn new(
        initial_backoff: Duration,
        max_backoff: Duration,
        cleanup_interval: Duration,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            initial_backoff,
            max_backoff,
            cleanup_interval,
            last_cleanup: Instant::now(),
        }
    }

    /// Returns `true` if the given IP is currently allowed to reconnect.
    /// Call this *after* accepting the TCP connection but *before* spawning
    /// the client handler.  Blocklisted IPs are always denied.
    pub(crate) fn is_allowed(&self, ip: IpAddr) -> bool {
        match self.entries.get(&ip) {
            Some(entry) => {
                if entry.blocked {
                    return false;
                }
                let now = Instant::now();
                now - entry.last_connect >= entry.backoff
            }
            None => true,
        }
    }

    /// Record a successful connection from this IP.  This updates the
    /// per-IP backoff window so subsequent rapid reconnects are rejected,
    /// and clears the accumulated rejection count (a legitimately accepted
    /// connection proves the IP is not merely flooding).
    /// Should be called only when `is_allowed()` returned `true`.
    pub(crate) fn record(&mut self, ip: IpAddr) {
        self.maybe_cleanup();

        let now = Instant::now();

        let is_first = !self.entries.contains_key(&ip);
        let entry = self.entries.entry(ip).or_insert(ReconnectEntry {
            last_connect: now,
            backoff: self.initial_backoff,
            rejections: 0,
            blocked: false,
        });

        if !is_first {
            let elapsed = now - entry.last_connect;
            if elapsed >= self.max_backoff {
                entry.backoff = self.initial_backoff;
            } else {
                entry.backoff = self.max_backoff.min(entry.backoff.saturating_mul(2));
            }
        }
        entry.last_connect = now;
        entry.rejections = 0;
    }

    /// Record a rejected (backoff-active or blocked) connection attempt from
    /// this IP.  Once the accumulated rejection count reaches the block
    /// threshold the IP is blocklisted and all further connections are
    /// dropped immediately.  Should be called only when `is_allowed()`
    /// returned `false`.
    pub(crate) fn record_rejection(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let entry = self.entries.entry(ip).or_insert(ReconnectEntry {
            last_connect: now,
            backoff: self.initial_backoff,
            rejections: 0,
            blocked: false,
        });
        entry.rejections = entry.rejections.saturating_add(1);
        if entry.rejections >= RECONNECT_REJECTION_BLOCK_THRESHOLD as u32 {
            entry.blocked = true;
        }
    }

    /// Returns `true` if this IP has been blocklisted for exceeding the
    /// rejection threshold.
    pub(crate) fn is_blocked(&self, ip: IpAddr) -> bool {
        self.entries
            .get(&ip)
            .map(|entry| entry.blocked)
            .unwrap_or(false)
    }

    /// Take a metrics snapshot without mutating internal state.
    pub(crate) fn metrics(&self) -> ReconnectPacerMetrics {
        let now = Instant::now();
        let entries_in_backoff = self
            .entries
            .values()
            .filter(|e| !e.blocked && now - e.last_connect < e.backoff)
            .count();
        let blocked_ips = self.entries.values().filter(|e| e.blocked).count();
        ReconnectPacerMetrics {
            entries_in_backoff,
            total_tracked_ips: self.entries.len(),
            blocked_ips,
            initial_backoff_ms: self.initial_backoff.as_millis() as u64,
            max_backoff_ms: self.max_backoff.as_millis() as u64,
            block_threshold: RECONNECT_REJECTION_BLOCK_THRESHOLD,
        }
    }

    fn maybe_cleanup(&mut self) {
        let now = Instant::now();
        if now - self.last_cleanup >= self.cleanup_interval {
            self.last_cleanup = now;
            let retain_duration = self.max_backoff.saturating_mul(2);
            self.entries
                .retain(|_, entry| !entry.blocked || now - entry.last_connect < retain_duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_ip_is_allowed() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(pacer.is_allowed(ip));
    }

    #[test]
    fn rapid_reconnect_is_rejected() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(pacer.is_allowed(ip));
        pacer.record(ip);

        // Immediate reconnect should be rejected
        assert!(!pacer.is_allowed(ip));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        // First connect — allowed, backoff becomes 1s
        assert!(pacer.is_allowed(ip));
        pacer.record(ip);

        // Simulate waiting past the backoff so we can connect again
        std::thread::sleep(Duration::from_millis(1100));

        // Second connect — backoff doubles to 2s
        assert!(pacer.is_allowed(ip));
        pacer.record(ip);

        // Should be rejected immediately
        assert!(!pacer.is_allowed(ip));

        std::thread::sleep(Duration::from_millis(2100));

        // Third connect — backoff doubles to 4s
        assert!(pacer.is_allowed(ip));
        pacer.record(ip);

        std::thread::sleep(Duration::from_millis(4100));

        // Fourth connect — backoff would be 8s but caps at 5s
        assert!(pacer.is_allowed(ip));
        pacer.record(ip);

        // Backoff stuck at 5s now
        assert!(!pacer.is_allowed(ip));
    }

    #[test]
    fn backoff_resets_after_long_absence() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.3".parse().unwrap();

        // Connect twice rapidly to build up backoff to 2s
        assert!(pacer.is_allowed(ip));
        pacer.record(ip);
        std::thread::sleep(Duration::from_millis(1100));

        assert!(pacer.is_allowed(ip));
        pacer.record(ip);
        assert!(!pacer.is_allowed(ip));

        // Wait longer than max_backoff (2s)
        std::thread::sleep(Duration::from_millis(2100));

        // Should reset to initial backoff
        assert!(pacer.is_allowed(ip));
        pacer.record(ip);
        // Now backoff is 1s again
        assert!(!pacer.is_allowed(ip));

        std::thread::sleep(Duration::from_millis(1100));
        assert!(pacer.is_allowed(ip));
    }

    #[test]
    fn different_ips_independent() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(pacer.is_allowed(ip_a));
        pacer.record(ip_a);
        assert!(!pacer.is_allowed(ip_a));
        assert!(pacer.is_allowed(ip_b));
    }

    #[test]
    fn ip_is_blocklisted_after_rejection_threshold() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // First rejection moves the untracked (allowed) IP into tracked-and-
        // rejected state; rejections accumulate below the threshold without
        // blocking.
        pacer.record_rejection(ip);
        for _ in 1..(RECONNECT_REJECTION_BLOCK_THRESHOLD - 1) {
            assert!(!pacer.is_blocked(ip));
            assert!(!pacer.is_allowed(ip));
            pacer.record_rejection(ip);
        }
        // Total rejections so far: 1 + (THRESHOLD - 2) = THRESHOLD - 1.
        assert!(!pacer.is_blocked(ip));

        // The threshold rejection flips the IP to blocked.
        assert!(!pacer.is_allowed(ip));
        pacer.record_rejection(ip);
        assert!(pacer.is_blocked(ip));
        assert!(!pacer.is_allowed(ip));
    }

    #[test]
    fn blocked_ip_is_denied_even_after_backoff_expires() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Build up to the block threshold.
        for _ in 0..RECONNECT_REJECTION_BLOCK_THRESHOLD {
            pacer.record_rejection(ip);
        }
        assert!(pacer.is_blocked(ip));

        // Even after a long wait (well past max_backoff), a blocked IP is
        // still denied immediately.
        std::thread::sleep(Duration::from_secs(1));
        assert!(!pacer.is_allowed(ip));
    }

    #[test]
    fn accepted_connection_resets_rejection_count() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Accumulate rejections below the threshold.
        for _ in 0..(RECONNECT_REJECTION_BLOCK_THRESHOLD - 1) {
            pacer.record_rejection(ip);
        }
        assert!(!pacer.is_blocked(ip));

        // A successful connection clears the rejection count.
        pacer.record(ip);
        assert!(!pacer.is_blocked(ip));
        assert!(!pacer.is_allowed(ip)); // now in backoff, but not blocked

        // Rejections start counting again from zero.
        for _ in 0..(RECONNECT_REJECTION_BLOCK_THRESHOLD - 1) {
            pacer.record_rejection(ip);
        }
        assert!(
            !pacer.is_blocked(ip),
            "rejections were not reset by record()"
        );
    }

    #[test]
    fn blocked_ips_are_not_counted_as_in_backoff() {
        let mut pacer = ReconnectPacer::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        let normal: IpAddr = "10.0.0.1".parse().unwrap();
        let blocked: IpAddr = "10.0.0.2".parse().unwrap();

        // normal IP in backoff
        pacer.record(normal);
        // blocked IP
        for _ in 0..RECONNECT_REJECTION_BLOCK_THRESHOLD {
            pacer.record_rejection(blocked);
        }
        assert!(pacer.is_blocked(blocked));

        let m = pacer.metrics();
        // Only the normal IP counts toward entries_in_backoff; blocked IPs are
        // tracked separately and excluded.
        assert_eq!(m.entries_in_backoff, 1);
        assert_eq!(m.total_tracked_ips, 2);
        assert_eq!(m.blocked_ips, 1);
        assert_eq!(m.block_threshold, RECONNECT_REJECTION_BLOCK_THRESHOLD);
    }
}
