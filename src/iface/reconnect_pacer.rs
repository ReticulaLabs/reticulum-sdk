use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Per-source-IP reconnect backoff pacer.
///
/// Tracks how recently and how often each client IP address has connected
/// to a server-style interface (e.g. `BackboneServer`).  When the same IP
/// reconnects faster than its current backoff window, the connection is
/// rejected.  The backoff doubles on each accepted connection up to a
/// configurable maximum, preventing rapid reconnect storms from
/// misbehaving or buggy clients.
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
    /// the client handler.
    pub(crate) fn is_allowed(&mut self, ip: IpAddr) -> bool {
        self.maybe_cleanup();

        match self.entries.get(&ip) {
            Some(entry) => {
                let now = Instant::now();
                now - entry.last_connect >= entry.backoff
            }
            None => true,
        }
    }

    /// Record a successful connection from this IP.  This updates the
    /// per-IP backoff window so subsequent rapid reconnects are rejected.
    /// Should be called only when `is_allowed()` returned `true`.
    pub(crate) fn record(&mut self, ip: IpAddr) {
        let now = Instant::now();

        let is_first = !self.entries.contains_key(&ip);
        let entry = self.entries.entry(ip).or_insert(ReconnectEntry {
            last_connect: now,
            backoff: self.initial_backoff,
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
    }

    fn maybe_cleanup(&mut self) {
        let now = Instant::now();
        if now - self.last_cleanup >= self.cleanup_interval {
            self.last_cleanup = now;
            let retain_duration = self.max_backoff.saturating_mul(2);
            self.entries
                .retain(|_, entry| now - entry.last_connect < retain_duration);
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
}
