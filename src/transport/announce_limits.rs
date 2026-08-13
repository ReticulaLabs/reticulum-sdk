use alloc::collections::BTreeMap;

use tokio::time::Duration;
use tokio::time::Instant;

use crate::hash::AddressHash;

pub struct AnnounceRateLimit {
    pub target: Duration,
    pub grace: u32,
    pub penalty: Option<Duration>,
}

impl Default for AnnounceRateLimit {
    fn default() -> Self {
        Self {
            target: Duration::from_secs(3600),
            grace: 10,
            penalty: Some(Duration::from_secs(7200)),
        }
    }
}

pub struct AnnounceLimitEntry {
    pub rate_limit: Option<AnnounceRateLimit>,
    pub violations: u32,
    pub last_announce: Instant,
    pub blocked_until: Instant,
}

impl AnnounceLimitEntry {
    pub fn new(rate_limit: Option<AnnounceRateLimit>) -> Self {
        Self {
            rate_limit,
            violations: 0,
            last_announce: Instant::now(),
            blocked_until: Instant::now(),
        }
    }

    pub fn handle_announce(&mut self) -> Option<Duration> {
        let now = Instant::now();

        // No rate limit configured → never block.  Matches the Python
        // reference, where the limiter is disabled unless an interface
        // explicitly sets `announce_rate_target`.
        let Some(rate_limit) = self.rate_limit.as_ref() else {
            return None;
        };

        // While blocked, the block runs for a fixed duration anchored at
        // block time and is NOT extended by further announces.  Python
        // computes `blocked_until = last + target + penalty` once and only
        // checks it against the current time (Transport.py should_add).
        if now < self.blocked_until {
            return Some(self.blocked_until.saturating_duration_since(now));
        }

        let next_allowed = self.last_announce + rate_limit.target;
        if now < next_allowed {
            // The announce arrived sooner than the target: count a
            // violation and block once it exceeds the grace allowance.
            self.violations += 1;
            if self.violations > rate_limit.grace {
                self.violations = 0;
                let penalty = rate_limit.penalty.unwrap_or(Duration::ZERO);
                // Anchor the block to the last accepted announce, exactly
                // like Python (`rate_entry["last"] + target + penalty`),
                // so it cannot be kept alive by the blocked node itself.
                self.blocked_until = self.last_announce + rate_limit.target + penalty;
                return Some(self.blocked_until.saturating_duration_since(now));
            }
            // Within grace: accept and refresh the reference time.
            self.last_announce = now;
        } else {
            // Well-behaved (announcements spaced out): decay the violation
            // counter toward zero and accept.
            self.violations = self.violations.saturating_sub(1);
            self.last_announce = now;
        }

        None
    }
}

pub struct AnnounceLimits {
    limits: BTreeMap<AddressHash, AnnounceLimitEntry>,
}

impl AnnounceLimits {
    pub fn new() -> Self {
        Self {
            limits: BTreeMap::new(),
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = (&AddressHash, &AnnounceLimitEntry)> {
        self.limits.iter()
    }

    pub fn check(&mut self, destination: &AddressHash) -> Option<Duration> {
        if let Some(entry) = self.limits.get_mut(destination) {
            return entry.handle_announce();
        }

        // Disabled by default: Python's `announce_rate_target` is `None`
        // unless explicitly configured, and there is no configuration
        // surface for it here yet.  Entries therefore never block unless a
        // rate limit is supplied (currently only via tests).
        self.limits.insert(destination.clone(), AnnounceLimitEntry::new(None));

        None
    }

    /// Remove entries whose `last_announce` is older than `max_age`.
    /// Returns the number of pruned entries.
    pub fn prune(&mut self, max_age: Duration) -> usize {
        let now = Instant::now();
        let before = self.limits.len();
        self.limits.retain(|_, entry| {
            let age = now.saturating_duration_since(entry.last_announce);
            age < max_age
        });
        before - self.limits.len()
    }

    #[cfg(test)]
    pub(crate) fn force_block(&mut self, destination: AddressHash, duration: Duration) {
        let mut entry = AnnounceLimitEntry::new(Some(AnnounceRateLimit::default()));
        entry.blocked_until = Instant::now() + duration;
        self.limits.insert(destination, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_limit() -> AnnounceRateLimit {
        AnnounceRateLimit {
            target: Duration::from_secs(10),
            grace: 2,
            penalty: Some(Duration::from_secs(30)),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_by_default_never_blocks() {
        let mut entry = AnnounceLimitEntry::new(None);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(entry.handle_announce().is_none());
        assert_eq!(entry.violations, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn violations_decay_on_well_behaved_announces() {
        let mut entry = AnnounceLimitEntry::new(Some(enabled_limit()));
        // Model a destination that has been quiet for longer than the
        // target: the first announce is well-spaced and accepted cleanly.
        entry.last_announce = tokio::time::Instant::now() - Duration::from_secs(30);
        assert!(entry.handle_announce().is_none());
        assert_eq!(entry.violations, 0);

        // Two announces within the 10s target: two violations, still within
        // the grace of 2, so both accepted.
        for _ in 0..2 {
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(entry.handle_announce().is_none());
        }
        assert_eq!(entry.violations, 2);

        // A well-spaced announce (> target) decays the counter toward zero
        // instead of accumulating a permanent violation.
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(entry.handle_announce().is_none());
        assert_eq!(entry.violations, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn block_anchored_to_last_accepted_and_includes_penalty() {
        let mut entry = AnnounceLimitEntry::new(Some(enabled_limit()));
        entry.last_announce = tokio::time::Instant::now() - Duration::from_secs(30);
        assert!(entry.handle_announce().is_none());

        // Two accepted announces within the target (grace is 2).
        for _ in 0..2 {
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(entry.handle_announce().is_none());
        }

        // The next within-target announce exceeds the grace of 2 and
        // triggers a block anchored to the last ACCEPTED announce plus
        // target + penalty (10s + 30s), exactly like Python.
        let last_accepted = entry.last_announce;
        tokio::time::advance(Duration::from_secs(2)).await;
        let remaining = entry.handle_announce().expect("announce triggers block");
        assert!(!remaining.is_zero());
        assert_eq!(
            entry.blocked_until - last_accepted,
            Duration::from_secs(10) + Duration::from_secs(30),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn block_is_not_extended_by_further_announces() {
        let mut entry = AnnounceLimitEntry::new(Some(enabled_limit()));
        entry.blocked_until = tokio::time::Instant::now() + Duration::from_secs(60);

        let blocked_until = entry.blocked_until;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(entry.handle_announce().is_some(), "announce still blocked");
        }

        // The block expiry is fixed and must not creep forward.
        assert_eq!(entry.blocked_until, blocked_until);
    }
}
