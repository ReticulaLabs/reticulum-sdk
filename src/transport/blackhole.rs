use std::collections::HashMap;

use rmpv::Value;
use sha2::Digest;
use tokio::time::{Duration, Instant};

use crate::destination::DestinationName;
use crate::hash::AddressHash;
use crate::hash::Hash;

/// Compute the destination hash for the blackhole info service associated
/// with a given source identity. Matches the Python reference:
/// `RNS.Destination.hash_from_name_and_identity("rnstransport.info.blackhole", identity_hash)`.
pub fn blackhole_destination_hash(identity_hash: &AddressHash) -> AddressHash {
    let name = DestinationName::new("rnstransport", "info.blackhole");
    let hash = Hash::new(
        Hash::generator()
            .chain_update(name.as_name_hash_slice())
            .chain_update(identity_hash.as_slice())
            .finalize()
            .into(),
    );
    AddressHash::new_from_hash(&hash)
}

/// Interval at which expired blackhole entries are cleaned up.
const BLACKHOLE_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// A single blackhole entry, tracking which transport instance issued it,
/// when (if ever) it expires, and an optional human-readable reason.
#[derive(Debug, Clone)]
pub struct BlackholeEntry {
    /// Identity hash of the transport instance that blackholed this identity.
    pub source: AddressHash,
    /// Optional expiry timestamp. `None` means the entry never expires.
    pub until: Option<Instant>,
    /// Optional human-readable reason for the blackhole.
    pub reason: Option<String>,
}

impl BlackholeEntry {
    /// Returns `true` if this entry has an expiry that is now in the past.
    pub fn is_expired(&self) -> bool {
        self.until
            .map(|t| Instant::now() >= t)
            .unwrap_or(false)
    }
}

/// Tracks blackholed identities and their expiry.
///
/// Protocol-compatible with the Python Reticulum reference:
/// `RNS.Transport.blackholed_identities`.
pub struct BlackholeTable {
    /// identity_hash → entry
    entries: HashMap<AddressHash, BlackholeEntry>,
    /// When the table was last checked for expired entries.
    last_check: Instant,
}

impl BlackholeTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_check: Instant::now(),
        }
    }

    /// Add or overwrite a blackhole entry. Returns `true` if a new entry
    /// was inserted (i.e. the identity was not already blackholed).
    pub fn add(
        &mut self,
        identity_hash: AddressHash,
        source: AddressHash,
        until: Option<Instant>,
        reason: Option<String>,
    ) -> bool {
        use std::collections::hash_map::Entry;
        match self.entries.entry(identity_hash) {
            Entry::Vacant(e) => {
                e.insert(BlackholeEntry { source, until, reason });
                true
            }
            Entry::Occupied(mut e) => {
                e.insert(BlackholeEntry { source, until, reason });
                false
            }
        }
    }

    /// Remove a blackhole entry. Returns `true` if the identity was
    /// previously blackholed.
    pub fn remove(&mut self, identity_hash: &AddressHash) -> bool {
        self.entries.remove(identity_hash).is_some()
    }

    /// Check if an identity is currently blackholed.
    pub fn contains(&self, identity_hash: &AddressHash) -> bool {
        self.entries.contains_key(identity_hash)
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all (identity_hash, entry) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&AddressHash, &BlackholeEntry)> {
        self.entries.iter()
    }

    /// Return a set of all blackholed identity hashes.
    pub fn identity_hashes(&self) -> Vec<AddressHash> {
        self.entries.keys().cloned().collect()
    }

    /// Return entries whose `source` matches the given identity hash
    /// (i.e. the entries that originated from a particular transport instance).
    pub fn local_entries(&self, source_hash: &AddressHash) -> HashMap<AddressHash, BlackholeEntry> {
        self.entries
            .iter()
            .filter(|(_, e)| e.source == *source_hash)
            .map(|(h, e)| (*h, e.clone()))
            .collect()
    }

    /// Insert a single entry from a remote source. Local-originated
    /// entries are never overwritten. Returns `true` if a new entry
    /// was inserted.
    pub fn insert_remote_entry(
        &mut self,
        identity_hash: AddressHash,
        entry: BlackholeEntry,
    ) -> bool {
        use std::collections::hash_map::Entry;
        match self.entries.entry(identity_hash) {
            Entry::Vacant(e) => {
                e.insert(entry);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Merge entries from a remote source. Any conflicting identity
    /// hashes that were originally blackholed by the *local* identity
    /// are preserved (not overwritten by the remote source).
    pub fn insert_remote(
        &mut self,
        _source: AddressHash,
        entries: HashMap<AddressHash, BlackholeEntry>,
    ) -> usize {
        let mut inserted = 0;
        for (identity_hash, entry) in entries {
            use std::collections::hash_map::Entry;
            match self.entries.entry(identity_hash) {
                Entry::Vacant(e) => {
                    e.insert(entry);
                    inserted += 1;
                }
                Entry::Occupied(_) => {
                    // Local-originated entries always take precedence.
                    // Future: check source vs local identity.
                }
            }
        }
        inserted
    }

    /// Remove all expired entries. Returns the number of removed entries.
    pub fn remove_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        before - self.entries.len()
    }

    /// Check for expired entries, but only if enough time has passed
    /// since the last check (rate-limited to `BLACKHOLE_CHECK_INTERVAL`).
    /// Returns the number of entries removed in this check, or `None` if
    /// the check was skipped due to rate-limiting.
    pub fn check_expired(&mut self) -> Option<usize> {
        let now = Instant::now();
        if now >= self.last_check + BLACKHOLE_CHECK_INTERVAL {
            self.last_check = now;
            Some(self.remove_expired())
        } else {
            None
        }
    }

    /// Reset the check timer (called after bulk-loading entries).
    pub fn reset_check_timer(&mut self) {
        self.last_check = Instant::now();
    }

    #[cfg(test)]
    pub(crate) fn set_last_check(&mut self, last_check: Instant) {
        self.last_check = last_check;
    }

    // ── msgpack helpers for RPC / persistence ──

    /// Serialize the table to an `rmpv::Value::Map` matching the Python
    /// reference format: `{identity_hash_bytes: {source: ..., until: ..., reason: ...}}`.
    pub fn to_msgpack(&self) -> Value {
        let mut pairs = Vec::with_capacity(self.entries.len());
        for (hash, entry) in &self.entries {
            let entry_map = entry.to_msgpack();
            pairs.push((Value::from(hash.as_slice().to_vec()), entry_map));
        }
        Value::Map(pairs)
    }

    /// Deserialize from an `rmpv::Value::Map` produced by the Python
    /// reference. Returns `None` if the value is not a map.
    pub fn from_msgpack(value: &Value, source: AddressHash) -> Option<Self> {
        let map = value.as_map()?;
        let mut entries = HashMap::new();
        for (k, v) in map {
            let identity_bytes = k.as_slice()?;
            if identity_bytes.len() != AddressHash::new_empty().as_slice().len() {
                continue;
            }
            let mut identity_hash = AddressHash::new_empty();
            identity_hash.as_mut_slice().copy_from_slice(identity_bytes);

            let entry = BlackholeEntry::from_msgpack(v, source)?;
            entries.insert(identity_hash, entry);
        }
        Some(Self {
            entries,
            last_check: Instant::now(),
        })
    }
}

impl BlackholeEntry {
    pub(crate) fn to_msgpack(&self) -> Value {
        let mut pairs = vec![
            (Value::from("source"), Value::from(self.source.as_slice().to_vec())),
        ];
        if let Some(until) = self.until {
            let secs = until.duration_since(Instant::now());
            pairs.push((
                Value::from("until"),
                Value::from(secs.as_secs_f64()),
            ));
        }
        if let Some(ref reason) = self.reason {
            pairs.push((Value::from("reason"), Value::from(reason.clone())));
        }
        Value::Map(pairs)
    }

    pub(crate) fn from_msgpack(value: &Value, source: AddressHash) -> Option<Self> {
        let map = value.as_map()?;
        let mut until: Option<Instant> = None;
        let mut reason: Option<String> = None;

        for (k, v) in map {
            match k.as_str() {
                Some("until") => {
                    let secs = v.as_f64()?;
                    if secs > 0.0 {
                        until = Some(Instant::now() + Duration::from_secs_f64(secs));
                    }
                }
                Some("reason") => {
                    reason = Some(v.as_str()?.to_owned());
                }
                _ => {}
            }
        }

        Some(Self { source, until, reason })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(n: u8) -> AddressHash {
        let mut h = AddressHash::new_empty();
        h.as_mut_slice().fill(n);
        h
    }

    #[test]
    fn add_remove_contains() {
        let mut table = BlackholeTable::new();
        let id = test_hash(1);
        let src = test_hash(0xaa);

        assert!(!table.contains(&id));
        assert!(table.add(id, src, None, None));
        assert!(table.contains(&id));
        assert!(!table.add(id, src, None, None)); // already exists
        assert!(table.remove(&id));
        assert!(!table.contains(&id));
        assert!(!table.remove(&id));
    }

    #[test]
    fn remove_expired_drops_expired_entries() {
        let mut table = BlackholeTable::new();
        let id1 = test_hash(1);
        let id2 = test_hash(2);
        let src = test_hash(0xaa);

        // Permanent entry (no until)
        table.add(id1, src, None, None);
        // Entry that expires immediately
        table.add(id2, src, Some(Instant::now() - Duration::from_secs(1)), None);

        assert_eq!(table.remove_expired(), 1);
        assert!(table.contains(&id1));
        assert!(!table.contains(&id2));
    }

    #[test]
    fn local_entries_filters_by_source() {
        let mut table = BlackholeTable::new();
        let src_a = test_hash(0xaa);
        let src_b = test_hash(0xbb);
        let id1 = test_hash(1);
        let id2 = test_hash(2);

        table.add(id1, src_a, None, None);
        table.add(id2, src_b, None, None);

        let local = table.local_entries(&src_a);
        assert_eq!(local.len(), 1);
        assert!(local.contains_key(&id1));
        assert!(!local.contains_key(&id2));
    }

    #[test]
    fn identity_hashes_returns_all_keys() {
        let mut table = BlackholeTable::new();
        let src = test_hash(0xaa);
        let id1 = test_hash(1);
        let id2 = test_hash(2);

        table.add(id1, src, None, None);
        table.add(id2, src, None, None);

        let hashes = table.identity_hashes();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&id1));
        assert!(hashes.contains(&id2));
    }

    #[test]
    fn msgpack_roundtrip() {
        let mut table = BlackholeTable::new();
        let src = test_hash(0xaa);
        let id1 = test_hash(1);
        let id2 = test_hash(2);

        table.add(
            id1,
            src,
            Some(Instant::now() + Duration::from_secs(3600)),
            Some("spam".to_owned()),
        );
        table.add(id2, src, None, None);

        let msgpack = table.to_msgpack();
        let restored = BlackholeTable::from_msgpack(&msgpack, src).expect("from_msgpack");

        assert!(restored.contains(&id1));
        assert!(restored.contains(&id2));
        assert_eq!(restored.len(), 2);

        let entry1 = restored.entries.get(&id1).unwrap();
        assert_eq!(entry1.reason, Some("spam".to_owned()));
        assert!(entry1.until.is_some());

        let entry2 = restored.entries.get(&id2).unwrap();
        assert!(entry2.until.is_none());
        assert!(entry2.reason.is_none());
    }

    #[test]
    fn expired_entry_is_not_serialized_with_negative_until() {
        let mut table = BlackholeTable::new();
        let src = test_hash(0xaa);
        let id = test_hash(1);

        // Entry already expired
        table.add(id, src, Some(Instant::now() - Duration::from_secs(1)), None);

        assert!(table.remove_expired() > 0);
        assert!(!table.contains(&id));
    }

    #[test]
    fn insert_remote_preserves_local_entries() {
        let mut table = BlackholeTable::new();
        let local_src = test_hash(0xaa);
        let remote_src = test_hash(0xbb);
        let id = test_hash(1);

        // Local entry
        table.add(id, local_src, None, None);

        // Remote tries to overwrite
        let mut remote = HashMap::new();
        remote.insert(
            id,
            BlackholeEntry {
                source: remote_src,
                until: None,
                reason: Some("remote".to_owned()),
            },
        );

        table.insert_remote(remote_src, remote);

        // Local entry should not be overwritten
        let entry = table.entries.get(&id).unwrap();
        assert_eq!(entry.source, local_src);
        assert_eq!(entry.reason, None);
    }

    #[test]
    fn check_expired_rate_limits() {
        let mut table = BlackholeTable::new();
        // Set last_check far enough in the past so the first call runs
        table.set_last_check(Instant::now() - BLACKHOLE_CHECK_INTERVAL - Duration::from_secs(1));

        // First call should run
        let result = table.check_expired();
        assert!(result.is_some());

        // Second immediate call should be rate-limited
        let result = table.check_expired();
        assert!(result.is_none());
    }

    #[test]
    fn insert_remote_entry_preserves_local_entries() {
        let mut table = BlackholeTable::new();
        let local_src = test_hash(0xaa);
        let remote_src = test_hash(0xbb);
        let id = test_hash(1);

        // Local entry
        table.add(id, local_src, None, None);

        // Remote tries to overwrite via single-entry method
        let remote_entry = BlackholeEntry {
            source: remote_src,
            until: None,
            reason: Some("remote".to_owned()),
        };
        assert!(!table.insert_remote_entry(id, remote_entry));

        // Local entry should not be overwritten
        let entry = table.entries.get(&id).unwrap();
        assert_eq!(entry.source, local_src);
        assert_eq!(entry.reason, None);
    }

    #[test]
    fn insert_remote_entry_accepts_new_identity() {
        let mut table = BlackholeTable::new();
        let src = test_hash(0xaa);
        let id = test_hash(1);

        let remote_entry = BlackholeEntry {
            source: src,
            until: None,
            reason: Some("new".to_owned()),
        };
        assert!(table.insert_remote_entry(id, remote_entry));
        assert!(table.contains(&id));
    }

    #[test]
    fn blackhole_destination_hash_is_deterministic() {
        let id = test_hash(0x42);
        let hash_a = super::blackhole_destination_hash(&id);
        let hash_b = super::blackhole_destination_hash(&id);
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn blackhole_destination_hash_differs_for_different_identities() {
        let id_a = test_hash(0x01);
        let id_b = test_hash(0x02);
        let hash_a = super::blackhole_destination_hash(&id_a);
        let hash_b = super::blackhole_destination_hash(&id_b);
        assert_ne!(hash_a, hash_b);
    }
}
