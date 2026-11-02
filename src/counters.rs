//! Counters keyed by two label values, for the series whose labels are not known until a
//! request has been answered.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A monotonically increasing counter per `(first, second)` label pair.
#[derive(Debug, Default)]
pub struct LabeledCounters {
    counts: Mutex<BTreeMap<(String, String), u64>>,
}

impl LabeledCounters {
    pub fn increment(&self, first: &str, second: &str) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        *counts
            .entry((first.to_string(), second.to_string()))
            .or_insert(0) += 1;
    }

    pub fn get(&self, first: &str, second: &str) -> u64 {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(first.to_string(), second.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Every pair seen so far, in label order.
    pub fn snapshot(&self) -> Vec<(String, String, u64)> {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|((a, b), n)| (a.clone(), b.clone(), *n))
            .collect()
    }
}
