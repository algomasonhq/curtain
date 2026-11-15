use std::collections::HashMap;

/// Packed reversed-byte strings with u32 end offsets and one suffix flag per rule.
/// Reversing bytes puts shared DNS suffixes together without allocating label nodes.
pub struct Packed {
    bytes: Vec<u8>,
    ends: Vec<u32>,
    suffix: Vec<bool>,
}
impl Packed {
    fn new(rules: &[(String, bool)]) -> Self {
        let mut order: Vec<usize> = (0..rules.len()).collect();
        order.sort_unstable_by(|&a, &b| rules[a].0.bytes().rev().cmp(rules[b].0.bytes().rev()));
        let mut p = Self {
            bytes: Vec::new(),
            ends: Vec::new(),
            suffix: Vec::new(),
        };
        for i in order {
            p.bytes.extend(rules[i].0.bytes().rev());
            p.ends
                .push(u32::try_from(p.bytes.len()).expect("packed index exceeds 4GiB"));
            p.suffix.push(rules[i].1);
        }
        p.bytes.shrink_to_fit();
        p.ends.shrink_to_fit();
        p.suffix.shrink_to_fit();
        p
    }
    fn get(&self, key: &[u8]) -> Option<bool> {
        let mut lo = 0;
        let mut hi = self.ends.len();
        while lo < hi {
            let i = lo + (hi - lo) / 2;
            let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
            match self.bytes[start..self.ends[i] as usize].cmp(key) {
                std::cmp::Ordering::Less => lo = i + 1,
                std::cmp::Ordering::Greater => hi = i,
                std::cmp::Ordering::Equal => return Some(self.suffix[i]),
            }
        }
        None
    }
    fn footprint(&self) -> usize {
        self.bytes.len() + self.ends.len() * 4 + self.suffix.len()
    }
}
pub enum Store {
    Sorted(Packed),
    Hashed(HashMap<String, bool>),
}
impl Store {
    fn get(&self, key: &str, reverse: &[u8]) -> Option<bool> {
        match self {
            Self::Sorted(p) => p.get(reverse),
            Self::Hashed(h) => h.get(key).copied(),
        }
    }
    fn matches(&self, host: &str) -> bool {
        let mut rev = [0u8; 253];
        for (i, b) in host.bytes().rev().enumerate() {
            rev[i] = b;
        }
        let rev = &rev[..host.len()];
        if self.get(host, rev).is_some() {
            return true;
        }
        for (i, _) in host.match_indices('.') {
            let suffix = &host[i + 1..];
            if self.get(suffix, &rev[..suffix.len()]) == Some(true) {
                return true;
            }
        }
        false
    }
    fn footprint(&self) -> usize {
        match self {
            Self::Sorted(p) => p.footprint(),
            Self::Hashed(h) => {
                h.keys().map(|s| s.len()).sum::<usize>()
                    + h.capacity() * (std::mem::size_of::<(String, bool)>() + 1)
            }
        }
    }
}
pub struct Index {
    block: Store,
    allow: Store,
}
impl Index {
    pub fn sorted(block: &[(String, bool)], allow: &[(String, bool)]) -> Self {
        Self {
            block: Store::Sorted(Packed::new(block)),
            allow: Store::Sorted(Packed::new(allow)),
        }
    }
    pub fn hashed(block: &[(String, bool)], allow: &[(String, bool)]) -> Self {
        Self {
            block: Store::Hashed(block.iter().cloned().collect()),
            allow: Store::Hashed(allow.iter().cloned().collect()),
        }
    }
    /// Input must already be a normalized hostname of at most 253 bytes.
    pub fn blocked(&self, host: &str) -> bool {
        !self.allow.matches(host) && self.block.matches(host)
    }
    pub fn contains_block_exact(&self, host: &str) -> bool {
        let rev: Vec<u8> = host.bytes().rev().collect();
        self.block.get(host, &rev).is_some()
    }
    pub fn footprint(&self) -> usize {
        self.block.footprint() + self.allow.footprint()
    }
}
