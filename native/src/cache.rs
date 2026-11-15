use std::collections::{BTreeMap, HashMap};
/// Single-thread benchmark cache. Generation must change for every policy replacement.
/// BTreeMap recency is O(log capacity), strictly bounded (no stale queue entries).
pub struct DecisionCache {
    cap: usize,
    generation: u64,
    tick: u64,
    values: HashMap<String, (bool, u64)>,
    order: BTreeMap<u64, String>,
}
impl DecisionCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            generation: 0,
            tick: 0,
            values: HashMap::new(),
            order: BTreeMap::new(),
        }
    }
    fn sync(&mut self, generation: u64) {
        if self.generation != generation || self.tick == u64::MAX {
            self.values.clear();
            self.order.clear();
            self.tick = 0;
            self.generation = generation;
        }
    }
    pub fn get(&mut self, key: &str, generation: u64) -> Option<bool> {
        self.sync(generation);
        let (value, old) = *self.values.get(key)?;
        self.order.remove(&old);
        self.tick += 1;
        self.order.insert(self.tick, key.to_owned());
        self.values.get_mut(key).unwrap().1 = self.tick;
        Some(value)
    }
    pub fn put(&mut self, key: &str, value: bool, generation: u64) {
        self.sync(generation);
        if self.cap == 0 {
            return;
        }
        if let Some((_, old)) = self.values.remove(key) {
            self.order.remove(&old);
        }
        if self.values.len() == self.cap {
            let (_, key) = self.order.pop_first().unwrap();
            self.values.remove(&key);
        }
        self.tick += 1;
        self.values.insert(key.to_owned(), (value, self.tick));
        self.order.insert(self.tick, key.to_owned());
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}
