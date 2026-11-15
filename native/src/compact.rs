//! Static front-coded domain map. Keys are full bytes, never probabilistic hashes.
use sha2::{Digest, Sha256};
const HEADER: usize = 64;
const STRIDE: usize = 16;
const MAGIC: &[u8; 8] = b"CURTFC01";

#[derive(Default)]
pub struct Builder {
    payload: Vec<u8>,
    offsets: Vec<u64>,
    previous: String,
    count: usize,
}
impl Builder {
    pub fn push(&mut self, key: &str, flags: u8) -> Result<(), String> {
        if crate::normalize(key).as_deref() != Some(key) || flags == 0 || flags & !63 != 0 {
            return Err("invalid normalized key or flags".into());
        }
        if self.count > 0 && key <= self.previous.as_str() {
            return Err("keys must be strictly sorted".into());
        }
        let prefix = if self.count.is_multiple_of(STRIDE) {
            self.offsets.push(self.payload.len() as u64);
            0
        } else {
            key.bytes()
                .zip(self.previous.bytes())
                .take_while(|(a, b)| a == b)
                .count()
        };
        self.payload
            .extend_from_slice(&[prefix as u8, (key.len() - prefix) as u8, flags]);
        self.payload.extend_from_slice(&key.as_bytes()[prefix..]);
        self.previous.clear();
        self.previous.push_str(key);
        self.count += 1;
        Ok(())
    }
    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.offsets.len() * 8 + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.count as u64).to_le_bytes());
        out.extend_from_slice(&(self.offsets.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        out.resize(HEADER, 0);
        for offset in self.offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(&self.payload);
        let digest = digest(&out);
        out[32..64].copy_from_slice(&digest);
        out
    }
}
/// Headerless audit TSV; provenance is validated as a nonempty field, not discarded at source.
pub fn parse_row(line: &str) -> Result<(&str, u8), String> {
    let mut fields = line.trim_end_matches('\n').split('\t');
    let kind = fields.next().ok_or("missing kind")?;
    let key = fields.next().ok_or("missing domain")?;
    let source = fields.next().ok_or("missing source")?;
    if source.is_empty() || fields.next().is_some() || key.len() > 253 || !valid_key(key.as_bytes())
    {
        return Err("invalid audit row".into());
    }
    let flag = match kind {
        "exact" => 1,
        "suffix" => 2,
        "subdomains" => 4,
        "allow-exact" => 8,
        "allow-suffix" => 16,
        "allow-subdomains" => 32,
        _ => return Err("unsupported kind".into()),
    };
    Ok((key, flag))
}
fn valid_key(key: &[u8]) -> bool {
    key.split(|&b| b == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label[0] != b'-'
            && label[label.len() - 1] != b'-'
            && label
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    }) && std::str::from_utf8(key).is_ok_and(|s| s.parse::<std::net::IpAddr>().is_err())
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&bytes[..32]);
    h.update(&bytes[64..]);
    h.finalize().into()
}
pub fn encode(rules: &[(&str, u8)]) -> Result<Vec<u8>, String> {
    let mut builder = Builder::default();
    for &(key, flags) in rules {
        builder.push(key, flags)?;
    }
    Ok(builder.finish())
}
pub struct View<'a> {
    bytes: &'a [u8],
    blocks: usize,
    count: usize,
    start: usize,
}
fn u64_at(bytes: &[u8], pos: usize) -> usize {
    u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize
}
impl<'a> View<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < HEADER || &bytes[..8] != MAGIC {
            return Err("bad header".into());
        }
        let count = u64_at(bytes, 8);
        let blocks = u64_at(bytes, 16);
        let start = blocks
            .checked_mul(8)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or("size overflow")?;
        let end = start
            .checked_add(u64_at(bytes, 24))
            .ok_or("size overflow")?;
        if blocks != count.div_ceil(STRIDE)
            || end != bytes.len()
            || digest(bytes).as_slice() != &bytes[32..64]
        {
            return Err("size/count/checksum mismatch".into());
        }
        let view = Self {
            bytes,
            blocks,
            count,
            start,
        };
        let mut pos = start;
        let mut previous = [0u8; 253];
        let mut previous_len = 0;
        for i in 0..count {
            if i.is_multiple_of(STRIDE) && u64_at(bytes, HEADER + (i / STRIDE) * 8) != pos - start {
                return Err("bad block offset".into());
            }
            let head = bytes.get(pos..pos + 3).ok_or("truncated record")?;
            let prefix = head[0] as usize;
            let tail = head[1] as usize;
            let len = prefix + tail;
            if prefix > previous_len
                || len == 0
                || len > 253
                || head[2] == 0
                || head[2] & !63 != 0
                || (i.is_multiple_of(STRIDE) && prefix != 0)
            {
                return Err("bad record".into());
            }
            let rest = bytes.get(pos + 3..pos + 3 + tail).ok_or("truncated key")?;
            let mut key = previous;
            key[prefix..len].copy_from_slice(rest);
            if (i > 0 && key[..len] <= previous[..previous_len]) || !valid_key(&key[..len]) {
                return Err("unsorted or invalid key".into());
            }
            previous = key;
            previous_len = len;
            pos += 3 + tail;
        }
        if pos != bytes.len() {
            return Err("trailing bytes".into());
        }
        Ok(view)
    }
    fn offset(&self, block: usize) -> usize {
        self.start + u64_at(self.bytes, HEADER + block * 8)
    }
    fn first(&self, block: usize) -> &[u8] {
        let p = self.offset(block);
        &self.bytes[p + 3..p + 3 + self.bytes[p + 1] as usize]
    }
    pub fn flags(&self, key: &str) -> u8 {
        let mut lo = 0;
        let mut hi = self.blocks;
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.first(mid) <= key.as_bytes() {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return 0;
        }
        let block = lo - 1;
        let mut pos = self.offset(block);
        let mut buf = [0u8; 253];
        for _ in 0..STRIDE.min(self.count - block * STRIDE) {
            let prefix = self.bytes[pos] as usize;
            let tail = self.bytes[pos + 1] as usize;
            let flags = self.bytes[pos + 2];
            buf[prefix..prefix + tail].copy_from_slice(&self.bytes[pos + 3..pos + 3 + tail]);
            pos += 3 + tail;
            match buf[..prefix + tail].cmp(key.as_bytes()) {
                std::cmp::Ordering::Equal => return flags,
                std::cmp::Ordering::Greater => break,
                _ => {}
            }
        }
        0
    }
    /// Normalized ASCII DNS input only. Allow rules override all block rules.
    pub fn blocked(&self, host: &str) -> bool {
        let flags = self.flags(host);
        let mut block = flags & 3 != 0;
        let mut allow = flags & 24 != 0;
        for (i, _) in host.match_indices('.') {
            let f = self.flags(&host[i + 1..]);
            block |= f & 6 != 0;
            allow |= f & 48 != 0;
        }
        block && !allow
    }
    pub fn count(&self) -> usize {
        self.count
    }
}
