# Index format 1 and parser contracts

Canonical input is UTF-8, headerless `rule_type<TAB>normalized_domain<TAB>source_id`, sorted with `LC_ALL=C` by domain, type, source and deduplicated per source/type/domain. Allows are explicit, not flattened into blocks. IDNA uses pinned idna 3.20 (UTS46, non-transitional, STD3 / IDNA2008); IPs, URLs, local/reserved host names, invalid labels and unsupported syntax are rejected. Review `tools/audit_blocklists.py` for the exact accepted grammar.

* Hosts entries only accept sink addresses 0.0.0.0, 127.0.0.1, ::, ::1; following domains are exact.
* Plain domains are exact by default. Generic `*.domain` is descendant-only (apex excluded).
* Exact HaGeZi wildcard PRO/NSFW/Gambling/TIF URLs override `*.` to inclusive suffix, based on publisher export contracts. Jarelllama’s exact `wildcard_domains/scams.txt` URL treats plain domains as inclusive suffix. Arbitrary filename resemblance does not enable overrides.
* Only unmodified `||domain^` and `@@||domain^` become suffix and allow-suffix. Paths/modifiers/regex/cosmetic rules remain unsupported, never silently flattened. HTML/binary/error/invalid-UTF8/hash-mismatch downloads fail as a whole.
* Mirror exports may already have lost original adblock exceptions/context: normalization cannot recover that. Snapshot audit: 4,459 rejected row values, zero unsupported rows, 1,167 within-source duplicate occurrences; cross-source provenance is retained. Zero supported exceptions in this snapshot is not proof original upstream policies had none.
* Same-domain exact/suffix bits are preserved (501,907 overlaps in the snapshot). Compiler groups by domain and ORs flags; it does not remove nested suffix redundancy. Any applicable allow overrides any applicable block. Audit metadata `enabled:false` is historical audit state, not a compiler selection gate.

## Binary layout (`CURTFC01`)

All integer fields below are unsigned little-endian. Domains are sorted full ASCII keys (not hashes), front-coded in blocks of 16.

| Byte offset | Field |
|---|---|
| 0..8 | ASCII magic CURTFC01 |
| 8..16 | u64 domain count |
| 16..24 | u64 block count = ceil(domain count / 16) |
| 24..32 | u64 payload byte length |
| 32..64 | SHA-256 over bytes 0..32 concatenated with bytes 64..end (excludes digest field) |
| 64.. | block_count u64 offsets relative to payload start |
| after offsets | front-coded records |

Each record: `u8 prefix_length`, `u8 tail_length`, `u8 flags`, then tail bytes. Prefix length references the previous key; first record of each block has prefix zero. Reconstructed keys must be strictly sorted, valid lowercase LDH names, at most 253 bytes. Offset table, count, payload length, every record and embedded checksum are validated. This embedded hash is not a signature.

Flag bits: 1 exact block; 2 inclusive suffix block; 4 descendant-only block; 8 exact allow; 16 inclusive suffix allow; 32 descendant-only allow. Nonzero flags, no unknown bits. On lookup binary-search the first keys, decode up to 16 records per probe, then probe label ancestors. No probabilistic membership filter. Files are immutable while mapped; publish a new inode via atomic replacement, never truncate a mapped file.

## Signed distribution metadata

Fields are `version`, `format` (1), `file` (indexes/NNNNNN.fc), `bytes`, `sha256`, plus Base64 `signature`. Ed25519 signs UTF-8 JSON of the five metadata fields with sorted keys, compact separators and no ASCII escaping, excluding signature. The external SHA-256 covers the **entire** .fc file. Android additionally restricts paths/endpoint, size/time, format and version monotonicity. A signature authenticates publisher metadata, not domain quality, copyright clearance or universal DNS coverage.
