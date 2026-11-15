# Rebuilding Curtain and its all-source index

## Clean clone: bounded, offline fixture verification

Install Python 3.11+, GNU sort and Rust >=1.87 on Linux, then run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r tools/requirements.txt
python -m unittest discover -s tools -p 'test_*.py' -v
cargo test --locked --manifest-path native/Cargo.toml
python tools/check_fixture_pipeline.py
```

The smoke script constructs tiny **synthetic** reserved example-domain source rows, performs the actual source-aware audit twice, compiles both outputs through the real Rust CLI, byte-compares indexes, checks all source flags and six independent linear-oracle queries, and packages/verifies an Ed25519 manifest. Keys are ephemeral, outside the repository; this does not sign as the production publisher. Expected deterministic fixture index: 158 bytes, SHA-256 `24cda4a741a9515d3ced3d7f99d16d5cb62e991d8fba0ecb1c2745a573b4bea5`. Timestamps, performance fields and generated keys/signatures are not deterministic outputs.

## Fresh full rebuild using exactly the published catalog URLs

These commands perform network requests and require substantial disk/RAM. Keep historical checked-in metadata untouched by using `rebuild/blocklists`. Raw downloads and normalization consume much more than the final 121 MB; reserve several GB of free disk and sufficient RAM for Python’s legacy experimental union and Rust encoding. No policy is filtered down to one publisher.

```sh
python tools/fetch_blocklists.py --root rebuild/blocklists \
  --snapshot data/blocklists/audit-manifest.json
python tools/audit_blocklists.py --root rebuild/blocklists \
  --report rebuild/list-audit.md
cargo build --release --locked --manifest-path native/Cargo.toml --bin compact-index
mkdir -p rebuild/indexes
native/target/release/compact-index build \
  rebuild/blocklists/canonical.tsv rebuild/indexes/rebuilt.fc
sha256sum rebuild/blocklists/canonical.tsv rebuild/indexes/rebuilt.fc
printf 'smoke\tdoubleclick.net\nsmoke\texample.com\n' > rebuild/queries.tsv
native/target/release/compact-index verify rebuild/indexes/rebuilt.fc \
  rebuild/blocklists/canonical.tsv rebuild/queries.tsv
```

`build` refuses to overwrite an existing output. Choose a new output name on reruns. `verify` checks **every** source membership and complete grouped flags, and checks a bounded sample (up to 32 per workload) against an independent linear source oracle; it is not exhaustive over all possible DNS names.

`--snapshot` fixes all 62 source URLs and preserves the recorded Firebog categories/recommendation markers through a minimal reconstructed HTML input; it does **not** download the historical Firebog page or promise its original HTML/hash. Source contents and availability change. Previously failed URLs may now succeed; a fresh index may have different counts and hash. No missing source is silently replaced with an alternative. For a new live Firebog catalog plus supplements, omit `--snapshot`.

### Exact historical byte reproduction boundary

For a bit-identical version-1 index you need the exact 59 archived source export bytes whose SHA-256 values are in `manifest.json` / `audit-manifest.json`, and the archived acquisition inputs hashed in `audit-summary.json`: `manifest.json`, `summary.json`, `firebog.html`, `firebog-catalog.txt`, `domains.experimental.txt`. The audit validates raw bytes before parsing. Given the same canonical TSV, the Rust index encoding is deterministic. Historical canonical SHA-256:

```text
63f29f5649066f3532eb3d9b20c422b59620ab20ccd18a63e56e707fa4ce9d14
```

Raw exports, canonical TSV and full fetched license/page blobs are **not bundled in this source repository**. Mutable upstream URLs cannot guarantee recovering those historical bytes; this repository alone is not a complete immutable data-source archive or a certification of corresponding-source compliance for all third-party data. Metadata, scripts and hashes enable verification when the exact inputs are available. The existing immutable compiled snapshot remains downloadable from the CDN. This limitation is deliberate and disclosed, not a claim of exact live re-download reproducibility.

## Where the lists came from

Acquisition: `https://v.firebog.net/hosts/lists.php?type=all`, with `https://firebog.net/` used for recommendation/category markers. The acquisition script unions that catalog with six supplement URLs (adult categories plus HaGeZi wildcard PRO, NSFW, Gambling and TIF). Some adult supplements already occur in Firebog, so the original union is 62 unique URLs; exact IDs are the first 20 hex digits of SHA-256(URL). Firebog’s ticked/unmarked/crossed-out classification is provenance, not safety certification or an automatic filter. The published policy includes supported rows even from crossed-out sources.

Historical failures (no rows in version 1): `https://hostsfile.mine.nu/hosts0.txt` (name resolution failure), `https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt` (timeout), `https://urlhaus.abuse.ch/downloads/hostfile/` (HTTP 410). See the catalog for exact recorded errors. Follow-up retrieval metadata is not silently substituted.

`domains.experimental.txt` is an older, lossy benchmark union produced by the downloader; **do not compile it**. Compile only the source-aware `canonical.tsv` from `audit_blocklists.py`. Unsupported/rejected diagnostics and per-source normalized TSV files are generated on rebuild; exact and suffix rules remain distinct. The compiler ORs semantic bits for identical domains across sources; provenance remains in the canonical TSV, not each binary record.

## Download and authenticate the existing snapshot

```sh
mkdir -p artifacts/r2/curtain/indexes
curl --fail --location https://cdn.clapbox.net/curtain/version.json -o artifacts/r2/curtain/version.json
curl --fail --location https://cdn.clapbox.net/curtain/indexes/000001.fc -o artifacts/r2/curtain/indexes/000001.fc
printf 'b88dd9abfe3d0dc8340a309c97cbdaff4c6f67002d83cab2a322003d2678c32c  artifacts/r2/curtain/indexes/000001.fc\n' | sha256sum -c -
python tools/verify_snapshot.py artifacts/r2/curtain/version.json artifacts/r2/curtain/indexes/000001.fc
```

The manifest is a moving pointer and may advance beyond v1; use the tracked `docs/index-v1-manifest.json` to authenticate the immutable version-1 file if it has advanced. The verifier rejects a path/name mismatch and size/hash/signature mismatch. Hash checking alone does not authenticate metadata; the verification key is `tools/update-public-key.pem`, also pinned in Android `UpdateTrust.kt`.

## Package your own snapshot (no upload)

```sh
python tools/prepare_update.py --source rebuild/indexes/rebuilt.fc \
  --output rebuild/package --version 1 \
  --key "$HOME/.local/share/curtain-test-signing/update.pem" \
  --public-key rebuild/test-public.pem
```

A first run creates a signing identity outside the checkout. Keep it secret. This is **your** key, not the production key; the shipping app will reject its signatures unless deliberately rebuilt with your public trust key. Never overwrite the tracked production public key with your own. New content needs a monotonically higher version; immutable outputs and existing signed metadata are checked. Packaging uploads nothing. Production private keys are not distributed.

## Android clean build

JDK 21, SDK platform 35, build-tools 35.0.0; set `ANDROID_HOME` or create ignored `android/local.properties`. Gradle wrapper 8.10.2, AGP 8.8.2, Kotlin 2.1.10; wrapper distribution SHA and dependency checksums are tracked.

```sh
(cd android && ./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug)
```

Output: `android/app/build/outputs/apk/debug/app-debug.apk`. Debug signing uses the local developer identity, not a distributed private keystore, so rebuilt APK bytes/signatures are not guaranteed to match the first release. Runtime Kotlin, resources, manifests, Gradle inputs and wrapper were copied from the tested development source; `docs/release-inputs.json` records original input hashes. Publication changes tests, host scripts and docs, not production app behavior. This is source-dump provenance, not a cryptographic attestation of the original build environment. The released APK was not replaced with the clean-clone build.

Three historical JVM integration tests require the full original snapshot/canonical TSV; they explicitly skip if absent. The remaining fixture tests work without massive downloads. To run those snapshot-specific checks, place the exact version-1 file at `native/compact-evidence/audited.fc`, the exact original canonical TSV at `data/blocklists/canonical.tsv`, and the original signed package under `artifacts/r2/curtain`. Their fixed assertions intentionally target the historical snapshot, not any later fresh rebuild. A rebuild with different upstream bytes is not expected to satisfy those fixed counts. The CDN test uses a local HTTP server, not a live publication test.

Original development tests reported 45 JVM tests passing. Physical-device observations were on Pixel 7 / Android 16: installation, VPN start, opt-in logging, allowed and blocked names, and in-app blocked filter. Search/Share/Clear were **not** independently verified on that phone. No phone is controlled by these build instructions; emulator scripts clear only a designated private emulator and must be reviewed before use.
