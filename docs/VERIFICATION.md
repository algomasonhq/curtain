# First public release verification

Executed during public-source preparation, 2026-11-15 (UTC). These are real host/tool results, not a claim of GitHub Actions CI or universal Android compatibility.

## Source-only clean checkout

Exported the exact staged tree to a separate clean directory (no local.properties, raw downloads, canonical TSV, signed package or native index):

| Command | Observed result |
|---|---|
| `python -m unittest discover -s tools -p 'test_*.py' -v` | 12 passed, including the mocked-network exact-62-URL acquisition test |
| `python tools/check_fixture_pipeline.py` | PASS: two audits, two deterministic Rust builds, all four fixture domain flags and six independent oracle probes; signed package verified |
| `cargo test --locked --manifest-path native/Cargo.toml` | 14 passed, no failed/ignored tests |
| `cargo fmt --manifest-path native/Cargo.toml --check` | PASS |
| `cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings` | PASS |
| `./gradlew --offline --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug` from android | BUILD SUCCESSFUL; 45 discovered JVM tests: 42 passed, 3 explicit optional-full-input skips, zero failures/errors; lint and APK build succeeded |

Gradle offline builds reused the installed dependency cache; this does not claim dependencies were fetched from an empty cache or that dependency services always remain available. No CI workflow was added.

## Full historical snapshot checks

Then supplied exact original canonical TSV and signed package as ignored integration inputs to that separate clean checkout and reran `:app:testDebugUnitTest --rerun-tasks`: **45 passed, zero failures/errors/skips**. This includes every canonical provenance row / complete compiled-domain flag equivalence, full snapshot count, actual local HTTP transfer of the 120,741,632-byte signed file and offline restore.

Separately built the actual public Rust compiler from the historical canonical TSV: **11,186,031 provenance rows**, **9,737,280 domains**, **120,741,632 bytes**, SHA-256 **b88dd9abfe3d0dc8340a309c97cbdaff4c6f67002d83cab2a322003d2678c32c**, exactly matching version 1. This was not a fresh network re-download of all upstream sources.

The public CDN manifest was read using curl and matched the local signed version-1 metadata. Python urllib returned HTTP 403 from this host; curl succeeded. No geographic/WAF cause is asserted. Signature, version/path, whole-file size and SHA-256 were independently verified using the tracked public key. No CDN objects were changed in this task.

## Release APK

Preserved the pre-existing tested APK, rather than substituting the clean-source build. Verified with apksigner and aapt, ZIP CRC checks, no bundled .fc/.so entries, package `org.curtain.dns`, min/target SDK 35, internal versionCode 2. Byte length **6,406,955**, SHA-256 **6d2f7de715c42754ecff2ea18abdcf721909423c540ab2a377b6bf3e6ad630e4**. It uses the existing **Android Debug** certificate (SHA-256 c08f9e18f2ac010a0081a3383b0e1deee4515e01f321e64831f188791a20fbc8), APK v2 signature. Private signing identity is not included.

All production Android source/manifests/resources and build inputs match the development hashes recorded in release-inputs.json. Test/host-tool/documentation changes are disclosed. The source-input record is not a cryptographic APK build attestation or a byte-reproducibility claim.

Device observations supplied from the preceding development session: Pixel 7 / Android 16 install, VPN start, logging toggle, allowed/blocked queries and in-app blocked filter. No phone actions were performed for public-source preparation; Search/Share/Clear were not independently verified on the physical phone.

## Publication safety

Curated new source tree with no imported history. Massive/raw datasets, build outputs, private signing keys, Android local.properties, credentials, phone query logs/screenshots and evidence directories are omitted. Checked staged content against known local credential values without displaying them; no matches. Gitleaks v8.30.1 (download checksum checked) scanned staged source with redaction: **no leaks found**. This is a bounded scan, not an absolute guarantee against every possible secret or sensitive value.
