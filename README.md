# Curtain

Experimental **Android 15+ DNS-only filtering VPN** with an on-device compact domain index, signed static CDN updates, and opt-in query logging. No account, backend service, root, CA installation, TLS interception, or analytics. Not a full-request or child-safety filter.

## Install the first APK

[v0.1.0 prerelease](https://github.com/algomasonhq/curtain/releases/tag/v0.1.0) contains `curtain-v0.1.0-debug.apk` and `SHA256SUMS`. This is explicitly **debug-signed**, experimental software—not a production signing identity or Play Store release. The internal Android version remains `0.2-cdn` / versionCode 2; v0.1.0 is the public project release tag.

```sh
sha256sum -c SHA256SUMS
adb install -r curtain-v0.1.0-debug.apk
```

First launch downloads and verifies the index before Start becomes available. Allow storage for the **120,741,632-byte** snapshot plus future retained versions; the APK is 6,406,955 bytes, not the total installed data. Tap Start and grant Android VPN consent. Stop closes the tunnel. Only one VPN can be active.

**Do not enable Android “Block connections without VPN” / lockdown**: ordinary connections intentionally travel outside this split-route VPN. Strict Private DNS had to be disabled in current device tests; this is not a universal compatibility claim. DoH, custom resolvers, direct IPs, caches and strict Private DNS can bypass filtering or interfere with resolution.

## What it does

* Captures IPv4 **UDP DNS only** to virtual resolver `10.111.0.2/32`; no default route. Ordinary IPv4/IPv6 traffic is not proxied. Allowed DNS goes, unencrypted, to Cloudflare `1.1.1.1:53` through protected sockets; that resolver sees those queries.
* Exact, inclusive suffix, subdomains-only and allow-override semantics. Blocked names receive NXDOMAIN. No HTTP paths, URLs, request bodies, HTTPS inspection, SafeSearch or YouTube restricted mapping. No TCP DNS fallback, DNS64 or IPv6-only upstream support.
* Downloads an authenticated immutable index from [the signed manifest](https://cdn.clapbox.net/curtain/version.json), verifies Ed25519, SHA-256 and full structure, then atomically publishes it. Failures retain the last working snapshot. Approximately 48-hour deferrable checks plus manual retry; apply a newer snapshot with Stop/Start. Old versions are retained.
* Optional **Query log**, off by default: bounded 2,000-entry memory ring, in-app filters/search/copy/share/clear. Debug builds additionally write bounded app-private JSONL and logcat while enabled. Logs are never automatically uploaded; explicit Share exports visible rows. No per-app attribution and no DoH/path visibility.

## Source and index provenance

This release uses the **all-source policy**, not a HaGeZi-only replacement. The frozen catalog has **62 exact URLs**, **59 successful inputs / 3 failures**, producing **9,737,280 distinct domains** from **11,186,031 source-aware provenance rows**. “All-source” means all successfully ingested inputs in that catalog, not every available list or every possible rule.

* [Rebuild / clean-clone instructions](docs/REPRODUCING.md)
* [Index format and ingestion semantics](docs/FORMAT.md)
* [Exact source IDs, URLs, hashes, status, markers and parser contracts](data/blocklists/audit-manifest.json)
* [Original ingestion totals and canonical checksum](data/blocklists/audit-summary.json)
* [Source-specific licensing findings](docs/source-licenses.md) / [machine-readable metadata](docs/source-licenses.json)
* [Third-party notices](THIRD_PARTY_NOTICES.md) and [release source-input hashes](docs/release-inputs.json)

Index version 1: [000001.fc](https://cdn.clapbox.net/curtain/indexes/000001.fc), SHA-256:

```text
b88dd9abfe3d0dc8340a309c97cbdaff4c6f67002d83cab2a322003d2678c32c
```

The list policy is aggressive and can overblock. Historical manifest fields `enabled:false` and `license_review:pending` describe the ingestion audit, not runtime exclusion: the compiler imports all supported rows of the 59 successful inputs. Publication was an explicit owner decision with unresolved source-specific licensing findings, **not legal clearance**. Upstream list terms are not replaced by this repository’s license.

## Develop

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r tools/requirements.txt
python -m unittest discover -s tools -p 'test_*.py' -v
python tools/check_fixture_pipeline.py
cargo test --locked --manifest-path native/Cargo.toml
# With JDK 21 and ANDROID_HOME containing platform 35 / build-tools 35.0.0:
(cd android && ./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug)
```

Python 3.11+, GNU sort, Rust 1.87+ (edition 2024 / integer APIs), JDK 21 and Android SDK are needed for the corresponding components. The small fixture pipeline needs Linux (`/proc` RSS inspection and file locking) and produces no production data or permanent key. See [Android details](android/README.md).

Owned app/compiler/tooling code: **GPL-3.0-only**, copyright 2026 Rocky / AlgoMason contributors. Third-party components retain their own licenses; see LICENSE and notices. Raw source downloads, massive normalized/canonical datasets, index binaries, signing keys, local configuration, phone logs/screenshots and private evidence are intentionally not in Git. Curtain Lab and support infrastructure are separate projects and are not included.
