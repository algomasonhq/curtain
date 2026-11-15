# Third-party notices and licensing boundaries

## Owned source

Copyright 2026 Rocky / AlgoMason contributors. Owned Curtain Kotlin, Rust and Python code and project documentation are licensed **GPL-3.0-only** (LICENSE). This does not relicense upstream data or third-party software. The public-source preparation changes portable host tooling, fixture coverage, and documentation; it does not claim authorship of upstream lists. Normalization/compilation transforms source lists by grammar validation, IDNA normalization, type-preserving deduplication and front-coding; it is not an unmodified copy of any list.

## Blocklist publishers and data

Every catalog publisher is credited by its exact input and publisher URL in [audit-manifest.json](data/blocklists/audit-manifest.json), together with source IDs, input checksums and semantics. Per-source **observed licenses, findings, obligations and official legal/README URLs with retrieval timestamps/hashes** are in [source-licenses.json](docs/source-licenses.json) and the [readable table](docs/source-licenses.md). These notices are part of this release; no blanket permissive data grant is asserted.

Firebog supplies catalog/recommendation metadata: https://firebog.net/ and https://v.firebog.net/hosts/lists.php?type=all . HaGeZi’s four supplements are published at https://github.com/hagezi/dns-blocklists ; its published-list GPL grant does not itself relicense every underlying input. Jarelllama, AdAway, Frogeye, EasyList/Firebog mirrors, Dan Pollock, MVPS, RPiList, yhosts, Disconnect and all other included publishers retain their applicable rights; the full table is authoritative for the recorded source-specific findings.

The historical independent review did **not** certify redistribution clearance. The owner explicitly chose public all-source publication nevertheless. Outstanding issues include noncommercial/NoDerivatives/ShareAlike/custom terms, mirror vs upstream authority, differing historical/current license versions, no verified grant for some sources and unfinished transitive input review. Their historical `publication_approved:false` / pending flags are retained, not presented as operational policy selection. No legal certification is supplied.

Raw downloads and full fetched LICENSE/README/page evidence are not vendored here; recorded file paths identify historical local archive objects, not promised repository files. Exact quotations in original audit headers are short provenance notices. Official response URLs/timestamps/hashes are retained as metadata. A link and compiler alone may not discharge GPL corresponding-source or other source/notice obligations for an immutable third-party data artifact; no claim of completed data-license compliance is made. Exact historical byte reproduction needs the archived inputs described in REPRODUCING.md.

## Software dependencies

Dependency manifests, lockfiles and Gradle checksum metadata preserve exact selections. No dependency source trees are vendored (except the Gradle wrapper JAR). Dependencies retain their own notices and licenses, not the owned-source GPL notice:

* Gradle wrapper: Gradle Inc. / contributors, Apache-2.0; https://github.com/gradle/gradle . Full Apache-2.0 text: licenses/Apache-2.0.txt.
* Kotlin standard library / Kotlin tooling: JetBrains / contributors, Apache-2.0; https://github.com/JetBrains/kotlin . Android Gradle Plugin and AndroidX WorkManager/runtime dependencies: Android Open Source Project / contributors, Apache-2.0; https://android.googlesource.com/ and https://developer.android.com/jetpack/androidx/releases/work . See published artifact notices for included transitive components.
* net.i2p.crypto:eddsa:0.3.0: https://github.com/str4d/ed25519-java ; use its upstream license/notices (public-domain/CC0 dedication for implementation, third-party notices retained by upstream). Explicit signature provider; no production private key included.
* Python idna 3.20: https://github.com/kjd/idna (BSD-3-Clause); cryptography 46.0.3: https://github.com/pyca/cryptography (Apache-2.0 OR BSD-3-Clause). These are build/audit tools, not Android runtime code.
* Rust crates are not vendored. `native/Cargo.lock` pins memmap2, sha2, serde_json and transitives; authoritative package license fields and full source/notices are in their downloaded crate archives on crates.io. Run `cargo metadata --locked --manifest-path native/Cargo.toml` to inspect all resolved package licenses.
* JUnit 4.13.2 (EPL-1.0) is test-only, not shipped runtime code: https://junit.org/junit4/ .

This file is an attribution and boundary statement, not a warranty that all inherited data rights or future uses are cleared. Preserve all applicable upstream notices when redistributing software dependencies or data.
