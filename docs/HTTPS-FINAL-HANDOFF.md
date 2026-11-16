# Final private HTTPS browsing APK handoff

> **Physical Pixel 7 follow-up (supersedes the old physical/arm64 gate below):**
> Actual Android 16 Chrome allow/block/replacement and arm64 TUN POST/stream/persistent-connection
> tests now pass after fixing SOCKS UDP-association worker starvation. Current privately installed
> APK: `artifacts/pixel-verification/curtain-pixel-fixed-debug.apk`, 8,899,878 bytes,
> SHA-256 `c2bf14b69cc83bff96152f19f6f69d9437c0335172b949741d31c407892f1839`.
> One matching AndroidCAStore entry/one user CA, unchanged installation fingerprint; no private key
> export or trust-store mutation. Final normal-use mode is DNS-only, with query and URL logging
> preferences enabled and the saved `/modified` replacement rule preserved. Clean verification:
> 121 JVM tests, zero failures/errors, three optional skips; lint 47 warnings/no errors.
> Full private evidence/report: `artifacts/pixel-verification/PHYSICAL-HTTPS-RESULT.md`,
> `physical-verification.json`, `pixel-network-local.txt` and actual Chrome screenshots.
> Original APK and historical evidence below remain preserved. No public release/push/CDN write.

## Delivery

- Repository: `/home/debian/www/curtain-public`, local `feature/https-inspection`.
- Installable app: `artifacts/curtain-https-browsing-debug.apk` (8,899,878 bytes).
- SHA-256: `687459babf7bcf2eea3272364e647d4da5a63411583a1f5f21805f3ef9364797`.
- Debug signer SHA-256: `c08f9e18f2ac010a0081a3383b0e1deee4515e01f321e64831f188791a20fbc8`.
- Instrumentation companion: `artifacts/curtain-https-browsing-test.apk`; not the end-user app.
- Historical `curtain-https-vpn-debug.apk` remains preserved but is **not** this final browsing build.

## Independently verified on resumption

Read the previous completed-child transcript and retained evidence before starting any emulator.
Ran one serialized **clean** build against current source:

```sh
cd /home/debian/www/curtain-public/android
export JAVA_HOME=/home/debian/.local/share/curtain-toolchain/jdk-21.0.13+9
export ANDROID_HOME=/home/debian/.local/share/curtain-toolchain/sdk
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew --no-daemon clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleDebugAndroidTest
```

Actual result: **BUILD SUCCESSFUL in 33s; 84 tasks executed**. Parsed JUnit XML:
**120 tests, 0 failures, 0 errors, 3 optional skips**. Lint: **47 warnings, 0 errors/fatal**.
The freshly rebuilt production APK is byte-for-byte identical to the delivered APK and the
previously emulator-tested production artifact, including its complete ZIP entry contents.
No expensive emulator rerun was needed. Production source was not changed during this audit.

From repository root, with the same toolchain environment:

```sh
python3 android/tools/verify_download_apk.py --inspection artifacts/curtain-https-browsing-debug.apk
"$ANDROID_HOME/build-tools/35.0.0/zipalign" -c -P 16 -v 4 artifacts/curtain-https-browsing-debug.apk
sha256sum artifacts/curtain-https-browsing-debug.apk
```

Actual APK v2 signature, SDK35 manifest, ZIP CRC, absence of bundled index/private CA identities,
arm64-v8a/x86_64 native entries and 16 KiB ZIP alignment pass. Independently decoded ELF PT_LOAD
alignments are 16384 for all four segments in each native library. This is not 16 KiB-device execution.

Machine record: `artifacts/final-verification.json`; archived build/signature/alignment logs and
665 input-file hashes: `artifacts/resumed-final-audit/`. The record hashes retained emulator
evidence so future audits can distinguish old runs from new ones. `git diff --check` passes.
No scoped emulator, harness, Gradle daemon or OpenCode run remains; unrelated shared services
were not stopped. All earlier tracked/untracked work and artifacts were preserved.

## Completed real Android evidence, not inferred from unit tests

`artifacts/browsing-vpn-evidence/final-artifact-run.txt` and `origin.json` record API35 x86_64
actual default-route TUN traffic with no explicit client proxy:

- Allow/block/replacement produce exact 19/30/24-byte fixture payloads.
- Fixed and chunked POST each echo **2,097,169 bytes**; **3,145,731-byte** streamed response.
- Both POSTs and the stream GET share **one downstream TLS connection**.
- Origin sees exactly four requests: `/allowed`, `/echo?n=0`, `/echo?n=1`, `/stream`.
  Block/replacement never reach it. Untrusted fixture origin is rejected with 502.
- Public HTTPS, IPv4/IPv6 TUN DNS, unchanged DNS-only split routing, actual VPN removal,
  three rapid Start/Stop cycles and normal platform-trusted HTTPS after Stop pass.

The network fixture provisions installation CA trust in its own test client and uses test-APK
reflection for its ephemeral origin certificate. This alone is **not** Android user-store
onboarding. Separate actual UI evidence does exercise that onboarding:

- `ca-upgrade.json`: package replacement preserves private-root hash and public fingerprint.
- `artifacts/ca-ui-evidence/ca-rotation-export-red.txt`: actual in-app confirmation widget already
  completed rotation and recorded exact old/new identities and one atomic root file; a subsequent
  document-export harness assertion failed. Retained as partial success plus real failure, not an
  overall PASS.
- `artifacts/ca-ui-evidence/ca-instrumentation.txt`: later completed test resumes that rotation,
  verifies process-restart reuse, performs actual document-provider Save and Settings CA warning /
  file-picker installation, and reads back **old absent, new present, exactly one user CA**. PASS.
- UI hierarchy evidence retains initial installed-CA detail and actual Settings removal confirmation.

Both identities have subject `CN=Curtain local inspection CA,OU=Curtain`:

- Exact old/new installation fingerprints are retained only in private test evidence.
- Public source contains no installation certificate or signing key.

These are emulator-only identities, not included in the APK. No private key was copied.

## CA behavior and user operation

Ordinary restarts, service starts, exports and same-installation app upgrades reuse the one
app-private no-backup root. Uninstall/reinstall or clearing app data is not preservation of the
same installation; an existing user-installed certificate may then need manual Settings cleanup.

For explicit rotation: stop inspection; Begin rotation; identify the exact old fingerprint in
Android Settings and remove it; return and explicitly confirm. Export/new-install guidance and
inspection service starts are gated while pending. A fresh read-only AndroidCAStore probe must
observe old-fingerprint absence before atomic private-root replacement; unreadable store blocks it.
Then export and install the replacement through Settings. Curtain cannot silently uninstall a user
CA: that requires device/profile-owner or authorized certificate-install delegate privileges, which
this normal app does not request. The app's fingerprint probe is an observation, not a silent-purge
claim. Only public certificates are exported; leaf identities remain in memory.

## Current scope and remaining gates

GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS; streamed uploads/responses; no former 1 MiB response cap;
64 MiB uploads; 15s idle/I/O timeout; up to 1000 requests per connection. Downstream HTTP/2,
WebSocket/Upgrade, non-DNS UDP/QUIC, fragmented multi-record ClientHello and server-first TCP
remain unsupported. TLS-pinned/apps not trusting user roots may not work. No arbitrary-app,
IPv6 Internet TLS, physical performance/battery or arm64 execution claim is made.

Pinned Hev plus recursive native dependencies and their retained original licenses were inspected:
MIT and BSD-3-Clause, compatible with owned GPL-3.0-only code. Apache HttpCore/OkHttp use
Apache-2.0; native and HttpCore notices are packaged. Full pins/boundaries remain in
`THIRD_PARTY_NOTICES.md` and `docs/HTTPS-INSPECTION.md`.

Earlier host-emulator shutdown crashes/137 exits and failed UI harness attempts remain disclosed in
the main report. They do not invalidate the completed instrumentation PASS, and are not presented
as clean emulator exits. No phone action was taken on resumption. Original checkout, publisher
keys, signed CDN/source-index policy and data were not modified. No commit, push, release,
CDN write or public upload was performed.
