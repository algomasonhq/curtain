# On-device HTTPS inspection — full-route VPN vertical slice

> **Physical follow-up:** Pixel 7 / Android 16 now passes actual Chrome public HTTPS,
> `/blocked` 403 and `/modified` deterministic replacement, real arm64 native default-route TUN,
> 2 MiB fixed/chunked POST, 3 MiB response and persistent TLS connection tests. Fixed a real-phone
> eight-worker SOCKS starvation bug: long-lived UDP associations occupied all workers; the bridge
> now directly hands off to on-demand workers bounded by the native 64-session limit.
> Clean results: 121 tests, zero failures/errors, three optional skips; 47 lint warnings/no errors.
> Latest private installed APK hash: `c2bf14b69cc83bff96152f19f6f69d9437c0335172b949741d31c407892f1839`.
> See `artifacts/pixel-verification/PHYSICAL-HTTPS-RESULT.md` and the final handoff for artifact,
> real user-store CA proof, screenshot evidence, fixture trust boundaries and retained failures.
> Older statements below that physical/arm64 execution is untested are historical, not current.

**Current result:** common HTTP/1 methods, streamed uploads/responses, persistent connections and
one reusable installation CA with gated explicit rotation. **Final APK:**
`artifacts/curtain-https-browsing-debug.apk` (not the historical GET/HEAD-only VPN APK).
Independent resumed audit: [final handoff](HTTPS-FINAL-HANDOFF.md),
`artifacts/final-verification.json`. See
[usable browsing and CA lifecycle results](#usable-browsing-and-ca-lifecycle-results) below;
earlier GET/HEAD-only artifacts and limits are retained as historical evidence.

## Scope and boundary

This branch now implements **opt-in full-route Android VPN transport → native Hev TCP/SOCKS → local TLS inspection**. An actual API35 x86_64 emulator client with `Proxy.NO_PROXY` traverses the TUN and receives allow/block/replacement bytes. Default DNS-only mode retains its original /32 resolver route; only explicit inspection VPN mode adds IPv4/IPv6 default routes. A separate standalone loopback proxy remains available. Clients must trust this installation's public CA; CA export does not establish trust automatically. Non-DNS UDP is blocked, not forwarded. See final VPN evidence below; earlier proxy-only results are preserved as history.

The acceptance workload is a real TLS client → CONNECT → locally signed TLS leaf → policy → separately verified TLS origin. Allowed requests return origin bytes; blocked and replacement paths return deterministic local bytes without contacting the origin. Keys used in tests are ephemeral, unrelated to the signed-index publisher identity. No runtime private key is source material.

## Engine investigation

Source inspected for this branch (2026-11-15):

| Candidate | Actual source / license | Maintenance / build compatibility | Decision |
|---|---|---|---|
| NetBare-Android | [MIT](https://github.com/MegatronKing/NetBare-Android/blob/master/LICENSE), commit `df5b417ea663763932cabf1ef52f15b09ddc2e16` | Latest default-branch commit 2020-03-02; root build pins AGP 3.3.0, Kotlin 1.3.11 and jcenter. Not demonstrated on Android 15 / AGP 8. | Do not integrate an obsolete build blindly. |
| HTTP Toolkit Android | [AGPL-3.0](https://github.com/httptoolkit/httptoolkit-android/blob/main/LICENSE), commit `53d7e356b1872d9ad20716113fc01b9388bdf4c3` | Default-branch commit 2026-09-03; README explicitly forwards captured Android traffic to the desktop application. A maintained VPN forwarding reference, not a ready standalone on-device TLS engine. GPLv3/AGPL combination requires honoring AGPL obligations, not merely copying GPL headers. | No code copied; avoid pulling in desktop-dependent architecture or changing overall licensing for this slice. |
| HevSocks5Tunnel | [MIT](https://github.com/heiher/hev-socks5-tunnel/blob/main/LICENSE), commit `75dbc1e9ace6c70d3d1b94df7c283efe1de7effc` | Default-branch commit 2026-11-13; README documents Android NDK build, IPv4/v6 TCP/UDP tunneling to SOCKS5. Requires recursive native dependencies, JNI lifecycle, socket protection, SOCKS bridge and TUN integration. It does not terminate TLS itself. | Integrated and built from pinned source with NDK 27.2.12479018 for arm64-v8a/x86_64; real x86_64 Android TUN/TLS evidence below. |
| Square OkHttp + okhttp-tls | [Apache-2.0](https://github.com/square/okhttp/blob/parent-4.12.0/LICENSE.txt), pinned 4.12.0 | Inspected HeldCertificate implementation: standard JCA signing and SAN generation; HandshakeCertificates provides JSSE context. Android-compatible mature 4.x API chosen to fit existing Kotlin/AGP; this is not a claim that 4.12 is the newest release. Upstream project remains active; current main README advertises newer 5.x. | Reuse TLS/certificate/upstream HTTP implementation, implement only bounded local CONNECT plumbing and policy. Apache-2.0 compatible with project GPLv3. |

References: [Android VPN API/lifecycle](https://developer.android.com/develop/connectivity/vpn), [Android trust configuration](https://developer.android.com/privacy-and-security/security-config), [OkHttp TLS APIs](https://github.com/square/okhttp/tree/parent-4.12.0/okhttp-tls).

## Design requirements

- Unique installation CA, generated on-device; signing key kept in app-private no-backup storage. Only public certificate exported using system document UI. Never export the signing key.
- Host-specific leaf certificates with DNS/IP SAN using OkHttp TLS, bounded cache. Normal upstream platform trust and hostname verification; no trust-all managers or permissive hostname verifier.
- Explicit host + encoded-path rules; exact host equality and segment-prefix paths. Local block/replacement decisions occur before upstream connection. This policy is independent of the signed DNS index format and publisher keys.
- Loopback binding only, bounded workers/queue/request sizes/timeouts; Stop closes listener and connections. Initial protocol scope HTTP/1.1 GET/HEAD; unsupported methods fail explicitly rather than pretend to filter them.
- Full inspected URL/action logs are separate from DNS logs, opt-in, bounded memory and cleared when disabled. Request/response bodies are not logged.
- DNS-only, standalone proxy and opt-in full-route inspection have distinct controls. Standalone proxy mode has no default route. Full-route mode owns native transport and the SOCKS-to-inspection bridge, protects upstream sockets before connect and preserves signed-index DNS filtering.

## Verification and follow-up

Execution evidence and final command results are recorded below after independent testing. Physical device operation, user certificate installer interaction and arbitrary-app/TUN coverage are not implied by JVM tests or a successful APK build.

### Baseline and environment

- Repository started clean on `main`, HEAD `1c15015d925228a089e60a91fbb52922ebb90262`; origin `git@github.com:algomasonhq/curtain.git`. Created local `feature/https-inspection`. No push/release/phone operation authorized or performed.
- Baseline: `JAVA_HOME=/home/debian/.local/share/curtain-toolchain/jdk-21.0.13+9 ANDROID_HOME=/home/debian/.local/share/curtain-toolchain/sdk ./gradlew --no-daemon :app:testDebugUnitTest` → `BUILD SUCCESSFUL in 4s`, 22 tasks up-to-date. Baseline output: `/home/debian/.hermes/cache/scratch/curtain-https-baseline.log` (local evidence, not a public URL).
- Existing SDK contains API/build tools/emulator but **no installed NDK**. Native TUN transport is not established merely by the maintained Hev source's Android build instructions.
- OpenCode 2.3.0 actual `run --help` and `models` inspected; bounded separate jobs explicitly selected `opencode/deepseek-v4.1-flash-free` for core and `opencode/glm-5.3-flash-free` for Android wiring. No paid fallback. Session event logs live in local scratch, not source.

### Historical proxy-only independent execution

With the coding jobs no longer running, executed from `android/`:

```sh
export JAVA_HOME=/home/debian/.local/share/curtain-toolchain/jdk-21.0.13+9
export ANDROID_HOME=/home/debian/.local/share/curtain-toolchain/sdk
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew --no-daemon clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
# BUILD SUCCESSFUL in 19s — 50 actionable tasks, all executed
```

JUnit XML aggregation: **86 tests, 0 failures, 0 errors, 3 skipped** (existing optional external/CDN/corpus gates). All new inspection/settings tests execute. Lint succeeds with **39 warnings, no errors**; this is not a warning-free build. Tests exercise real loopback TCP/TLS, not a mocked HTTP transport. Only the test upstream client trusts the ephemeral fixture origin CA; production uses the platform default trust/hostname verifier. A client trusting the installation CA succeeds, a client without that trust fails, and an untrusted origin yields 502. Persistence, DNS/IP SAN signing, bounded cache/logs, malformed Host/framing, redirect handling, Stop and unsupported methods are covered. A further settings RED→GREEN removes an unjustified loopback-host prohibition, allowing local owned-origin rules in the UI as well as the core (`curtain-https-settings-red.log`).

Actual byte evidence from `InspectionRegressionTest.threeRequestByteEvidence`:

```text
/allowed   200  19 bytes  4f726967696e20616c6c6f77656420e29c930a
/blocked   403  30 bytes  426c6f636b6564206279204375727461696e20696e7370656374696f6e0a
/modified  200  24 bytes  4375727461696e207265706c6163656d656e7420e29c930a
originRequestCount=1; blocked/replaced contactedOrigin=false
```

Independent review caught fail-open policy exceptions and chunked oversized-response truncation; retained regressions failed before the agent corrected them. Further independent **RED→GREEN** exercised HEAD replacement wire bytes and truncated known-length origins: both failed in `curtain-https-review-red.log`, then passed after suppressing HEAD bodies and validating the entire bounded origin body before sending success headers. A stalled-origin Stop test also passes. UI review corrected unattached rule fields, separated preferences so Save cannot clear logging/DNS settings, added a real Security-settings action, and guarded delayed service startup publication against Stop/onDestroy with a generation token. Android UI interactions themselves remain unexercised.

Initial delegated RED was contaminated by concurrently incomplete Android wiring, so it is **not proof of an isolated feature RED**. Likewise, a concurrent clean/build caused transient unresolved-reference errors; final verification was rerun serially after stopping the coding job. These are recorded issues, not successful tests. Never run competing Gradle clean/builds in one checkout.

Final private artifact (not published):

- `artifacts/curtain-https-inspection-debug.apk` — **7,818,416 bytes**.
- SHA-256: `957f8fd9ec9cc7e8405fad7c905a1c2d4f71f9e9544bc7dcab324cca1060175e`.
- `python3 android/tools/verify_download_apk.py artifacts/curtain-https-inspection-debug.apk` from repository root: APK v2 signature verified, ZIP CRC PASS, min/target SDK 35, no bundled index/native `.so`; no CA key/PEM identity files in APK. Debug signing identity, not a release identity. `apksigner` needs JDK `bin` on PATH, not only JAVA_HOME.
- `artifacts/https-verification.json`: machine-readable suite totals, byte evidence, lint counts and artifact checksum. `artifacts/opencode-evidence.json`: explicit free models/session IDs and recorded completed-step cost 0. These generated artifacts are intentionally Git-ignored.
- Final log: `/home/debian/.hermes/cache/scratch/curtain-https-final-verified.log`; APK verification: `curtain-https-apk-verify.log`; original free-model JSON events: `curtain-opencode-proxy.jsonl` and `curtain-opencode-ui.jsonl` in the same scratch folder.
- `git diff --check` passes. DNS VPN service, signed updater trust/engine and index manifest remain byte-identical to HEAD. No commit, push, release, phone or cloud mutation performed.

### Historical proxy-only operable slice

Open **HTTPS inspection** independently of the DNS index readiness. This screen creates/loads the no-backup installation CA off-thread, shows its fingerprint, exports **public certificate only** through the document picker and opens Security settings. Save one exact host with a block **or** replacement segment path (the core supports multiple rules); Start opens a real loopback listener and displays its actual ephemeral port. Stop closes it. Client configuration and public CA trust are explicit. URL/action logs are opt-in, 500 entries in memory, newest 200 displayed, cleared on disable/Stop; no body logs.

Initial protocol boundary: HTTPS CONNECT, HTTP/1.1 GET/HEAD, one request per connection, bounded 1 MiB upstream responses; other methods are rejected (body-bearing requests may receive 400, bodyless unsupported methods 405). No HTTP/2 downstream, WebSocket, POST/upload, streaming media or QUIC support is claimed. Existing DNS-only behavior remains the default.

The proxy-only limitation above was superseded by completed native VPN integration below. No `setHttpProxy` shortcut or app exclusion is used.

## Completed full-route VPN integration

### Native transport and lifecycle

- Vendored Hev and four recursive dependencies with exact commits in `android/app/src/main/jni/hev-socks5-tunnel/UPSTREAM-PINS.json`, original licenses retained in source and combined notices packaged under assets. MIT/BSD-3-Clause components; no NetBare/HTTP Toolkit code. JNI Java binding retains upstream's `hev.htproxy.TProxyService` registration name.
- Gradle pins **NDK 27.2.12479018**. Clean build compiles **arm64-v8a and x86_64**; APK contains exactly these two `libhev-socks5-tunnel.so` entries. Independently parsed ELF PT_LOAD alignment is **16384** for every load segment in both libraries. This verifies layout, not actual 16 KiB-device execution.
- `InspectionVpnService` adds explicit IPv4/IPv6 default routes and virtual DNS. No UID/app exclusion, `setHttpProxy`, `bindProcessToNetwork` or explicit proxy on test clients. Hev translates TUN TCP into loopback SOCKS. The bridge parses TLS ClientHello/SNI, enters local CONNECT, replays the hello, and relays real TLS bytes. Non-TLS client-first TCP uses protected direct sockets. DNS UDP passes through the existing QueryResolver/FilterSession signed-index decisions; other UDP is dropped.
- `ProtectedSocketFactory` binds an unconnected TCP socket before protection to materialize Android's fd, then protects before connect. Network-specific DNS and socket binding keep upstream requests outside the tunnel. Normal upstream trust/hostname checks remain intact. Protected socket creation/connect failures close the fd.
- Native borrows a caller-supplied TUN fd; it does **not** close it. Service retains its ParcelFileDescriptor, serializes native start/stop on main, joins native then closes its descriptor. Off-thread preparation cannot establish a stale VPN. Old local cleanup owns only captured local resources. Inherited VpnService.onBind preserves revoke delivery.

### Executed verification

From `android/` with the existing isolated JDK21/SDK:

```sh
./gradlew --no-daemon clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleDebugAndroidTest
# BUILD SUCCESSFUL in 24s; 84 tasks executed
python3 tools/inspection_vpn_emulator.py
# PASS; originRequests=["/allowed"], originRequestCount=1
```

After final instrumentation-readiness corrections, the same build/test/lint tasks passed again (`BUILD SUCCESSFUL in 8s`). Final aggregation: **96 JVM tests, 0 failures, 0 errors, 3 existing optional skips**; lint **41 warnings, 0 errors**. Final production APK is the clean-built artifact; later harness/test changes do not alter its bytes.

The private **AOSP Android 15 / API35 x86_64**, software-emulated `curtain35aosp` on `emulator-5580`, actually exercised:

1. Default VPN network/default IPv4 route and a fresh unbound socket with TUN source `10.111.0.1` before TLS requests.
2. Platform-trusting Android client rejects the installation CA. A test client trusting only its public installation CA reaches `https://example.com/` through TUN/native/bridge/proxy and receives **200, 577 bytes**; `/blocked` returns **403, 30 bytes**; `/modified` returns **200, 28 bytes**. No explicit proxy, process/network bind or app exclusion.
3. Real virtual-resolver IPv4 UDP DNS: `doubleclick.net` NXDOMAIN and `example.com` allowed. IPv6 TUN UDP to `fc00::2` returns NXDOMAIN for the blocked domain. Signed production corpus is restored from the emulator's existing verified snapshot; no fabricated test blocklist.
4. Owned host-loopback TLS origin, reachable from emulator as `10.0.2.2:<ephemeral port>`, yields:

| Path | HTTP | Bytes | Exact UTF-8 payload |
|---|---:|---:|---|
| `/untrusted` | 502 | 12 | `Bad Gateway\n` (production upstream trust rejects fixture) |
| `/allowed` | 200 | 19 | `Origin allowed ✓\n` |
| `/blocked` | 403 | 30 | `Blocked by Curtain inspection\n` |
| `/modified` | 200 | 24 | `Curtain replacement ✓\n` |

   Host records exactly **one HTTP request**, `/allowed`; block/replacement never reach origin. Fixture's signing key is generated in owner-scoped scratch and deleted on exit, never copied to Android, repository or artifacts. **Test-APK-only reflection** injects trust for this one ephemeral origin into the running proxy's existing upstream client, retaining protected socket factory and hostname verifier. Production source has no test trust hook or trust-all configuration. This fixture trust is test setup, not a claim that Android installed the origin CA globally.
5. Full URL/action opt-in log contains real allow/block/replacement entries. Stop removes the actual VPN and native engine. Three additional Start/Stop cycles leave no resurrected worker/native VPN. Stop readiness checks processed state, actual networks and a fresh restored kernel-route source, not just the UI flag.
6. Unchanged DNS-only mode has no default route, actually blocks DNS, permits normal platform-trusted HTTPS, and removes its VPN on Stop. Normal unproxied, platform-trusted HTTPS also succeeds **after final inspection Stop**.

### RED evidence and corrections

Preserved local scratch logs show real failures, not inferred success: `curtain-vpn-red.log` caught a protected-socket connect fd leak and a concurrent-set `toList()` Stop race; `curtain-protect-fd-red.log` caught lazy/unbound TCP protection ordering. `curtain-vpn-diagnostic.log` recorded Android protection failure; binding before protect made the real TUN TLS path work. `curtain-vpn-stop-red.log` then proved native exit alone leaked the caller-owned TUN (45-second real-network Stop failure); retained ParcelFileDescriptor ownership and serialized lifecycle fixed it. A fake SOCKS test incorrectly expected an already-consumed ClientHello in echoed application bytes; its assertion was corrected without changing routing behavior.

Initial full harness output incorrectly required an `INSTRUMENTATION_CODE` marker although this runner emits the stream directly; it now requires terminal PASS and no FAIL. Rapid-Stop coverage also exposed a harness readiness race: an empty network snapshot before VPN advertisement let final DNS resolution start on a disappearing VPN. Resolver/netd evidence is retained in `curtain-vpn-poststop-diagnostic.log`; waiting for processed Stop plus restored kernel route fixed the harness without adding DNS-response retries. The final real run is `curtain-vpn-stop-readiness-green.log`, with machine evidence under `artifacts/vpn-evidence/`.

Free OpenCode resumed `ses_e2093613effez473pU1if5wdco` with `opencode/glm-5.3-flash-free` for bounded service/UI generation; independent read-only review resumed `ses_e208e56b9ffexpwNqSicQsX2V3` with `opencode/deepseek-v4.1-flash-free`. Prior sessions were exported and confirmed interrupted before resumption. The implementation job was stopped after its bounded window, exported as interrupted, then independently corrected and tested. Recorded completed-step costs remain 0; no paid fallback. Original partial files were preserved.

### Private artifacts and remaining limits

- `artifacts/curtain-https-vpn-debug.apk`: **8,599,395 bytes**, SHA-256 **`e34538ea4c33a688f55b1e2b7f456fa62167eec5a2ee41ed5765c55fd3f0ae1d`**. APK v2 debug signature, ZIP CRC, min/target35, both native ABIs, absence of bundled index and private CA files verified using `android/tools/verify_download_apk.py --inspection`.
- `artifacts/curtain-https-vpn-test.apk`: instrumentation fixture, not an end-user app. `artifacts/vpn-verification.json` and `artifacts/vpn-evidence/` contain generated local evidence; not published.
- **Limits:** inspection remains HTTP/1.1 GET/HEAD, one request per TLS connection, 1 MiB response cap. No POST/upload/method expansion was present to preserve. No downstream HTTP/2, WebSocket, streaming, QUIC/non-DNS UDP forwarding, fragmented multi-record ClientHello handling or server-first TCP compatibility is claimed. DNS-over-HTTPS/custom DNS may bypass DNS-index decisions. UDP drop encourages QUIC fallback but arbitrary-app fallback is not proven.
- IPv6 TUN DNS is exercised, not IPv6 Internet TLS or IPv6-only upstream connectivity. arm64 is built/layout-verified, not executed. Physical performance/battery, pinned/native-app compatibility, interactive VPN consent and document-picker/CA installer UX remain untested; emulator consent was a shell app-op and client CA trust was test-only provisioning.
- `DnsVpnService`, signed updater/trust, all-source policy and index data are unchanged. Original `/home/debian/projects/curtain` remains untouched. No commit, push, release, physical-phone action or Cloudflare/CDN write.
- Cleanup: requested `adb -s emulator-5580 emu kill` after successful instrumentation and stopped VPN. Emulator process subsequently exited **139** during shutdown (host emulator tooling issue; the earlier instrumentation harness exited 0). It is no longer running; no emulator shutdown success-code claim is made.



## Appendix — CA lifecycle and explicit rotation (2026-11)

This follow-up supersedes the historical GET/HEAD-only limit above and adds explicit CA lifecycle
controls. A bounded free OpenCode job supplied CA state/probe/tests/UI, followed by independent
review and corrections: atomic root replacement (no delete/recreate gap), a fresh store probe at the
mutation boundary, service-level rotation gates, gated document-result writes, exact subject display,
and operation-busy controls. CA agent RED/GREEN logs were copied to
`/home/debian/.hermes/cache/scratch/curtain-ca-red.log` and `curtain-ca-green.log`; independent
atomic-gate RED is `curtain-ca-atomic-red.log`. Browsing tests failed on real TLS before codec
replacement (`curtain-browsing-red.log`); six browser connections separately exposed idle-worker
starvation (`curtain-browsing-concurrency-red.log`). Final tests/build are independent, serialized.
An intermediate browsing compile encountered the CA agent's deliberately incomplete test scaffold;
that is not counted as behavior RED. The final clean build is the relevant release gate.

### Invariants (all JVM unit-tested)

- **Identity persistence:** the root is generated exactly once and stored in
  `noBackupFilesDir/inspection/inspection-ca.pem` (key + certificate, app-private). Restarts, app
  updates, exports and unrelated file churn in the directory (e.g. imported rule files) never
  regenerate it — verified by byte-identical encoded certificates across reconstructions with
  foreign files present.
- **Fail closed:** a corrupt, truncated or non-CA stored certificate makes construction throw and
  leaves the stored bytes untouched; repeated attempts keep failing and nothing is replaced.
- **Leaves stay internal:** leaf keys/certificates live only in memory (bounded LRU cache) and are
  never written to disk; leaves are never the root and always verify under it. Disk shows exactly
  one file: the CA PEM.
- **Explicit rotation only:** Begin records the exact old identity and generates nothing.
  `rotateAfterRemoval(expectedFingerprint, confirmed, probe)` refuses unknown/present-old stores,
  missing user confirmation and mismatched identities. Only a fresh absence observation permits
  generation and atomic replacement of the old app-private PEM (no backup old key, no missing-file
  interval). The returned authority is used after services restart; old instances are discarded.
- **Pure state machine** (`CaRotation`/`CaRotationState`, persisted in SharedPreferences):
  `idle → pending-removal → idle`. Pending gates export/new install; double-begin is refused;
  cancel is explicit and clears the record; corrupt persisted state always falls back to idle
  (never permanently gated, never fake-completed).

### Platform API investigation (Android 15+)

- **Normal apps cannot silently remove a user CA.** Official
  [DevicePolicyManager.uninstallCaCert](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#uninstallCaCert(android.content.ComponentName,%20byte[]))
  requires a device/profile owner or an explicitly authorized `DELEGATION_CERT_INSTALL` delegate.
  [KeyChain.createInstallIntent](https://developer.android.com/reference/android/security/KeyChain#createInstallIntent())
  cannot install CA certificates since Android R; Settings must do it. Curtain requests neither
  management privileges nor root. User-confirmed Settings removal is required before replacement.
- **Observation instead of control:** `AndroidCaStoreProbe` reads the platform
  `AndroidCAStore` `KeyStore` (read-only for apps; aliases include system and user trust anchors)
  and has no pretend fallback or deletion API. It returns fingerprints or
  `null` for any unreadable/incomplete enumeration. Rotation blocks until the old fingerprint is observed absent; `null`
  means "unknown" and generation stays blocked (fail closed).
- **User confirmation vs proof, disclosed in the UI:** fingerprint absence in the store is the
  app's own observation, not proof Android has stopped trusting the certificate; the rotation text
  asks the user to verify visually in Settings before pressing the confirm button, and the confirm
  button is additionally gated on the probe result.
- **Services:** rotation (begin and confirm) refuses while `InspectionService` or
  `InspectionVpnService` is active/starting; service start is refused while a rotation is pending.
  Services construct their authority per start, so after a rotation a stopped-then-started service
  picks up the new root; no long-lived cached authority exists to invalidate, and the activity
  drops its cached exported PEM on completion.
- **Exact display:** pending shows the old subject (RFC 2253) and SHA-256 fingerprint; completion
  records and shows both old and new subject + fingerprint verbatim.

## Usable browsing and CA lifecycle results

### HTTP implementation and remaining protocol scope

- Replaced the handwritten tunneled HTTP/body/response codec with **Apache HttpCore 4.4.16**
  (`DefaultBHttpServerConnection`, bounded parser constraints and strict length strategies).
  Apache owns chunk decoding, fixed/chunked response framing and connection buffering; Curtain
  validates authority, Host, unsafe paths, duplicate/conflicting framing and hop-by-hop headers.
  The small CONNECT preface reader remains bounded and cannot consume TLS bytes.
- Supports GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; 64 MiB upload bound, constant-sized
  relay buffers, streamed responses (no former 1 MiB default cap), 15 s I/O/idle timeouts and up to
  1,000 requests per connection. Proxy workers are bounded at 16 with queue 32; the SOCKS bridge
  remains independently bounded at 8 workers. Stop cancels active OkHttp calls and closes sockets.
  Local policy decisions precede any upstream call; rejected body-bearing requests close rather
  than drain an untrusted upload. Bodies are never logged; full URL/action logging remains opt-in.
- Streaming changes truncation semantics deliberately: after success headers are sent, a broken
  origin or configured response-byte bound aborts the framed body without a terminal chunk, so
  clients observe an I/O/framing failure. It does not append a second 502 or silently finish a
  truncated 200. Known oversize responses can still be rejected before headers.
- Evaluated [HttpCore 5's separate HTTP/2/NIO modules](https://hc.apache.org/httpcomponents-core-5.4.x/index.html),
  [NanoHTTPD's body/file parsing](https://github.com/NanoHttpd/nanohttpd/blob/master/core/src/main/java/org/nanohttpd/protocols/http/HTTPSession.java)
  and [the original LittleProxy tree](https://github.com/adamfisk/LittleProxy).
  Selected the small Apache codec rather than extending our own chunk parser or importing a
  desktop proxy architecture. Its Apache-2.0 LICENSE/NOTICE is packaged as `licenses/HttpCore.txt`
  in APK assets and checksums are pinned. This is not a newest-version claim.
- **Still unsupported:** downstream HTTP/2 and WebSocket/Upgrade (explicit 501), non-DNS UDP/QUIC,
  fragmented multi-record ClientHello and server-first TCP. The app advertises HTTP/1.1 via ALPN;
  OkHttp remains free to negotiate HTTP/2 upstream. No arbitrary-browser/native-app compatibility,
  IPv6 Internet TLS, phone performance or battery claim is made. HTTP/2/WebSocket require another
  tested transport/engine slice, not a pretend passthrough that bypasses URL policy.

### Independently executed build and real TUN tests

Final production clean build, existing JDK21/SDK35/NDK27 toolchain:

```sh
./gradlew --no-daemon clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleDebugAndroidTest
# BUILD SUCCESSFUL in 29s; 84 tasks executed
```

**120 JVM tests, 0 failures/errors, 3 existing optional skips. Lint: 47 warnings, 0 errors.**
Subsequent changes were confined to CA instrumentation/harness and documentation; the copied
production APK is the clean-built APK exercised on Android. Final test-APK build/lint also passed.
Real TLS unit tests verify large POST echo, chunked uploads, local POST block/replacement,
PUT/PATCH/DELETE/OPTIONS, 204 framing, six simultaneous persistent connections, early first byte of
an unfinished stream, and known/chunked truncation failures. An independent full-suite run exposed
a log-publication race (client finished before its log entry existed); logging now precedes sending
response headers, and the full suite passes.

The final **AOSP API35 x86_64**, `Proxy.NO_PROXY`, actual default-route TUN run passed after CA
rotation and new CA installation:

- Fixed-length **2,097,169-byte POST** and chunked **2,097,169-byte POST**, exact byte echoes.
- **3,145,731-byte** streamed response, both POSTs and GET sharing **one downstream TLS connection**.
- Owned origin receives exactly `[/allowed, /echo?n=0, /echo?n=1, /stream]` (4 requests).
  Block/replacement never contact it. Original 19/30/24-byte allow/block/replacement evidence retained.
- Untrusted fixture origin yields 502; only test-APK reflection adds its ephemeral certificate,
  preserving protected sockets and hostname verification. Production has no trust bypass.
- Public example.com HTTPS, IPv4 and IPv6 TUN DNS block/allow, unchanged DNS-only split routing,
  three rapid Start/Stop cycles, actual network removal and normal HTTPS after Stop all pass.
- Harness restores exact prior Private DNS and hidden-API settings. Network-only instrumentation's
  last sentence about not testing the installer applies to that fixture; the separate CA UI test
  below actually does test it.

Evidence: `artifacts/browsing-vpn-evidence/{instrumentation.txt,origin.json,final-artifact-run.txt}`;
`artifacts/browsing-verification.json` aggregates parsed results, signatures, native alignment and
free-model cost evidence. These are local generated files, not published URLs.

### Actual Android CA onboarding, upgrade and replacement

1. `adb install -r` with the existing debug signer preserves the root file's SHA-256 and public
   fingerprint across upgrades, force-stop/restart and all VPN test starts. Exact baseline/read-back
   evidence is `artifacts/browsing-vpn-evidence/ca-upgrade.json`.
2. Actual document-picker Save exports a **579-byte public certificate**, no private key; the
   Settings CA warning and file picker install it. Trusted credentials → User shows exactly one
   entry; the system detail SHA-256 matches the installation fingerprint.
3. Begin rotation leaves the private root byte-identical, disables export and replacement while
   that fingerprint remains installed, and survives activity/process/package restart. Actual
   Settings Uninstall confirmation removes **only that CA**; the User list is empty before new
   root generation. No root, device-owner setup or policy-manager deletion is used.
4. The Android instrumentation invokes the real in-app confirmation Button handler on main after
   the fresh platform-store absence check. It atomically replaces the old private file, persists
   both exact identities and leaves exactly **one** private root file. Subsequent process restarts
   reuse this replacement; the test resumes rather than rotating yet again.
5. Actual ACTION_CREATE_DOCUMENT/Save exports the replacement. The automated Settings warning,
   CA file picker and install complete: read-back reports the **old fingerprint absent**, the
   **new fingerprint present**, and **exactly one installed user CA**. Public document copies are
   not new root identities or extra trust-store entries.

Exact subjects are `CN=Curtain local inspection CA,OU=Curtain`; exact old/new fingerprints
are retained only in private test evidence.
These are ephemeral emulator identities, not bundled production CAs. `artifacts/ca-ui-evidence/`
contains actual UI hierarchies, old detail/removal confirmation, initial rotation success and final
`ca-instrumentation.txt` PASS. `CaLifecycleSmoke` lives only in the test APK.

Harness issues are not hidden: boot completion raced launcher/shared-storage readiness; long-lived
host emulators twice exited 137, and emulator shutdown often exits SIGSEGV (-11 / shell 139).
A foreground owner now waits for shared storage, owns installation/tests and always waits for its
emulator child on cleanup. Instrumentation uses actual accessibility gestures for the nested Settings
scroll view. Document-provider duplicate filenames are discovered from actual created files;
UiAutomation command strings are argv, not shell-quoted commands, so observed spaced filenames
must be passed correctly. Earlier export fixture failures were harness path/quoting issues, not
successful onboarding claims. Final CA UI and network runs both pass; the shutdown crash remains
a host-tool issue, not an asserted clean emulator shutdown.

### Delivery and physical gate

- `artifacts/curtain-https-browsing-debug.apk`: **8,899,878 bytes**,
  SHA-256 **`687459babf7bcf2eea3272364e647d4da5a63411583a1f5f21805f3ef9364797`**.
- APK v2 signature verifies and matches previous debug signer
  `c08f9e18f2ac010a0081a3383b0e1deee4515e01f321e64831f188791a20fbc8`;
  ZIP CRC, SDK35, both native ABIs, absence of CA/private-key bundles, `zipalign -P 16`, and every
  ELF PT_LOAD segment's 16384-byte alignment pass. This is layout verification, not 16 KiB-device execution.
- Companion `artifacts/curtain-https-browsing-test.apk` is instrumentation only.
- OpenCode `opencode/glm-5.3-flash-free`, session `ses_e206bf37dffeE0bpCCmcRajiYS`, completed its
  bounded CA task; exported event costs aggregate to **0** (66 completed steps). No paid fallback.
- Physical Pixel 7 / Android16 remains untested: authorized `padb` cannot connect to
  `127.0.0.1:5038` (connection refused), checked before work and after final tests. No phone app,
  trust store, settings, PIN or credentials were touched.
- Original checkout, signed CDN/source-index policy and publisher files are untouched. Prior
  tracked/untracked prototype work and old APK/evidence artifacts remain. No commit, push,
  release, public upload or cloud mutation was performed.
