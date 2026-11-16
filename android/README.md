# Android application

See the [root README](../README.md) for installation, privacy and DNS-only limitations and [reproduction guide](../docs/REPRODUCING.md) for build and optional large-corpus tests.

```sh
# JDK 21 and ANDROID_HOME must be configured, SDK platform 35 / build-tools 35.0.0.
./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

Min/target SDK 35 (Android 15+). Platform Views, WorkManager 2.10.0, net.i2p.crypto:eddsa:0.3.0; no account or analytics. The opt-in inspection transport includes a pinned JNI native engine built with NDK 27.2.12479018 for arm64-v8a and x86_64. Ed25519 verification uses an explicit pure-Java provider, not an assumed Android platform provider. `gradle/verification-metadata.xml` and the Gradle distribution checksum are tracked.

Default DNS-only split route: virtual TUN 10.111.0.1/32, only 10.111.0.2/32 routed to DNS processing. Unconfigured IPv6 family explicitly permitted. Four relay workers, queue 32, connected protected UDP sockets to 1.1.1.1:53; checked query/response identity. Stop closes TUN, sockets and workers; no automatic sticky restart. No default route, TCP DNS, HTTPS interception or lockdown support.

Signed index updates are off the main thread, with atomic immutable-file publication and rollback protection. First Start requires successful verification. Updates apply to a new session after Stop/Start. Approximate 48-hour checks can be deferred by Android. No index bundled in the APK; installed-data storage remains large.

Query logging is explicitly opt-in. In-memory cap 2,000, UI shows newest 200. Debug builds additionally write logcat and rotating app-private JSONL (1 MiB per file, two files); off/Clear removes retained entries/files. Copy/Share exports only by user action. DNS only, no app attribution, URL paths or bypass traffic. Never attach real query logs to public issues without sanitizing.

`tools/smoke_emulator.py` and `tools/cdn_smoke_emulator.py` are developer harnesses for a **private disposable emulator**, not phone-control tools. They may install packages, grant VPN app-op, disable Private DNS and clear app data on the selected emulator. Inspect first. Host build/tests do not require them or a phone. Release builds omit the debug-only signed loopback fixture endpoint override and cleartext exceptions.

## Optional full-route HTTPS inspection (this branch)

[Design, source pins/licenses and exact verification](../docs/HTTPS-INSPECTION.md). The inspection screen offers a standalone loopback proxy and a separate opt-in full-route VPN. The VPN routes IPv4/IPv6 through vendored Hev TUN→SOCKS transport; TLS flows enter the local CONNECT inspection engine without an explicit client proxy. Upstream TCP/UDP sockets are protected before connect, and upstream HTTPS retains certificate/hostname validation. The signed DNS index filters DNS; non-DNS UDP (including QUIC) is blocked. DNS-only mode is unchanged. Export only the installation public CA and explicitly provision trust in consenting clients; installing a user CA does not make all apps trust it. HTTP/1.1 GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS, streamed fixed-length/chunked uploads (64 MiB bound), streamed responses and up to 1,000 requests per TLS connection (15 s idle timeout). Apache HttpCore owns framing; OkHttp validates upstream TLS and can use HTTP/2 upstream. Downstream HTTP/2 and WebSocket upgrades are not supported. The same no-backup root CA is reused across process restarts and package upgrades; explicit rotation requires old trust-store removal, confirmed absence and atomic replacement. UI configures one block **or** replacement rule; core supports multiple.

Verified on private AOSP API35 x86_64: no-proxy real-TUN allow/block/replacement; 2,097,169-byte fixed and chunked POST echoes; 3,145,731-byte response and three requests on one downstream TLS connection; IPv4+IPv6 TUN DNS, DNS-only regression, native/real-network Stop and normal HTTPS afterwards. `tools/inspection_vpn_emulator.py` installs debug+test APKs on disposable `emulator-5580`, restores Private DNS/hidden-API settings and records exact origin requests. Test-APK reflection trusts only the ephemeral fixture origin and retains protected sockets/hostname checks; there is no production trust hook. Separate actual document-picker/Settings tests install the old CA, verify rotation gates, remove it, confirm replacement and install the new CA with exactly one user trust anchor. `CaLifecycleSmoke` can resume after the deliberate Settings removal with `am instrument -w -e caLifecycle true org.curtain.dns.test/org.curtain.dns.SmokeInstrumentation`; never run this on an unapproved phone. A physical Pixel 7 / Android 16 also passed actual Chrome allow/block/replacement, arm64 TUN large-upload/stream/persistent-connection, DNS-only and Stop checks. Physical-device performance/battery and arbitrary native-app compatibility remain untested. Verify the private artifact with `python3 tools/verify_download_apk.py --inspection ../artifacts/curtain-https-browsing-debug.apk`.

## Historical first public artifact

The first public APK is the previously tested debug-signed development artifact, not a rebuilt production release. Its internal versionName is 0.2-cdn / code 2. Keep your own debug keystore private. Production signing/distribution hardening is future work.
