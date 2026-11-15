# Android application

See the [root README](../README.md) for installation, privacy and DNS-only limitations and [reproduction guide](../docs/REPRODUCING.md) for build and optional large-corpus tests.

```sh
# JDK 21 and ANDROID_HOME must be configured, SDK platform 35 / build-tools 35.0.0.
./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

Min/target SDK 35 (Android 15+). Platform Views, WorkManager 2.10.0, net.i2p.crypto:eddsa:0.3.0; no JNI, account or analytics. Ed25519 verification uses an explicit pure-Java provider, not an assumed Android platform provider. `gradle/verification-metadata.xml` and the Gradle distribution checksum are tracked.

Split route: virtual TUN 10.111.0.1/32, only 10.111.0.2/32 routed to DNS processing. Unconfigured IPv6 family explicitly permitted. Four relay workers, queue 32, connected protected UDP sockets to 1.1.1.1:53; checked query/response identity. Stop closes TUN, sockets and workers; no automatic sticky restart. No default route, TCP DNS, HTTPS interception or lockdown support.

Signed index updates are off the main thread, with atomic immutable-file publication and rollback protection. First Start requires successful verification. Updates apply to a new session after Stop/Start. Approximate 48-hour checks can be deferred by Android. No index bundled in the APK; installed-data storage remains large.

Query logging is explicitly opt-in. In-memory cap 2,000, UI shows newest 200. Debug builds additionally write logcat and rotating app-private JSONL (1 MiB per file, two files); off/Clear removes retained entries/files. Copy/Share exports only by user action. DNS only, no app attribution, URL paths or bypass traffic. Never attach real query logs to public issues without sanitizing.

`tools/smoke_emulator.py` and `tools/cdn_smoke_emulator.py` are developer harnesses for a **private disposable emulator**, not phone-control tools. They may install packages, grant VPN app-op, disable Private DNS and clear app data on the selected emulator. Inspect first. Host build/tests do not require them or a phone. Release builds omit the debug-only signed loopback fixture endpoint override and cleartext exceptions.

The first public APK is the previously tested debug-signed development artifact, not a rebuilt production release. Its internal versionName is 0.2-cdn / code 2. Keep your own debug keystore private. Production signing/distribution hardening is future work.
