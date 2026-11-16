plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
 namespace = "org.curtain.dns"
 compileSdk = 35
 defaultConfig { applicationId = "org.curtain.dns"; minSdk = 35; targetSdk = 35; versionCode = 2; versionName = "0.2-cdn"; testInstrumentationRunner = "org.curtain.dns.SmokeInstrumentation" }
 compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
 kotlinOptions { jvmTarget = "17" }
 androidResources { noCompress += "fc" }
 // Opt-in full-route inspection VPN: hev-socks5-tunnel native engine (third-party),
 // built from app/src/main/jni via the checked-in entry makefiles.
 ndkVersion = "27.2.12479018"
 sourceSets { getByName("main") { java.srcDir("src/main/jni/hev-socks5-tunnel/android") } }
 defaultConfig { ndk { abiFilters += listOf("arm64-v8a","x86_64") } }
 externalNativeBuild { ndkBuild { path = file("src/main/jni/Android.mk") } }
}
dependencies {
 implementation("androidx.work:work-runtime:2.10.0")
 implementation("net.i2p.crypto:eddsa:0.3.0")
 implementation("com.squareup.okhttp3:okhttp:4.12.0")
 implementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
 // Apache-2.0 framing/parser engine; no handwritten chunk or persistent-response codec.
 implementation("org.apache.httpcomponents:httpcore:4.4.16")
 testImplementation("junit:junit:4.13.2")
 testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}
