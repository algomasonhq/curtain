plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
 namespace = "org.curtain.dns"
 compileSdk = 35
 defaultConfig { applicationId = "org.curtain.dns"; minSdk = 35; targetSdk = 35; versionCode = 2; versionName = "0.2-cdn"; testInstrumentationRunner = "org.curtain.dns.SmokeInstrumentation" }
 compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
 kotlinOptions { jvmTarget = "17" }
 androidResources { noCompress += "fc" }
}
dependencies { implementation("androidx.work:work-runtime:2.10.0"); implementation("net.i2p.crypto:eddsa:0.3.0"); testImplementation("junit:junit:4.13.2") }
