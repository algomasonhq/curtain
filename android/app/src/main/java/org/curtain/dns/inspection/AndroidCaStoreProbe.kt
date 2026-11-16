package org.curtain.dns.inspection

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/**
 * Read-only view of Android's platform CA store (the "AndroidCAStore" KeyStore, which holds the
 * trusted credential list shown in Settings → user/system certificates).
 *
 * Apps can READ this store but have no public API to modify it: KeyChain offers no delete, and
 * DevicePolicyManager.installCaCert/uninstallCaCert work only for a device owner or profile
 * owner or explicitly authorized certificate-install delegate. A normal Android 15+ app cannot
 * silently delete an installed user CA — the
 * user must remove it in Settings. This probe only observes: it never claims to delete, and a
 * failed read returns null ("unknown") so callers fail closed instead of guessing.
 */
object AndroidCaStoreProbe {
 private const val ANDROID_CA_STORE="AndroidCAStore"

 /** Canonical SHA-256 fingerprints of every certificate in the platform CA store, or null when
  *  the store is unreadable on this device/runtime. */
 fun installedFingerprints():Set<String>? = try {
  val store=KeyStore.getInstance(ANDROID_CA_STORE)
  store.load(null,null)
  buildSet {
   val aliases=store.aliases()
   while(aliases.hasMoreElements()) {
    val certificate=store.getCertificate(aliases.nextElement()) as? X509Certificate
     ?: error("Incomplete platform certificate-store read")
    add(sha256Fingerprint(certificate))
   }
  }
 } catch(_:Exception) { null }

 fun sha256Fingerprint(cert:X509Certificate):String =
  MessageDigest.getInstance("SHA-256").digest(cert.encoded)
   .joinToString(":") { "%02X".format(it.toInt() and 0xff) }
}
