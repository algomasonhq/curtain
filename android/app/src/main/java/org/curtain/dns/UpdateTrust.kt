package org.curtain.dns
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import net.i2p.crypto.eddsa.EdDSASecurityProvider
object UpdateTrust {
 const val BASE="https://cdn.clapbox.net/curtain/"
 // An explicit pure-Java provider: Android 15 does not promise platform Ed25519 support.
 // Never register/replace a system security provider.
 private val provider=EdDSASecurityProvider()
 private fun decode(encoded:ByteArray)=KeyFactory.getInstance("EdDSA",provider).generatePublic(X509EncodedKeySpec(encoded))
 // Existing publisher PUBLIC Ed25519 SPKI. No private identity or storage credentials.
 val key by lazy { decode(Base64.getDecoder().decode("MCowBQYDK2VwAyEAATACzojxIuNL8ERTeUOotlmrCv9siT89s6u9oIjRXXs=")) }
 fun verify(key:PublicKey,message:ByteArray,signature:ByteArray):Boolean {
  val verifier=Signature.getInstance("NONEwithEdDSA",provider)
  verifier.initVerify(decode(key.encoded)); verifier.update(message)
  return verifier.verify(signature)
 }
}
