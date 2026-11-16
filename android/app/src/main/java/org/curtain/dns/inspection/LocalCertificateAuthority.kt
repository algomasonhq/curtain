package org.curtain.dns.inspection

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.LinkedHashMap
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate

/**
 * Installation-local inspection CA. The private PEM lives only in the caller-supplied directory
 * (the app passes noBackupFilesDir); callers can export or read the public certificate, never the key.
 */
class LocalCertificateAuthority(
 private val directory:File,
 private val leafCacheSize:Int=64,
 private val leafValidityDays:Long=7,
 private val leafCacheTtlMs:Long=TimeUnit.HOURS.toMillis(1)
) {
 companion object {
  const val FILE_NAME="inspection-ca.pem"
  private const val CA_DAYS=3650L
  private val random=SecureRandom()
  private val processLock=Any()
 }

 init {
  require(leafCacheSize in 1..1024) { "leafCacheSize must be 1..1024" }
  require(leafValidityDays in 1..3650) { "leafValidityDays must be 1..3650" }
  require(leafCacheTtlMs in 1..TimeUnit.DAYS.toMillis(30)) { "leafCacheTtlMs out of range" }
  if(!directory.isDirectory && !directory.mkdirs()) throw IOException("could not create CA directory")
  if(!directory.isDirectory) throw IOException("CA directory is not a directory")
 }

 private val ca:HeldCertificate=loadOrCreate()
 private val lock=Any()
 private val leaves=LinkedHashMap<String,Leaf>(16,0.75f,true)

 private class Leaf(val held:HeldCertificate,val sslContext:SSLContext,val createdAt:Long)

 private fun loadOrCreate():HeldCertificate = synchronized(processLock) {
  val file=File(directory,FILE_NAME)
  if(file.isFile) {
   val held=try { HeldCertificate.decode(file.readText(Charsets.US_ASCII)) } catch(e:Exception) { throw IOException("could not load $FILE_NAME",e) }
   if(held.certificate.basicConstraints<0) throw IOException("$FILE_NAME is not a CA certificate")
   held
  } else {
   val created=generateRoot()
   writeAtomically(file,(created.certificatePem()+created.privateKeyPkcs8Pem()).toByteArray(Charsets.US_ASCII),ownerOnly=true)
   created
  }
 }

 /** Public certificate only; the signing key is never returned to callers. */
 fun certificatePem():String=ca.certificatePem()

 fun certificate():X509Certificate=ca.certificate

 /** Exact RFC 2253 subject of this installation's root, for unambiguous display. */
 fun subjectDistinguishedName():String = ca.certificate.subjectX500Principal.getName(javax.security.auth.x500.X500Principal.RFC2253)

 /** SHA-256 fingerprint of the root certificate, uppercase hex in colon-separated pairs. */
 fun fingerprintSha256():String = AndroidCaStoreProbe.sha256Fingerprint(ca.certificate)

 /** Explicit confirmed rotation. The fresh platform-store probe must report the exact old CA
  * absent BEFORE key generation. Replace the old private file atomically: no delete/recreate gap,
  * no backup key pile, and an interrupted write leaves the previous root intact. Discard this
  * instance afterwards; only the returned authority may be used for the new inspection session. */
 fun rotateAfterRemoval(expectedFingerprint:String,confirmed:Boolean,probe:()->Set<String>?):LocalCertificateAuthority = synchronized(processLock) {
  check(confirmed) { "Explicit old-CA removal confirmation required" }
  val expected=CaRotation.canonicalFingerprint(expectedFingerprint)
  val file=File(directory,FILE_NAME)
  if(!file.isFile) throw IOException("No stored CA to rotate")
  val stored=try { HeldCertificate.decode(file.readText(Charsets.US_ASCII)) } catch(e:Exception) { throw IOException("Cannot read stored CA",e) }
  check(AndroidCaStoreProbe.sha256Fingerprint(stored.certificate)==expected) { "CA fingerprint mismatch: nothing changed" }
  val state=CaRotation.begin(CaRotationState(),subjectDistinguishedName(),expected,System.currentTimeMillis())
  check(CaRotation.oldCaAbsent(state,probe())==true) { "Old CA still installed or certificate store unreadable" }
  val created=generateRoot()
  writeAtomically(file,(created.certificatePem()+created.privateKeyPkcs8Pem()).toByteArray(Charsets.US_ASCII),ownerOnly=true)
  LocalCertificateAuthority(directory,leafCacheSize,leafValidityDays,leafCacheTtlMs)
 }

 private fun generateRoot():HeldCertificate {
  val now=System.currentTimeMillis()
  return HeldCertificate.Builder().commonName("Curtain local inspection CA").organizationalUnit("Curtain")
   .certificateAuthority(0).validityInterval(now-TimeUnit.MINUTES.toMillis(5),now+TimeUnit.DAYS.toMillis(CA_DAYS))
   .serialNumber(randomSerial()).build()
 }

 /** Writes only the public certificate PEM. */
 fun exportCertificate(file:File) {
  file.parentFile?.let { if(!it.isDirectory && !it.mkdirs()) throw IOException("could not create export directory") }
  writeAtomically(file,certificatePem().toByteArray(Charsets.US_ASCII),ownerOnly=false)
 }

 /** Public leaf certificate for inspection/tests. Signing key material stays inside this object. */
 fun leafCertificate(host:String):X509Certificate=leaf(host).held.certificate

 val cachedLeafCount:Int get()=synchronized(lock) { leaves.size }

 internal fun serverSslContext(host:String):SSLContext=leaf(host).sslContext

 private fun leaf(host:String):Leaf {
  val canonical=InspectionUrls.canonicalHost(host)
  val now=System.currentTimeMillis()
  synchronized(lock) {
   val cached=leaves[canonical]
   if(cached!=null && now-cached.createdAt<=leafCacheTtlMs) return cached
   val leaf=HeldCertificate.Builder()
    .commonName(canonical)
    .addSubjectAlternativeName(canonical)
    .duration(leafValidityDays,TimeUnit.DAYS)
    .serialNumber(randomSerial())
    .signedBy(ca)
    .build()
   val context=HandshakeCertificates.Builder()
    .heldCertificate(leaf,ca.certificate)
    .build()
    .sslContext()
   val result=Leaf(leaf,context,now)
   leaves[canonical]=result
   while(leaves.size>leafCacheSize) {
    val eldest=leaves.entries.iterator()
    if(eldest.hasNext()) { eldest.next(); eldest.remove() } else break
   }
   return result
  }
 }

 private fun randomSerial():BigInteger=BigInteger(72,random).max(BigInteger.ONE)

 private fun writeAtomically(target:File,bytes:ByteArray,ownerOnly:Boolean) {
  val parent=target.parentFile ?: throw IOException("target has no parent")
  if(!parent.isDirectory && !parent.mkdirs()) throw IOException("could not create directory")
  val temporary=File(parent,target.name+".tmp")
  try {
   FileOutputStream(temporary).use { it.write(bytes); it.fd.sync() }
   if(ownerOnly) setOwnerOnly(temporary)
   if(!temporary.renameTo(target)) throw IOException("could not persist ${target.name}")
   if(ownerOnly) setOwnerOnly(target)
  } finally {
   if(temporary.exists()) temporary.delete()
  }
 }

 private fun setOwnerOnly(file:File) {
  try {
   file.setReadable(false,false); file.setWritable(false,false); file.setExecutable(false,false)
   file.setReadable(true,true); file.setWritable(true,true)
  } catch(_:Exception) {}
 }
}
