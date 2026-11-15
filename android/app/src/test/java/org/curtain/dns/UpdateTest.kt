package org.curtain.dns

import org.junit.Test
import org.junit.Assert.*
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

class UpdateTest {
 private val keys=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
 private val data=CompactIndexTest.fixture(listOf("ads.example" to 2))
 private fun manifest(version:Long=1, bytes:ByteArray=data):String {
  val hash=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
  val payload="{\"bytes\":${bytes.size},\"file\":\"indexes/${version.toString().padStart(6,'0')}.fc\",\"format\":1,\"sha256\":\"$hash\",\"version\":$version}"
  val signature=Signature.getInstance("Ed25519").run { initSign(keys.private); update(payload.toByteArray()); Base64.getEncoder().encodeToString(sign()) }
  return payload.dropLast(1)+",\"signature\":\"$signature\"}"
 }
 private fun <T> inDirectory(body:(File)->T):T {
  val directory=Files.createTempDirectory("curtain-update").toFile()
  try { return body(directory) } finally { directory.walkBottomUp().forEach { it.setWritable(true); it.delete() } }
 }
 private fun rejected(body:()->Unit) { try { body(); fail("Expected rejection") } catch(_:IllegalArgumentException) {} catch(_:IllegalStateException) {} }
 @Test fun rollbackAndSameVersionReplacementAreRejectedWithoutRewritingMappedInode() = inDirectory { directory ->
  val engine=UpdateEngine(directory,keys.public)
  val old=engine.update(manifest(2),{ data.inputStream() })
  val inode=Files.getAttribute(old.file.toPath(),"unix:ino")
  val repeated=engine.update(manifest(2),{ error("Same version must not download") })
  assertEquals(inode,Files.getAttribute(repeated.file.toPath(),"unix:ino"))
  rejected { engine.update(manifest(1),{ data.inputStream() }) }
  val changed=CompactIndexTest.fixture(listOf("evil.example" to 2))
  rejected { engine.update(manifest(2,changed),{ changed.inputStream() }) }
  val newer=engine.update(manifest(3,changed),{ changed.inputStream() })
  assertTrue(old.index.blocked("ads.example")); assertFalse(old.index.blocked("evil.example"))
  assertTrue(newer.index.blocked("evil.example")); assertTrue(old.file.exists())
  assertEquals(inode,Files.getAttribute(old.file.toPath(),"unix:ino"))
  assertEquals(3L,engine.restore()!!.version)
 }
 @Test fun concurrentWritersAreRejectedAndFailedDownloadCanRetry() = inDirectory { directory ->
  val engine=UpdateEngine(directory,keys.public)
  val entered=java.util.concurrent.CountDownLatch(1); val release=java.util.concurrent.CountDownLatch(1)
  val errors=java.util.concurrent.atomic.AtomicReference<Throwable?>()
  val thread=Thread { try { engine.update(manifest(),{ entered.countDown(); release.await(); data.inputStream() }) } catch(t:Throwable) { errors.set(t) } }
  thread.start(); assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS))
  try { rejected { UpdateEngine(directory,keys.public).update(manifest(2),{ data.inputStream() }) } } finally { release.countDown(); thread.join(5000) }
  assertNull(errors.get()); assertEquals(1L,engine.restore()!!.version)
  try { engine.update(manifest(2),{ throw java.io.IOException("offline") }); fail() } catch(_:java.io.IOException) {}
  assertEquals(1L,UpdateEngine(directory,keys.public).restore()!!.version)
  assertEquals(2L,engine.update(manifest(2),{ data.inputStream() }).version)
 }
 @Test fun tamperedManifestsAndBadDownloadsNeverEnableInvalidData() = inDirectory { directory ->
  val engine=UpdateEngine(directory,keys.public)
  val signed=manifest()
  listOf(signed.replace("\"version\":1","\"version\":2"),signed.replace("\"format\":1","\"format\":2"),signed.replace("indexes/000001.fc","../000001.fc"),signed.replace("\"bytes\":","\"extra\":1,\"bytes\":"),signed.replace("\"version\":1","\"version\":1,\"version\":1"),signed+" ".repeat(17000)).forEach { rejected { engine.update(it,{ data.inputStream() }) }; assertNull(engine.restore()) }
  val wrong=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  rejected { UpdateEngine(directory,wrong.public).update(signed,{ data.inputStream() }) }
  rejected { engine.update(signed,{ data.copyOf(data.size-1).inputStream() }) }
  rejected { engine.update(signed,{ (data+byteArrayOf(0)).inputStream() }) }
  rejected { engine.update(signed,{ data.copyOf().apply { this[lastIndex]=0 }.inputStream() }) }
  val broken=data.copyOf().apply { this[0]=0 }
  rejected { engine.update(manifest(bytes=broken),{ broken.inputStream() }) }
  assertNull(engine.restore()); assertFalse(directory.listFiles()!!.any { it.name.endsWith(".part") })
  engine.update(signed,{ data.inputStream() })
  rejected { engine.update(manifest(2),{ byteArrayOf().inputStream() }) }
  assertEquals(1L,engine.restore()!!.version)
 }
 @Test fun acceptedVersionStillPreventsRollbackWhenSnapshotIsMissing() = inDirectory { directory ->
  val engine=UpdateEngine(directory,keys.public)
  val snapshot=engine.update(manifest(2),{ data.inputStream() })
  assertTrue(snapshot.file.delete())
  rejected { engine.update(manifest(1),{ data.inputStream() }) }
  assertEquals(2L,engine.update(manifest(2),{ data.inputStream() }).version)
 }
 @Test fun signatureBytesCannotBeTampered() = inDirectory { directory ->
  val signed=manifest()
  val raw=Regex("\"signature\":\"([^\"]+)\"").find(signed)!!.groupValues[1]
  val bytes=Base64.getDecoder().decode(raw).apply { this[63]=(this[63].toInt() xor 1).toByte() }
  rejected { UpdateEngine(directory,keys.public).update(signed.replace(raw,Base64.getEncoder().encodeToString(bytes)),{ data.inputStream() }) }
  assertFalse(File(directory,"current.json").exists())
 }
 @Test fun rejectsNonJsonWhitespaceEvenAroundValidSignedMetadata() {
  rejected { UpdateManifest.parse("\u000c"+manifest(),keys.public) }
  rejected { UpdateManifest.parse(manifest().replace("\"bytes\":","\"bytes\":\u000b"),keys.public) }
 }
 @Test fun verificationDoesNotDependOnPlatformEd25519Provider() = inDirectory { directory ->
  val signed=manifest()
  val providers=java.security.Security.getProviders()
  val provider=providers.first { it.name=="SunEC" }
  val position=providers.indexOf(provider)+1
  java.security.Security.removeProvider(provider.name)
  try {
   val result=UpdateEngine(directory,keys.public).update(signed,{ data.inputStream() })
   assertEquals(1L,result.version)
  } finally { java.security.Security.insertProviderAt(provider,position) }
 }
 @Test fun signedDownloadPublishesValidatedSnapshotAndRestartsOffline() {
  val directory=Files.createTempDirectory("curtain-update").toFile()
  try {
   val engine=UpdateEngine(directory,keys.public)
   val result=engine.update(manifest(),{ data.inputStream() })
   assertEquals(1L,result.version)
   assertTrue(result.index.blocked("x.ads.example"))
   assertEquals(1L,UpdateEngine(directory,keys.public).restore()!!.version)
   assertFalse(result.file.canWrite() && System.getProperty("user.name")!="root")
  } finally { directory.walkBottomUp().forEach { it.setWritable(true); it.delete() } }
 }
}
