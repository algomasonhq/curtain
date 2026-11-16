package org.curtain.dns.inspection

import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * CA lifecycle invariants (TDD RED then GREEN):
 * - the installation root identity is stable across restarts, exports and unrelated file churn
 *   (rule import, app update artifacts) — the root is generated exactly once, only when no CA exists;
 * - a corrupt/unparsable/non-CA stored certificate fails closed: construction throws and the
 *   stored file is never replaced or regenerated;
 * - leaf certificates exist only in memory and are never persisted, and are never the root;
 * - explicit rotation: begin (records old identity, deletes the internal key only on an exact
 *   fingerprint match), removal proof from the platform store, explicit confirmation, then a new
 *   root; no new root can be generated before the old one is confirmed gone;
 * - pure rotation state machine gates export/new install while a rotation is pending and survives
 *   a persisted-state round trip, with corrupt persisted state falling back to idle.
 */
class CaLifecycleTest {
 private fun withDirectory(body:(File)->Unit) {
  val directory=Files.createTempDirectory("curtain-ca-lifecycle").toFile()
  try { body(directory) } finally { directory.walkBottomUp().forEach { it.delete() } }
 }

 private fun caFile(directory:File)=File(directory,LocalCertificateAuthority.FILE_NAME)

 private fun fingerprintRegex()=Regex("[0-9A-F]{2}(:[0-9A-F]{2}){31}")

 // 32 bytes = 64 hex digits, colon-separated pairs — the SHA-256 fingerprint format.
 private fun dummyValidFormatFingerprint(seed:Int)=List(32) { "%02X".format((it+seed)%256) }.joinToString(":")

 private fun expectFailure(type:Class<*>,block:()->Unit) {
  val error=try { block(); null } catch(e:Throwable) { e }
  if(error==null) fail("expected failure of ${type.simpleName}")
  if(!type.isInstance(error)) fail("expected ${type.simpleName} but got $error")
 }

 // ---- identity stability -------------------------------------------------------------------

 @Test fun identitySurvivesRestartExportAndUnrelatedFileChurn() = withDirectory { directory ->
  val first=LocalCertificateAuthority(directory)
  val original=first.certificate().encoded
  val subject=first.subjectDistinguishedName()
  val fp=first.fingerprintSha256()
  assertTrue(fingerprintRegex().matches(fp))
  assertTrue(subject.contains("CN=Curtain local inspection CA"))
  assertTrue(subject.contains("OU=Curtain"))

  // Export (public certificate only) and rule import-style churn in the same directory.
  first.exportCertificate(File(directory,"exported.crt"))
  File(directory,"rules.json").writeText("""{"rule":"unrelated"}""")
  File(directory,"subdir-import").mkdirs()
  File(File(directory,"subdir-import"),"index.dat").writeBytes(byteArrayOf(0,1,2,3))

  val second=LocalCertificateAuthority(directory)
  assertArrayEquals(original,second.certificate().encoded)
  assertEquals(subject,second.subjectDistinguishedName())
  assertEquals(fp,second.fingerprintSha256())
 }

 @Test fun fingerprintFormatIsUpperHexColonGroupsOfTwo() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val fp=ca.fingerprintSha256()
  assertTrue(fingerprintRegex().matches(fp))
  assertEquals(fp,CaRotation.canonicalFingerprint(fp.lowercase().replace(":","")))
 }

 // ---- fail closed on corrupt CA --------------------------------------------------------------

 @Test fun garbageCaFileFailsClosedAndIsNeverReplaced() = withDirectory { directory ->
  val garbage="this is not a pem at all bytes".toByteArray(Charsets.US_ASCII)
  caFile(directory).writeBytes(garbage)
  expectFailure(IOException::class.java) { LocalCertificateAuthority(directory) }
  assertTrue(caFile(directory).exists())
  assertArrayEquals(garbage,caFile(directory).readBytes())
  // Repeated attempts keep failing closed; nothing regenerates.
  expectFailure(IOException::class.java) { LocalCertificateAuthority(directory) }
  assertArrayEquals(garbage,caFile(directory).readBytes())
 }

 @Test fun truncatedCaFileFailsClosedAndIsNeverReplaced() = withDirectory { directory ->
  val keyDir=Files.createTempDirectory("curtain-ca-key").toFile()
  val half=try {
   val keyBearer=LocalCertificateAuthority(keyDir)
   val complete=File(keyDir,LocalCertificateAuthority.FILE_NAME).readText()
   complete.substring(0,complete.length/2).toByteArray(Charsets.US_ASCII)
  } finally { keyDir.deleteRecursively() }
  caFile(directory).writeBytes(half)
  expectFailure(IOException::class.java) { LocalCertificateAuthority(directory) }
  assertArrayEquals(half,caFile(directory).readBytes())
 }

 @Test fun nonCaStoredCertificateFailsClosed() = withDirectory { directory ->
  val leaf=HeldCertificate.Builder().commonName("not-a-ca").addSubjectAlternativeName("x.example").build()
  caFile(directory).writeText(leaf.certificatePem()+leaf.privateKeyPkcs8Pem())
  expectFailure(IOException::class.java) { LocalCertificateAuthority(directory) }
  assertTrue(caFile(directory).exists())
  assertTrue(caFile(directory).readText().contains("PRIVATE KEY"))
 }

 // ---- leaves are internal, never persisted, never the root ------------------------------------

 @Test fun leavesAreInternalNeverPersistedAndNeverTheRoot() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val rootEncoded=ca.certificate().encoded
  for(i in 1..50) {
   val host="leaf$i.example"
   val leaf=ca.leafCertificate(host)
   assertNotEquals("leaf must never be the root itself",rootEncoded,leaf.encoded)
   assertEquals("leaf must be issued by this root",ca.certificate().subjectX500Principal,leaf.issuerX500Principal)
   assertTrue(runCatching { leaf.verify(ca.certificate().publicKey) }.isSuccess)
  }
  val files=directory.listFiles()!!.map { it.name }.toSet()
  assertEquals("leaf material must stay in memory; only the CA file is on disk",
   setOf(LocalCertificateAuthority.FILE_NAME),files)
  assertTrue(caFile(directory).readText().contains("PRIVATE KEY"))
 }

 // ---- explicit rotation -----------------------------------------------------------------------

 @Test fun beginRotationRefusesWrongOrMalformedFingerprintAndKeepsIdentity() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val before=caFile(directory).readBytes()
  expectFailure(IllegalStateException::class.java) { ca.rotateAfterRemoval(dummyValidFormatFingerprint(7),true) { emptySet() } }
  expectFailure(IllegalArgumentException::class.java) { ca.rotateAfterRemoval("not-a-fingerprint",true) { emptySet() } }
  expectFailure(IllegalArgumentException::class.java) { ca.rotateAfterRemoval("",true) { emptySet() } }
  assertArrayEquals("wrong fingerprint must never delete the key",before,caFile(directory).readBytes())
  val reloaded=LocalCertificateAuthority(directory)
  assertEquals(ca.fingerprintSha256(),reloaded.fingerprintSha256())
 }

 @Test fun confirmedRotationAtomicallyReplacesOnlyTheMatchedOldKey() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val oldEncoded=ca.certificate().encoded
  val oldFp=ca.fingerprintSha256()
  ca.rotateAfterRemoval(oldFp,true) { emptySet() }
  assertTrue("replacement is persisted with no delete/recreate gap",caFile(directory).isFile)
  assertEquals(setOf(LocalCertificateAuthority.FILE_NAME),directory.listFiles()!!.map { it.name }.toSet())

  // Old instance still reflects the old (now retired) identity; it must be discarded, not reused
  // as the new root.
  assertArrayEquals(oldEncoded,ca.certificate().encoded)
  assertNotEquals(oldFp,LocalCertificateAuthority(directory).fingerprintSha256())

  val replacement=LocalCertificateAuthority(directory)
  val newEncoded=replacement.certificate().encoded
  assertNotEquals(oldEncoded,newEncoded)
  assertNotEquals(oldFp,replacement.fingerprintSha256())
  val oldLeaf=ca.leafCertificate("pre-rotation.example")
  assertFalse("leaf signed by the retired root must not verify under the replacement root",
   runCatching { oldLeaf.verify(replacement.certificate().publicKey) }.isSuccess)
  assertTrue(runCatching {
   replacement.leafCertificate("post-rotation.example").verify(replacement.certificate().publicKey)
  }.isSuccess)
 }

 @Test fun beginRotationWithoutStoredCaFails() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  caFile(directory).delete()
  expectFailure(IOException::class.java) { ca.rotateAfterRemoval(ca.fingerprintSha256(),true) { emptySet() } }
 }

 @Test fun rotationMustNotCreateNewRootWhileOldIsInstalledOrStoreUnknown() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory); val before=caFile(directory).readBytes()
  val fp=ca.fingerprintSha256()
  expectFailure(IllegalStateException::class.java) { ca.rotateAfterRemoval(fp,true) { setOf(fp) } }
  expectFailure(IllegalStateException::class.java) { ca.rotateAfterRemoval(fp,true) { null } }
  expectFailure(IllegalStateException::class.java) { ca.rotateAfterRemoval(fp,false) { emptySet() } }
  assertArrayEquals(before,caFile(directory).readBytes())
  val replacement=ca.rotateAfterRemoval(fp,true) { emptySet() }
  assertNotEquals(fp,replacement.fingerprintSha256())
  assertEquals(replacement.fingerprintSha256(),LocalCertificateAuthority(directory).fingerprintSha256())
  assertEquals(setOf(LocalCertificateAuthority.FILE_NAME),directory.listFiles()!!.map { it.name }.toSet())
 }
 // ---- pure rotation state machine -------------------------------------------------------------

 private fun pendingState():CaRotationState = CaRotation.begin(CaRotationState(),
  "CN=Curtain local inspection CA,OU=Curtain",dummyValidFormatFingerprint(1),1000L)

 @Test fun beginRecordsOldIdentityGatesExportAndRejectsDoubleBegin() {
  val s=pendingState()
  assertTrue(CaRotation.isPending(s))
  assertEquals("CN=Curtain local inspection CA,OU=Curtain",s.oldSubject)
  assertEquals(dummyValidFormatFingerprint(1),s.oldFingerprint)
  assertTrue("export/new install must be gated while pending",CaRotation.exportGated(s))
  expectFailure(IllegalStateException::class.java) {
   CaRotation.begin(s,"other",dummyValidFormatFingerprint(2),2000L)
  }
 }

 @Test fun removalProofIsFingerprintPresenceAndUnknownStoreFailsClosed() {
  val s=pendingState()
  assertEquals("old CA still installed → not absent",
   false,CaRotation.oldCaAbsent(s,setOf(dummyValidFormatFingerprint(1),"other")))
  assertEquals("old CA absent → removal confirmed by fingerprint absence",
   true,CaRotation.oldCaAbsent(s,setOf(dummyValidFormatFingerprint(2))))
  assertNull("store unreadable → unknown, generation must stay blocked",
   CaRotation.oldCaAbsent(s,null))
  assertEquals("comparison must be canonical: lowercase colonless form still matches",
   false,CaRotation.oldCaAbsent(s,setOf(dummyValidFormatFingerprint(1).lowercase().replace(":",""))))
 }

 @Test fun completeGenerationRequiresPendingAndRecordsExactOldAndNew() {
  val s=pendingState()
  val newSubject="CN=Curtain local inspection CA,OU=Curtain"
  val newFp=dummyValidFormatFingerprint(9)
  val done=CaRotation.completeGeneration(s,newSubject,newFp,5000L)
  assertFalse(CaRotation.isPending(done))
  assertFalse("export/new install re-opened after rotation",CaRotation.exportGated(done))
  assertTrue(CaRotation.hasCompletedRecord(done))
  assertEquals(dummyValidFormatFingerprint(1),done.oldFingerprint)
  assertEquals(newFp,done.newFingerprint)
  assertEquals(newSubject,done.newSubject)
  assertEquals(5000L,done.completedAtMs)
  assertTrue(CaRotation.displayOld(done).contains(dummyValidFormatFingerprint(1)))
  assertTrue(CaRotation.displayOld(done).contains("CN=Curtain local inspection CA,OU=Curtain"))
  assertTrue(CaRotation.displayNew(done).contains(newFp))
  assertTrue(CaRotation.displayNew(done).contains(newSubject))
  expectFailure(IllegalStateException::class.java) {
   CaRotation.completeGeneration(done,"x",dummyValidFormatFingerprint(3),6000L)
  }
  expectFailure(IllegalArgumentException::class.java) {
   CaRotation.completeGeneration(pendingState(),"",newFp,6000L)
  }
 }

 @Test fun cancelIsExplicitClearsRecordAndKeepsNothingGated() {
  val s=pendingState()
  val cancelled=CaRotation.cancel(s)
  assertFalse(CaRotation.isPending(cancelled))
  assertFalse(CaRotation.exportGated(cancelled))
  assertFalse(CaRotation.hasCompletedRecord(cancelled))
  assertEquals("",cancelled.oldFingerprint)
  assertEquals("",cancelled.newFingerprint)
  expectFailure(IllegalStateException::class.java) { CaRotation.cancel(cancelled) }
 }

 @Test fun corruptPersistedStateFallsBackToIdle() {
  val restored=CaRotation.fromPrefs(mapOf(
   "ca_rotation_phase" to "garbage-phase",
   "ca_rotation_old_fingerprint" to dummyValidFormatFingerprint(1),
   "ca_rotation_old_subject" to "CN=x"))
  assertFalse(CaRotation.isPending(restored))
  assertFalse(CaRotation.exportGated(restored))
  assertEquals(CaRotation.PHASE_IDLE,restored.phase)
 }

 @Test fun prefsRoundTripPreservesPhaseAndIdentity() {
  val pending=pendingState()
  val restoredPending=CaRotation.fromPrefs(CaRotation.toPrefs(pending))
  assertTrue(CaRotation.isPending(restoredPending))
  assertEquals(dummyValidFormatFingerprint(1),restoredPending.oldFingerprint)
  assertEquals("CN=Curtain local inspection CA,OU=Curtain",restoredPending.oldSubject)
  val done=CaRotation.completeGeneration(pendingState(),"CN=new",dummyValidFormatFingerprint(5),7777L)
  val restoredDone=CaRotation.fromPrefs(CaRotation.toPrefs(done))
  assertTrue(CaRotation.hasCompletedRecord(restoredDone))
  assertEquals(dummyValidFormatFingerprint(1),restoredDone.oldFingerprint)
  assertEquals(dummyValidFormatFingerprint(5),restoredDone.newFingerprint)
  assertEquals(7777L,restoredDone.completedAtMs)
  assertEquals(CaRotation.PHASE_IDLE,restoredDone.phase)
 }

 @Test fun defaultStateIsIdleAndNotGated() {
  val s=CaRotation.fromPrefs(emptyMap<String,String>())
  assertFalse(CaRotation.isPending(s))
  assertFalse(CaRotation.exportGated(s))
  assertFalse(CaRotation.hasCompletedRecord(s))
 }

 // ---- platform store probe --------------------------------------------------------------------

 @Test fun androidCaStoreProbeFailsClosedWithoutThrowingOffDevice() {
  // On a JVM there is no AndroidCAStore; the probe must degrade to "unknown" (null), never throw.
  assertNull(AndroidCaStoreProbe.installedFingerprints())
 }

 @Test fun subjectAndFingerprintSurviveRetrievalForDisplay() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val s=CaRotation.begin(CaRotationState(),ca.subjectDistinguishedName(),ca.fingerprintSha256(),1L)
  assertTrue(CaRotation.displayOld(s).contains(ca.fingerprintSha256()))
  assertNotNull(s.oldSubject)
 }
}
