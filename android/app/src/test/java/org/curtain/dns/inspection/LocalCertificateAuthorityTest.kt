package org.curtain.dns.inspection

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.cert.X509Certificate

class LocalCertificateAuthorityTest {
 private fun withDirectory(body:(File)->Unit) {
  val directory=Files.createTempDirectory("curtain-inspection-ca").toFile()
  try { body(directory) } finally { directory.walkBottomUp().forEach { it.delete() } }
 }

 private fun san(certificate:X509Certificate):List<String> =
  certificate.subjectAlternativeNames.orEmpty().map { it[1].toString() }

 @Test fun caPersistsAcrossRestartAndExportsOnlyThePublicCertificate() = withDirectory { directory ->
  val first=LocalCertificateAuthority(directory)
  val pem=first.certificatePem()
  assertTrue(pem.contains("BEGIN CERTIFICATE"))
  assertFalse(pem.contains("PRIVATE KEY"))
  val leaf=first.leafCertificate("persist.example")
  assertTrue(runCatching { leaf.verify(first.certificate().publicKey) }.isSuccess)
  assertTrue(san(leaf).contains("persist.example"))

  val exported=File(directory,"public.pem")
  first.exportCertificate(exported)
  assertEquals(pem,exported.readText())
  assertFalse(exported.readText().contains("PRIVATE KEY"))

  val second=LocalCertificateAuthority(directory)
  assertEquals(pem,second.certificatePem())
  assertArrayEquals(first.certificate().encoded,second.certificate().encoded)
  assertEquals(first.certificate().subjectX500Principal,second.certificate().subjectX500Principal)
  val restarted=second.leafCertificate("persist.example")
  assertEquals(first.certificate().subjectX500Principal,restarted.issuerX500Principal)
  assertTrue(runCatching { restarted.verify(second.certificate().publicKey) }.isSuccess)
  assertNotEquals(leaf.serialNumber,restarted.serialNumber)
 }

 @Test fun ipAndDnsLeavesCarryTheExpectedSanTypes() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val dns=ca.leafCertificate("site.example")
  val ip=ca.leafCertificate("127.0.0.1")
  assertEquals(2,dns.subjectAlternativeNames.first { it[1]=="site.example" }[0])
  assertEquals(7,ip.subjectAlternativeNames.first { it[1]=="127.0.0.1" }[0])
 }

 @Test fun leafCacheIsBoundedAndReusesEntries() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory,leafCacheSize=3)
  val first=ca.leafCertificate("one.example")
  assertEquals(1,ca.cachedLeafCount)
  assertEquals(first.serialNumber,ca.leafCertificate("one.example").serialNumber)
  for(i in 1..20) ca.leafCertificate("host$i.example")
  assertTrue(ca.cachedLeafCount in 1..3)
  for(i in 1..20) assertTrue(runCatching { ca.leafCertificate("host$i.example").verify(ca.certificate().publicKey) }.isSuccess)
  assertTrue(ca.cachedLeafCount in 1..3)
 }

 @Test fun privateKeyFileIsNotThePublicExport() = withDirectory { directory ->
  val ca=LocalCertificateAuthority(directory)
  val internal=File(directory,LocalCertificateAuthority.FILE_NAME)
  assertTrue(internal.exists())
  assertTrue(internal.readText().contains("PRIVATE KEY"))
  assertFalse(ca.certificatePem().contains("PRIVATE KEY"))
 }
}
