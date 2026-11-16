package org.curtain.dns
import org.curtain.dns.inspection.InspectionAction
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.Assert.*
/**
 * TDD record (2026-11-15): this file was authored before InspectionSettings.kt existed, so the
 * recorded intended failing state of the branch is these tests failing to compile/execute; the
 * first assertions meant to drive the implementation were acceptPlainHostAndBlockPrefix,
 * replaceRequiresBody and prefsRoundTrip. Pure JVM only: no Android types, no network, no TLS.
 * Core inspection tests under other files are intentionally untouched.
 */
class InspectionSettingsTest {
 private fun validHosts()=listOf("example.com","a-b.co","192.0.2.1","2001:db8::1","münchen.de")
 private fun badHosts()=listOf(""," ","https://example.com","example.com:443","*.example.com","exa mple.com",".example.com","example.com.","ex..com","exa_mple.com","-bad.com","bad-.com","ex\"ample.com","a".repeat(254))
 @Test fun acceptsOwnLoopbackOriginRules() {
  for(h in listOf("localhost","127.0.0.1","::1")) assertNull(InspectionSettings(host=h,blockPathPrefix="/blocked").validate())
 }
 @Test fun emptyMeansNoRuleAndIsValidOffState() {
  val s=InspectionSettings()
  assertNull(s.validate()); assertNull(s.actionKind()); assertFalse(InspectionSettings.isConfigured(s))
 }
 @Test fun acceptPlainHostAndBlockPrefix() {
  val s=InspectionSettings.sanitized(InspectionSettings(host=" Example.COM ",blockPathPrefix=" /ads "))
  assertEquals("example.com",s.host); assertEquals("/ads",s.blockPathPrefix)
  assertNull(s.validate()); assertEquals("block",s.actionKind())
  assertTrue(s.ruleText().contains("example.com"))
 }
 @Test fun acceptsValidHosts() { validHosts().forEach { assertNull("should accept $it",InspectionSettings.validateHost(it)) } }
 @Test fun rejectsBadHosts() { badHosts().forEach { assertNotNull("should reject '$it'",InspectionSettings.validateHost(it)) } }
 @Test fun hostIsTrimmedLowercasedAndUnbracketed() {
  assertEquals("example.com",InspectionSettings.normalizeHost(" Example.COM "))
  assertEquals("2001:db8::1",InspectionSettings.normalizeHost("[2001:DB8::1]"))
 }
 @Test fun rejectsBadPathPrefixes() {
  listOf("","ads","a?b","/a b","/a//b","/a#b","/a/../b","/"+ "x".repeat(300),"/é")
   .forEach { assertNotNull("should reject path '$it'",InspectionSettings.validatePathPrefix(it)) }
 }
 @Test fun acceptsPathPrefixes() { listOf("/","/ads","/ads/banner%20x").forEach { assertNull(InspectionSettings.validatePathPrefix(it)) } }
 @Test fun replaceRequiresBody() {
  val noBody=InspectionSettings(host="example.com",replacePathPrefix="/ads")
  assertNotNull(noBody.validate())
  val withBody=InspectionSettings(host="example.com",replacePathPrefix="/ads",replacementBody="<p>blocked</p>")
  assertNull(withBody.validate()); assertEquals("replace",withBody.actionKind())
  assertTrue(withBody.ruleText().contains("Replace"))
 }
 @Test fun blockAndReplaceAreMutuallyExclusive() {
  val both=InspectionSettings(host="example.com",blockPathPrefix="/a",replacePathPrefix="/b",replacementBody="x")
  assertNotNull(both.validate())
 }
 @Test fun prefixWithoutActionIsRejected() { assertNotNull(InspectionSettings(host="example.com").validate()) }
 @Test fun bodyLengthIsBounded() {
  assertNull(InspectionSettings.validateBody("b".repeat(65536)))
  assertNotNull(InspectionSettings.validateBody("b".repeat(65537)))
  assertNotNull(InspectionSettings.validateBody(""))
 }
 @Test fun prefsRoundTrip() {
  val s=InspectionSettings(host="example.com",replacePathPrefix="/ads",replacementBody="body")
  assertEquals(s,InspectionSettings.fromPrefs(s.toPrefs()))
  assertEquals(InspectionSettings(),InspectionSettings.fromPrefs(emptyMap<String,String>()))
 }
 @Test fun coreRuleMappingMatchesAction() {
  val block=InspectionSettings(host="example.com",blockPathPrefix="/a").coreRule()!!
  assertEquals(InspectionAction.BLOCK,block.action); assertEquals("example.com",block.host)
  val replace=InspectionSettings(host="example.com",replacePathPrefix="/a",replacementBody="x").coreRule()!!
  assertEquals(InspectionAction.REPLACE,replace.action); assertArrayEquals(byteArrayOf(120),replace.body)
  assertNull(InspectionSettings().coreRule())
 }
}
