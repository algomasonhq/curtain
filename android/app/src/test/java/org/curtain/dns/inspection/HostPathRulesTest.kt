package org.curtain.dns.inspection

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class HostPathRulesTest {
 @Test fun exactCanonicalHostOnly() {
  val rules=HostPathRules(InspectionRule("Block.Example.","/private",InspectionAction.BLOCK))
  assertEquals(InspectionAction.BLOCK,rules.decide("block.example","/private").action)
  assertEquals(InspectionAction.BLOCK,rules.decide("BLOCK.EXAMPLE","/private/x").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("evilblock.example","/private").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("block.example.evil","/private").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("block.example","/not-private").action)
 }

 @Test fun rawPathPrefixUsesSegmentsNotSubstrings() {
  val rules=HostPathRules(InspectionRule("block.example","/a/b",InspectionAction.BLOCK))
  assertEquals(InspectionAction.BLOCK,rules.decide("block.example","/a/b").action)
  assertEquals(InspectionAction.BLOCK,rules.decide("block.example","/a/b/").action)
  assertEquals(InspectionAction.BLOCK,rules.decide("block.example","/a/b/c").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("block.example","/a/bc").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("block.example","/a").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("block.example","/x/a/b").action)
  assertEquals(InspectionAction.ALLOW,rules.decide("block.example","/a%2Fb").action)
 }

 @Test fun longestPrefixWinsAndReplacementBytesArePreserved() {
  val body="local-\u2713\n".toByteArray(Charsets.UTF_8)
  val rules=HostPathRules(
   InspectionRule("h.test","/",InspectionAction.BLOCK),
   InspectionRule("h.test","/allowed",InspectionAction.ALLOW),
   InspectionRule("h.test","/allowed/replaced",InspectionAction.REPLACE,body)
  )
  val blocked=rules.decide("h.test","/other")
  assertEquals(InspectionAction.BLOCK,blocked.action)
  assertEquals(InspectionAction.ALLOW,rules.decide("h.test","/allowed/x").action)
  val replaced=rules.decide("h.test","/allowed/replaced/deep")
  assertEquals(InspectionAction.REPLACE,replaced.action)
  assertEquals(body.toList(),replaced.body.toList())
 }

 @Test fun invalidRulesAreRejected() {
  for(rule in listOf(
   { InspectionRule("h.test","private",InspectionAction.BLOCK) },
   { InspectionRule("h.test","/a?b",InspectionAction.BLOCK) },
   { InspectionRule("h.test","/a/../b",InspectionAction.BLOCK) },
   { InspectionRule("", "/a",InspectionAction.BLOCK) },
   { InspectionRule("h.test","/a",InspectionAction.REPLACE) }
  )) {
   try { rule(); fail("Expected invalid rule") } catch(_:IllegalArgumentException) {}
  }
 }
}
