package org.curtain.dns.inspection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InspectionLogTest {
 private fun entry(i:Int,action:InspectionAction=InspectionAction.ALLOW,status:Int=200)=
  InspectionEntry(i.toLong(),"https://example.test/path/$i?q=$i",action,status)

 @Test fun disabledByDefaultAndDisableClears() {
  val log=InspectionLog(4)
  assertFalse(log.enabled)
  log.record(entry(1))
  assertEquals(0,log.recent(10).size)

  log.setEnabled(true)
  log.record(entry(2))
  assertEquals(1,log.recent(10).size)
  log.setEnabled(false)
  assertEquals(0,log.recent(10).size)
  log.record(entry(3))
  assertEquals(0,log.recent(10).size)
 }

 @Test fun ringBufferIsBoundedNewestFirstAndCallbackOnlyWhileEnabled() {
  val seen=mutableListOf<InspectionEntry>()
  val log=InspectionLog(3){ seen.add(it) }
  for(i in 1..6) log.record(entry(i))
  assertTrue(seen.isEmpty())

  log.setEnabled(true)
  for(i in 1..6) log.record(entry(i))
  val recent=log.recent(10)
  assertEquals(3,recent.size)
  assertEquals("https://example.test/path/6?q=6",recent[0].url)
  assertEquals("https://example.test/path/4?q=4",recent[2].url)
  assertEquals(6,seen.size) // the callback sees each enabled event; the in-memory ring stays bounded

  log.clear()
  assertEquals(0,log.recent(10).size)
  assertTrue(log.enabled)
 }

 @Test fun actionAndStatusAreRecorded() {
  val log=InspectionLog(2).apply { setEnabled(true) }
  log.record(entry(1,InspectionAction.BLOCK,403))
  log.record(entry(2,InspectionAction.REPLACE,200))
  assertEquals(InspectionAction.REPLACE,log.recent(1)[0].action)
  assertEquals(200,log.recent(1)[0].status)
  assertEquals(InspectionAction.BLOCK,log.recent(2)[1].action)
  assertEquals(403,log.recent(2)[1].status)
 }
}
