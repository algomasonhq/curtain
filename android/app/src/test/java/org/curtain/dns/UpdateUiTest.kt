package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
import java.nio.ByteBuffer
import java.io.File
class UpdateUiTest {
 private fun snapshot(v:Long,host:String)=IndexSnapshot(UpdateManifest(v,"indexes/000001.fc",64,"0".repeat(64),""),CompactIndex(ByteBuffer.wrap(CompactIndexTest.fixture(listOf(host to 2)))),File("unused"))
 @Test fun firstRunCannotStartAndShowsProgressAndRetry() {
  val empty=UpdateUi.render(null,null,false,true,"Downloading 10 / 115 MiB",null,"Stopped")
  assertFalse(empty.canStart); assertFalse(empty.canUpdate); assertTrue(empty.text.contains("Downloading"))
  val failed=UpdateUi.render(null,null,false,false,"","CDN HTTP 404","Stopped")
  assertFalse(failed.canStart); assertTrue(failed.canUpdate); assertTrue(failed.text.contains("unavailable")); assertTrue(failed.text.contains("404"))
 }
 @Test fun failedUpdatesKeepFilteringAndNewVersionWaitsForExplicitRestart() {
  val old=snapshot(1,"old.example"); val session=FilterSession(old); val latest=snapshot(2,"new.example")
  val running=UpdateUi.render(latest,session.version,false,false,"","offline","Running")
  assertTrue(running.canStart); assertTrue(running.text.contains("Running rules v1")); assertTrue(running.text.contains("stop/start")); assertTrue(running.text.contains("offline"))
  assertTrue(session.blocked("old.example")); assertFalse(session.blocked("new.example"))
  assertTrue(FilterSession(latest).blocked("new.example"))
 }
}
