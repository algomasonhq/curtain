package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
import java.io.File
import java.nio.ByteBuffer

class QueryLogTest {
 private fun entry(i:Int,action:QueryAction=QueryAction.ALLOWED,host:String="h$i.example") = QueryEntry(1000L+i,host,1,action,0,5,null)
 private fun log(cap:Int=5):QueryLog = QueryLog(cap).also { it.setEnabled(true) }

 @Test fun offByDefaultAndRecordIsNoop() {
  val l=QueryLog(5); assertFalse(l.enabled); l.record(entry(1)); assertEquals(0,l.recent(QueryFilter.ALL,10).size); assertEquals(0,l.counts().total)
 }
 @Test fun ringBufferKeepsNewestBounded() {
  val l=log(5); for(i in 1..12) l.record(entry(i))
  val r=l.recent(QueryFilter.ALL,200); assertEquals(5,r.size); assertEquals("h12.example",r.first().host); assertEquals("h8.example",r.last().host)
  assertEquals(12,l.counts().total) // lifetime since clear, not buffer size
  assertEquals(2,l.recent(QueryFilter.ALL,2).size)
 }
 @Test fun filtersAndCounts() {
  val l=log(50); l.record(entry(1,QueryAction.BLOCKED)); l.record(entry(2)); l.record(entry(3)); l.record(entry(4,QueryAction.UPSTREAM_ERROR)); l.record(entry(5,QueryAction.OVERRIDDEN))
  val c=l.counts(); assertEquals(1,c.blocked); assertEquals(2,c.allowed); assertEquals(1,c.errors); assertEquals(5,c.total)
  assertEquals(1,l.recent(QueryFilter.BLOCKED,10).size); assertEquals(2,l.recent(QueryFilter.ALLOWED,10).size); assertEquals(1,l.recent(QueryFilter.ERRORS,10).size)
 }
 @Test fun toggleOffClearsAndStopsRecording() {
  val l=log(); l.record(entry(1)); l.setEnabled(false)
  assertEquals(0,l.recent(QueryFilter.ALL,10).size); assertEquals(0,l.counts().total); l.record(entry(2)); assertEquals(0,l.recent(QueryFilter.ALL,10).size)
  l.setEnabled(true); assertEquals(0,l.recent(QueryFilter.ALL,10).size)
 }
 @Test fun clearKeepsEnabled() { val l=log(); l.record(entry(1)); l.clear(); assertTrue(l.enabled); assertEquals(0,l.counts().total); l.record(entry(2)); assertEquals(1,l.counts().total) }
 @Test fun threadSafe() {
  val l=log(100); val ts=(1..8).map { t -> Thread { for(i in 1..500) l.record(entry(t*1000+i)) } }; ts.forEach { it.start() }; ts.forEach { it.join() }
  assertEquals(4000,l.counts().total); assertEquals(100,l.recent(QueryFilter.ALL,1000).size)
 }
 @Test fun logcatLineFormat() {
  val e=QueryEntry(1700000000123L,"ads.example.com",28,QueryAction.BLOCKED,3,2,"suffix")
  assertEquals("ts=1700000000123 domain=ads.example.com qtype=28 qname=AAAA action=BLOCKED rcode=3 latency_ms=2 rule=suffix",e.logLine())
  assertEquals("ts=1 domain=a.b qtype=65 qname=HTTPS action=ALLOWED rcode=0 latency_ms=9",QueryEntry(1,"a.b",65,QueryAction.ALLOWED,0,9,null).logLine())
  assertTrue(QueryEntry(1,"a.b",999,QueryAction.ALLOWED,0,9,null).logLine().contains("qname=TYPE999"))
  assertEquals("A",QueryTypes.name(1)); assertEquals("OVERRIDDEN",QueryAction.OVERRIDDEN.name)
 }
 @Test fun hostileDomainIsSingleLineAndKeyValueSafe() {
  val e=QueryEntry(1,"a b\nc=d\u0000\"\\é",1,QueryAction.ALLOWED,0,0,null)
  val line=e.logLine(); assertFalse(line.contains('\n')); assertEquals(1,Regex("domain=").findAll(line).count()); assertEquals(1,Regex(" domain=\\S+ ").findAll(line).count())
  val j=e.json(); assertFalse(j.contains('\n')); assertTrue(j.contains("\\n")); assertTrue(j.contains("\\u0000")); assertTrue(j.contains("\\\"")); assertTrue(j.contains("\\\\"))
 }
 @Test fun jsonShape() {
  assertEquals("""{"ts":5,"domain":"a.b","qtype":1,"qname":"A","action":"BLOCKED","rcode":3,"latency_ms":0,"rule":"exact"}""",QueryEntry(5,"a.b",1,QueryAction.BLOCKED,3,0,"exact").json())
  assertEquals("""{"ts":5,"domain":"a.b","qtype":1,"qname":"A","action":"ALLOWED","rcode":0,"latency_ms":0}""",QueryEntry(5,"a.b",1,QueryAction.ALLOWED,0,0,null).json())
 }
 @Test fun sinksReceiveOnlyWhileEnabled() {
  val lines=mutableListOf<String>(); val json=mutableListOf<String>(); val l=QueryLog(5,{ lines.add(it) },{ json.add(it) })
  l.record(entry(1)); assertTrue(lines.isEmpty() && json.isEmpty()); l.setEnabled(true); l.record(entry(2)); assertEquals(1,lines.size); assertEquals(1,json.size)
  l.setEnabled(false); l.record(entry(3)); assertEquals(1,lines.size)
 }
 @Test fun sinkFailureNeverBreaksRecording() { val l=QueryLog(5,{ error("x") },{ error("y") }); l.setEnabled(true); l.record(entry(1)); assertEquals(1,l.counts().total) }

 @Test fun jsonlRotatesAtCapAndClears() {
  val dir=java.nio.file.Files.createTempDirectory("ql").toFile(); val f=File(dir,"querylog.jsonl"); val s=JsonlFile(f,1024)
  val line="x".repeat(99); for(i in 1..50) s.append(line)
  assertTrue(f.length()<=1024); assertTrue(File(dir,"querylog.jsonl.1").exists()); assertTrue(File(dir,"querylog.jsonl.1").length()<=1024)
  assertEquals(0L,f.readLines().count { it.length!=99 }.toLong())
  val total=f.readLines().size+File(dir,"querylog.jsonl.1").readLines().size; assertTrue(total in 10..50)
  s.delete(); assertFalse(f.exists()); assertFalse(File(dir,"querylog.jsonl.1").exists())
 }
 @Test fun jsonlOversizeSingleLineDropped() { val dir=java.nio.file.Files.createTempDirectory("ql").toFile(); val f=File(dir,"q"); JsonlFile(f,10).append("x".repeat(50)); assertFalse(f.exists() && f.length()>10) }
 @Test fun disablingDeletesFileSink() {
  val dir=java.nio.file.Files.createTempDirectory("ql").toFile(); val f=File(dir,"querylog.jsonl"); val s=JsonlFile(f,1024)
  val l=QueryLog(5,{},{ s.append(it) },{ s.delete() }); l.setEnabled(true); l.record(entry(1)); assertTrue(f.exists()); l.setEnabled(false); assertFalse(f.exists())
 }

 // --- resolver pipeline: logging must not change DNS bytes
 private val index=CompactIndex(ByteBuffer.wrap(CompactIndexTest.fixture(listOf("ads.example" to 1,"allow.ads.example" to 8,"example" to 2).sortedBy { it.first })))
 private val upstreamOk={ q:ByteArray -> val r=q.clone(); r[2]=(r[2].toInt() or 0x80).toByte(); r }
 private fun resolver(l:QueryLog,up:(ByteArray)->ByteArray?)=QueryResolver(blockedRule={ h -> index.blockRule(h) },upstream=up,log=l,clockMs={ 42L },nanos=object:()->Long { var t=0L; override fun invoke():Long { t+=3_000_000; return t } })
 @Test fun blockRuleKinds() {
  assertEquals(RuleKind.EXACT,index.blockRule("ads.example")); assertEquals(RuleKind.SUFFIX,index.blockRule("x.example")); assertNull(index.blockRule("allow.ads.example")); assertNull(index.blockRule("other.test"))
 }
 @Test fun loggingDoesNotAlterBytes() {
  val hosts=listOf("ads.example","x.example","allow.ads.example","Other.TEST")
  for(h in hosts) for(up in listOf<(ByteArray)->ByteArray?>(upstreamOk,{ null },{ q -> Dns.error(q,2) })) {
   val q=DnsTest.query(h); val off=QueryLog(10); val on=log(10)
   assertArrayEquals(h,resolver(off,up).handle(q),resolver(on,up).handle(q))
   assertEquals(0,off.counts().total); assertEquals(1,on.counts().total)
  }
 }
 @Test fun upstreamThrowingBecomesServfailAndIsLogged() {
  val l=log(); val r=resolver(l){ throw java.io.IOException("x") }.handle(DnsTest.query("a.test")); assertEquals(2,r[3].toInt() and 15)
  assertEquals(QueryAction.UPSTREAM_ERROR,l.recent(QueryFilter.ALL,1)[0].action)
 }
 @Test fun entriesClassified() {
  val l=log(20); val q=DnsTest.query("Ads.Example")
  resolver(l,upstreamOk).handle(q); resolver(l,upstreamOk).handle(DnsTest.query("other.test")); resolver(l){ null }.handle(DnsTest.query("t.test")); resolver(l){ Dns.error(it,2) }.handle(DnsTest.query("s.test"))
  val e=l.recent(QueryFilter.ALL,10).reversed()
  assertEquals(QueryAction.BLOCKED,e[0].action); assertEquals("ads.example",e[0].host); assertEquals(3,e[0].rcode); assertEquals("exact",e[0].rule); assertEquals(1,e[0].qtype); assertEquals(42L,e[0].ts)
  assertEquals(QueryAction.ALLOWED,e[1].action); assertEquals(0,e[1].rcode); assertEquals(3,e[1].latencyMs); assertNull(e[1].rule)
  assertEquals(QueryAction.UPSTREAM_ERROR,e[2].action); assertEquals(-1,e[2].rcode)
  assertEquals(QueryAction.UPSTREAM_ERROR,e[3].action); assertEquals(2,e[3].rcode)
 }
 @Test fun upstreamNxdomainIsAllowedNotError() { val l=log(); resolver(l){ Dns.error(it,3) }.handle(DnsTest.query("nx.test")); assertEquals(QueryAction.ALLOWED,l.recent(QueryFilter.ALL,1)[0].action); assertEquals(3,l.recent(QueryFilter.ALL,1)[0].rcode) }
 @Test fun malformedQueryThrowsLikeBeforeAndIsNotLogged() { val l=log(); try { resolver(l,upstreamOk).handle(ByteArray(5)); fail() } catch(_:Exception) {}; assertEquals(0,l.counts().total) }
 @Test fun searchIsCaseInsensitiveSubstringCombinedWithFilter() {
  val l=log(50); l.record(entry(1,QueryAction.BLOCKED,"Ads.Tracker.example")); l.record(entry(2,QueryAction.ALLOWED,"tracker.good.test")); l.record(entry(3,QueryAction.ALLOWED,"other.test"))
  assertEquals(2,l.recent(QueryFilter.ALL,10,"TRACKER").size); assertEquals(1,l.recent(QueryFilter.BLOCKED,10,"tracker").size); assertEquals(3,l.recent(QueryFilter.ALL,10,"  ").size); assertEquals(0,l.recent(QueryFilter.ALL,10,"zzz").size)
  assertEquals(1,l.recent(QueryFilter.ALL,1,"tracker").size) // limit applies after search
 }
 @Test fun exportTextOneLinePerVisibleEntryNewestFirst() {
  val l=log(10); l.record(entry(1)); l.record(entry(2,QueryAction.BLOCKED))
  val t=QueryExport.text(l.recent(QueryFilter.ALL,10)); val lines=t.trim().lines(); assertEquals(2,lines.size); assertTrue(lines[0].contains("domain=h2.example") && lines[0].contains("action=BLOCKED")); assertTrue(lines[1].contains("h1.example"))
  assertEquals("",QueryExport.text(emptyList()))
 }
 @Test fun displayLabelsMapErrorsAndOverride() { assertEquals("BLOCKED",QueryExport.label(QueryAction.BLOCKED)); assertEquals("ERROR",QueryExport.label(QueryAction.UPSTREAM_ERROR)); assertEquals("OVERRIDDEN",QueryExport.label(QueryAction.OVERRIDDEN)) }
}
