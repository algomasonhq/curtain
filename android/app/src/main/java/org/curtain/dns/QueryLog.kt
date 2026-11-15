package org.curtain.dns
import java.io.File
import java.io.FileOutputStream

enum class QueryAction { BLOCKED, ALLOWED, UPSTREAM_ERROR, /** Reserved for SafeSearch/YouTube mapping; never produced yet. */ OVERRIDDEN }
enum class RuleKind(val label:String) { EXACT("exact"), SUFFIX("suffix") }
enum class QueryFilter { ALL, BLOCKED, ALLOWED, ERRORS }

object QueryTypes {
 fun name(t:Int):String = when(t) { 1->"A"; 2->"NS"; 5->"CNAME"; 6->"SOA"; 12->"PTR"; 15->"MX"; 16->"TXT"; 28->"AAAA"; 33->"SRV"; 64->"SVCB"; 65->"HTTPS"; 255->"ANY"; 257->"CAA"; else->"TYPE$t" }
}

/** rcode is -1 when no upstream answer arrived (timeout/failure). rule is set only for BLOCKED. */
data class QueryEntry(val ts:Long,val host:String,val qtype:Int,val action:QueryAction,val rcode:Int,val latencyMs:Long,val rule:String?) {
 private fun safeDomain():String = buildString { host.forEach { append(if(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it=='.' || it=='-' || it=='_' || it=='*') it else '?') } }
 /** One logcat line, key=value, nothing but query data. */
 fun logLine():String = "ts=$ts domain=${safeDomain()} qtype=$qtype qname=${QueryTypes.name(qtype)} action=${action.name} rcode=$rcode latency_ms=$latencyMs" + (if(rule!=null) " rule=$rule" else "")
 fun json():String {
  val sb=StringBuilder("""{"ts":$ts,"domain":"""").also { esc(it,host) }
  sb.append("""","qtype":$qtype,"qname":"${QueryTypes.name(qtype)}","action":"${action.name}","rcode":$rcode,"latency_ms":$latencyMs""")
  if(rule!=null) sb.append(""","rule":"$rule"""")
  return sb.append('}').toString()
 }
 private fun esc(sb:StringBuilder,s:String) { s.forEach { c -> when { c=='"'->sb.append("\\\""); c=='\\'->sb.append("\\\\"); c=='\n'->sb.append("\\n"); c=='\r'->sb.append("\\r"); c=='\t'->sb.append("\\t"); c<' ' || c=='\u2028' || c=='\u2029'->sb.append("\\u%04x".format(c.code)); else->sb.append(c) } } }
}

data class QueryCounts(val total:Long,val blocked:Long,val allowed:Long,val errors:Long)

/** Bounded in-memory ring buffer; off by default. Sinks (logcat, debug file) are called only while enabled. */
class QueryLog(private val capacity:Int=2000,private val logcat:(String)->Unit={},private val file:(String)->Unit={},private val onDisable:()->Unit={}) {
 companion object { @Volatile var shared:QueryLog=QueryLog() }
 @Volatile var enabled=false; private set
 private val lock=Any()
 private val ring=arrayOfNulls<QueryEntry>(capacity); private var next=0; private var size=0
 private var total=0L; private var blocked=0L; private var allowed=0L; private var errors=0L
 fun setEnabled(on:Boolean) {
  if(on) { enabled=true; return }
  enabled=false; clear(); try { onDisable() } catch(_:Exception) {}
 }
 fun record(e:QueryEntry) {
  if(!enabled) return
  synchronized(lock) {
   if(!enabled) return
   ring[next]=e; next=(next+1)%capacity; if(size<capacity) size++
   total++; when(e.action) { QueryAction.BLOCKED->blocked++; QueryAction.ALLOWED->allowed++; QueryAction.UPSTREAM_ERROR->errors++; QueryAction.OVERRIDDEN->{} }
  }
  try { logcat(e.logLine()) } catch(_:Exception) {}
  try { file(e.json()) } catch(_:Exception) {}
 }
 fun clear() { synchronized(lock) { ring.fill(null); next=0; size=0; total=0; blocked=0; allowed=0; errors=0 } }
 fun counts():QueryCounts = synchronized(lock) { QueryCounts(total,blocked,allowed,errors) }
 /** Newest first. */
 fun recent(filter:QueryFilter,limit:Int,search:String=""):List<QueryEntry> = synchronized(lock) {
  val needle=search.trim().lowercase()
  val out=ArrayList<QueryEntry>(minOf(limit,size)); var i=0
  while(i<size && out.size<limit) {
   val e=ring[(next-1-i+2*capacity)%capacity]!!; i++
   val ok=when(filter) { QueryFilter.ALL->true; QueryFilter.BLOCKED->e.action==QueryAction.BLOCKED; QueryFilter.ALLOWED->e.action==QueryAction.ALLOWED; QueryFilter.ERRORS->e.action==QueryAction.UPSTREAM_ERROR }
   if(ok && (needle.isEmpty() || e.host.lowercase().contains(needle))) out.add(e)
  }
  out
 }
}

/** Debug-build JSON-lines dump: one file rotated to <name>.1 at capBytes, so disk use <= 2*capBytes. */
object QueryExport {
 fun label(a:QueryAction):String = if(a==QueryAction.UPSTREAM_ERROR) "ERROR" else a.name
 /** Plain text for copy/share: one logcat-format line per entry, as given (newest first). */
 fun text(entries:List<QueryEntry>):String = entries.joinToString("") { it.logLine()+"\n" }
}

class JsonlFile(private val file:File,private val capBytes:Long=1L shl 20) {
 private val old=File(file.path+".1")
 @Synchronized fun append(line:String) {
  val bytes=(line+"\n").toByteArray(Charsets.UTF_8); if(bytes.size>capBytes) return
  if(file.length()+bytes.size>capBytes) { old.delete(); file.renameTo(old) }
  FileOutputStream(file,true).use { it.write(bytes) }
 }
 @Synchronized fun delete() { file.delete(); old.delete() }
}

/** Query path: filter, relay, and (only when the log is on) record. Result bytes never depend on logging. */
class QueryResolver(private val blockedRule:(String)->RuleKind?,private val upstream:(ByteArray)->ByteArray?,private val log:()->QueryLog,private val clockMs:()->Long={ System.currentTimeMillis() },private val nanos:()->Long={ System.nanoTime() }) {
 constructor(blockedRule:(String)->RuleKind?,upstream:(ByteArray)->ByteArray?,log:QueryLog,clockMs:()->Long={ System.currentTimeMillis() },nanos:()->Long={ System.nanoTime() }):this(blockedRule,upstream,{ log },clockMs,nanos)
 fun handle(query:ByteArray):ByteArray {
  val question=Dns.question(query)
  val l=log(); val on=l.enabled  // single volatile read when off
  val t0=if(on) nanos() else 0L
  val rule=if(CompactIndex.validHost(question.host)) blockedRule(question.host) else null
  val response:ByteArray; val action:QueryAction; val rcode:Int
  if(rule!=null) { response=Dns.error(query,3); action=QueryAction.BLOCKED; rcode=3 }
  else {
   val up=try { upstream(query) } catch(_:Exception) { null }
   if(up==null) { response=Dns.error(query,2); action=QueryAction.UPSTREAM_ERROR; rcode=-1 }
   else { response=up; rcode=up[3].toInt() and 15; action=if(rcode==2) QueryAction.UPSTREAM_ERROR else QueryAction.ALLOWED }
  }
  if(on) l.record(QueryEntry(clockMs(),question.host,question.type,action,rcode,(nanos()-t0)/1_000_000,rule?.label))
  return response
 }
}
