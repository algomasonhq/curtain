package org.curtain.dns.inspection

import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Locale

enum class InspectionAction { ALLOW, BLOCK, REPLACE }

/** A local decision. REPLACE bodies are copied by [InspectionRule] and served as UTF-8 bytes. */
data class InspectionDecision(val action:InspectionAction, val body:ByteArray=ByteArray(0)) {
 companion object { val ALLOW=InspectionDecision(InspectionAction.ALLOW) }
}

/** Only exact canonical host and raw encoded-path segment prefix matching are supported. */
fun interface InspectionPolicy {
 fun decide(host:String,rawPath:String):InspectionDecision
}

class InspectionRule(host:String,pathPrefix:String,val action:InspectionAction,body:ByteArray=ByteArray(0)) {
 val host:String=InspectionUrls.canonicalHost(host)
 val pathPrefix:String=InspectionUrls.canonicalPathPrefix(pathPrefix)
 val body:ByteArray=body.copyOf()
 init {
  require(action!=InspectionAction.REPLACE || this.body.isNotEmpty()) { "replacement body is required" }
 }
}

/** Deterministic policy: longest matching segment prefix wins; ties keep the earlier rule. */
class HostPathRules(rules:List<InspectionRule>) : InspectionPolicy {
 constructor(vararg rules:InspectionRule):this(rules.toList())
 private val rules:List<InspectionRule> =rules.toList()

 override fun decide(host:String,rawPath:String):InspectionDecision {
  val canonicalHost=try { InspectionUrls.canonicalHost(host) } catch(_:IllegalArgumentException) { return InspectionDecision.ALLOW }
  if(!InspectionUrls.validRequestPath(rawPath)) return InspectionDecision.ALLOW
  var best:InspectionRule?=null
  for(rule in rules) {
   if(rule.host==canonicalHost && InspectionUrls.pathPrefixMatches(rule.pathPrefix,rawPath)) {
    if(best==null || rule.pathPrefix.length>best.pathPrefix.length) best=rule
   }
  }
  return if(best==null) InspectionDecision.ALLOW else InspectionDecision(best.action,best.body.copyOf())
 }
}

internal object InspectionUrls {
 private const val MAX_HOST=253
 private const val MAX_PATH=8*1024

 fun canonicalHost(raw:String):String {
  require(raw.isNotEmpty() && raw.length<=MAX_HOST+2) { "invalid host length" }
  require(raw.none { it=='\u0000' || it<'\u0020' || it=='\u007f' || it==' ' || it=='\t' })
  require(!raw.contains('@') && !raw.contains('/') && !raw.contains('\\') && !raw.contains('?') && !raw.contains('#')) { "invalid host characters" }
  val bracketed=raw.startsWith("[") || raw.endsWith("]")
  val host=if(bracketed) {
   require(raw.startsWith("[") && raw.endsWith("]") && raw.length>2) { "invalid bracketed host" }
   raw.substring(1,raw.length-1)
  } else raw
  require(!host.contains('[') && !host.contains(']')) { "invalid bracket" }
  if(host.contains(':')) {
   require(!host.contains('%')) { "IPv6 zone identifiers are not accepted" }
   val address=try { InetAddress.getByName(host) } catch(_:Exception) { throw IllegalArgumentException("invalid IPv6 address") }
   require(address is Inet6Address) { "invalid IPv6 address" }
   val literal=address.hostAddress ?: throw IllegalArgumentException("invalid IPv6 address")
   return literal.lowercase(Locale.ROOT)
  }
  val withoutRoot=host.trimEnd('.')
  require(withoutRoot.isNotEmpty() && withoutRoot.length<=MAX_HOST) { "invalid host length" }
  val ascii=try { IDN.toASCII(withoutRoot,IDN.ALLOW_UNASSIGNED) } catch(_:Exception) { throw IllegalArgumentException("invalid host") }
  val canonical=ascii.lowercase(Locale.ROOT)
  for(label in canonical.split('.')) {
   require(label.isNotEmpty() && label.length<=63) { "invalid host label" }
   require(label.first()!='-' && label.last()!='-') { "invalid host label" }
   require(label.all { it in 'a'..'z' || it in '0'..'9' || it=='-' }) { "invalid host label" }
  }
  return canonical
 }

 fun canonicalPathPrefix(raw:String):String {
  require(raw.startsWith('/') && raw.length<=MAX_PATH) { "invalid path prefix" }
  require(raw.none { it=='?' || it=='#' || it=='\\' || it=='\u0000' || it<'\u0020' || it=='\u007f' || it==' ' || it=='\t' }) { "invalid path prefix characters" }
  require(!raw.contains("//")) { "empty path segment" }
  val path=if(raw.length>1) raw.trimEnd('/') else raw
  if(path=="/") return path
  for(segment in path.substring(1).split('/')) {
   require(segment!="." && segment!="..") { "dot path segment" }
  }
  return path
 }

 /** True for a validated origin-form path (no query, fragment or ambiguous encoded separators). */
 fun validRequestPath(rawPath:String):Boolean {
  if(!rawPath.startsWith('/') || rawPath.length>MAX_PATH) return false
  if(rawPath.contains('\\') || rawPath.contains('#') || rawPath.contains("//")) return false
  if(rawPath.any { it=='\u0000' || it<'\u0020' || it=='\u007f' || it==' ' || it=='\t' }) return false
  val lower=rawPath.lowercase(Locale.ROOT)
  if(lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00")) return false
  for(segment in rawPath.substring(1).split('/')) {
   if(segment=="." || segment=="..") return false
  }
  return true
 }

 fun pathPrefixMatches(prefix:String,rawPath:String):Boolean {
  if(prefix=="/") return true
  if(!rawPath.startsWith(prefix)) return false
  return rawPath.length==prefix.length || rawPath[prefix.length]=='/'
 }

 data class Authority(val host:String,val port:Int)

 fun parseAuthority(raw:String):Authority {
  require(raw.isNotEmpty() && raw.length<=MAX_HOST+16) { "invalid authority" }
  require(raw.none { it=='\u0000' || it<'\u0020' || it=='\u007f' || it==' ' || it=='\t' }) { "invalid authority characters" }
  require(!raw.contains('@') && !raw.contains('/') && !raw.contains('\\') && !raw.contains('?') && !raw.contains('#')) { "invalid authority characters" }
  val hostPart:String
  val portPart:String?
  if(raw.startsWith("[")) {
   val close=raw.indexOf(']')
   require(close>1) { "invalid IPv6 authority" }
   hostPart=raw.substring(0,close+1)
   val rest=raw.substring(close+1)
   if(rest.isEmpty()) portPart=null
   else { require(rest.startsWith(':')) { "invalid authority port" }; portPart=rest.substring(1) }
  } else {
   val colon=raw.lastIndexOf(':')
   if(colon<0) { hostPart=raw; portPart=null }
   else { require(raw.indexOf(':')==colon) { "IPv6 literals require brackets" }; hostPart=raw.substring(0,colon); portPart=raw.substring(colon+1) }
  }
  val port=if(portPart==null) 443 else {
   require(portPart.isNotEmpty() && portPart.length<=5 && portPart.all { it in '0'..'9' }) { "invalid authority port" }
   portPart.toInt().also { require(it in 1..65535) { "invalid authority port" } }
  }
  return Authority(canonicalHost(hostPart),port)
 }

 fun urlHost(host:String):String = if(host.contains(':')) "[$host]" else host
}
