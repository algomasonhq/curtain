package org.curtain.dns
import java.util.Locale
import org.curtain.dns.inspection.InspectionAction
import org.curtain.dns.inspection.InspectionRule
/**
 * Pure settings model for the local HTTPS inspection proxy UI: one rule, one exact host.
 * JVM-only (no Android imports), so unit tests cover validation directly (InspectionSettingsTest).
 *
 * The proxy engine (org.curtain.dns.inspection) owns the authoritative interpretation — exact
 * canonical host and segment-prefix matching on the encoded path — and remains free to reject
 * anything this UI validation let through. This class only stops the UI from persisting obvious
 * garbage: schemes, ports, wildcards, whitespace, control characters or ambiguous rules, and maps
 * a saved rule to the core [InspectionRule] (the core validator stays authoritative).
 */
data class InspectionSettings(
 val host:String="",
 val blockPathPrefix:String="",
 val replacePathPrefix:String="",
 val replacementBody:String=""
) {
 companion object {
  const val MAX_HOST=253; const val MAX_PATH=256; const val MAX_BODY=65536
  val EMPTY=InspectionSettings()
  fun normalizeHost(raw:String):String {
   val t=raw.trim().lowercase(Locale.ROOT)
   return if(t.length>2 && t.first()=='[' && t.last()==']') t.substring(1,t.length-1) else t
  }
  fun isConfigured(s:InspectionSettings) =
   s.host.isNotEmpty()||s.blockPathPrefix.isNotEmpty()||s.replacePathPrefix.isNotEmpty()||s.replacementBody.isNotEmpty()
  /** Lowercased host, trimmed prefixes; body kept as typed. */
  fun sanitized(s:InspectionSettings) =
   InspectionSettings(normalizeHost(s.host),s.blockPathPrefix.trim(),s.replacePathPrefix.trim(),s.replacementBody)
  fun validateHost(raw:String):String? {
   val h=normalizeHost(raw)
   if(h.isEmpty()) return "host is empty"
   if(h.length>MAX_HOST) return "longer than $MAX_HOST characters"
   if(h.contains("://")) return "do not include http:// or https://"
   if(h.contains('*')||h.contains('?')) return "wildcards are not allowed; this rule matches one exact host"
   if(h.any { it=='\u0000' || it.code<0x20 || it.code==0x7f || it==' ' || it=='\t' || it=='@' || it=='/' || it=='\\' || it=='#' || it=='"' || it=='\'' || it=='%' }) return "contains characters that cannot appear in a host"
   if(h.contains(':')) {
    if(!h.all { it in '0'..'9' || it in 'a'..'f' || it==':' }) return "do not include a port"
    if(h.count { it==':' }<2) return "not a valid IPv6 address"
    return null
   }
   if(h.startsWith(".")||h.endsWith(".")) return "leading or trailing dot"
   if(h.contains("..")) return "empty label (..)"
   for(label in h.split('.')) {
    if(label.length>63) return "label longer than 63 characters"
    if(label.isEmpty()||label.startsWith("-")||label.endsWith("-")) return "label must not be empty or start/end with a hyphen"
    if(label.all { it.code<0x80 } && label.any { it !in 'a'..'z' && it !in '0'..'9' && it!='-' }) return "label contains characters other than letters, digits and hyphens"
   }
   return null
  }
  /** Structural validation of an encoded path prefix; segment-prefix semantics are the engine's. */
  fun validatePathPrefix(raw:String):String? {
   val p=raw.trim()
   if(p.isEmpty()) return "prefix is empty"
   if(!p.startsWith("/")) return "must start with /"
   if(p.length>MAX_PATH) return "longer than $MAX_PATH characters"
   if(p.contains("//")) return "empty path segment (//)"
   if(p.split('/').any { it=="."||it==".." }) return "must not contain . or .. path segments"
   if(p.contains('?')||p.contains('#')) return "must not include the query (?) or fragment (#)"
   if(p.any { it.code<0x20||it.code>0x7e }) return "must be printable ASCII (the engine matches the encoded path)"
   if(p.contains(' ')) return "must not contain spaces"
   return null
  }
  fun validateBody(raw:String):String? {
   if(raw.isEmpty()) return "body is empty"
   if(raw.length>MAX_BODY) return "longer than $MAX_BODY characters"
   return null
  }
  /** null = one well-formed rule, or nothing configured at all (proxy simply runs without a rule). */
  fun validate(s:InspectionSettings):String? {
   if(!isConfigured(s)) return null
   validateHost(s.host)?.let { return "Host $it" }
   val block=s.blockPathPrefix.trim(); val replace=s.replacePathPrefix.trim()
   if(block.isNotEmpty()&&replace.isNotEmpty()) return "Use either a block path prefix or a replace path prefix, not both"
   if(block.isNotEmpty()) { validatePathPrefix(block)?.let { return "Block path $it" }; return null }
   if(replace.isNotEmpty()) {
    validatePathPrefix(replace)?.let { return "Replace path $it" }
    validateBody(s.replacementBody)?.let { return "Replacement body $it" }
    return null
   }
   return "Set a block path prefix, or a replace path prefix with a replacement body"
  }
  fun actionKind(s:InspectionSettings):String? {
   if(!isConfigured(s)) return null
   return if(s.blockPathPrefix.trim().isNotEmpty()) "block" else if(s.replacePathPrefix.trim().isNotEmpty()) "replace" else null
  }
  fun ruleText(s:InspectionSettings):String = when(actionKind(s)) {
   "block"->"Block https://${normalizeHost(s.host)}${s.blockPathPrefix.trim()}… locally"
   "replace"->"Replace https://${normalizeHost(s.host)}${s.replacePathPrefix.trim()}… with a local body (${s.replacementBody.length} chars)"
   else->"No local rule configured"
  }
  private const val K_HOST="inspection_host"; private const val K_BLOCK="inspection_block_path"
  private const val K_REPLACE="inspection_replace_path"; private const val K_BODY="inspection_replacement_body"
  /** Only non-empty values are written; missing keys read back as the off (unconfigured) state. */
  fun toPrefs(s:InspectionSettings):Map<String,String> = buildMap {
   if(s.host.isNotEmpty()) put(K_HOST,s.host)
   if(s.blockPathPrefix.isNotEmpty()) put(K_BLOCK,s.blockPathPrefix)
   if(s.replacePathPrefix.isNotEmpty()) put(K_REPLACE,s.replacePathPrefix)
   if(s.replacementBody.isNotEmpty()) put(K_BODY,s.replacementBody)
  }
  fun fromPrefs(m:Map<String,*>):InspectionSettings = InspectionSettings(
   m[K_HOST] as? String ?: "", m[K_BLOCK] as? String ?: "", m[K_REPLACE] as? String ?: "", m[K_BODY] as? String ?: "")
  /** Maps a saved rule to the core engine rule; null = no rule configured. The core validator
   *  (InspectionRule) remains authoritative and throws IllegalArgumentException on anything it
   *  rejects, which callers must surface — not swallow. */
  fun coreRule(s:InspectionSettings):InspectionRule? = when(actionKind(s)) {
   "block"->InspectionRule(s.host,s.blockPathPrefix.trim(),InspectionAction.BLOCK)
   "replace"->InspectionRule(s.host,s.replacePathPrefix.trim(),InspectionAction.REPLACE,s.replacementBody.toByteArray(Charsets.UTF_8))
   else->null
  }
 }
 fun validate():String?=Companion.validate(this)
 fun actionKind():String?=Companion.actionKind(this)
 fun ruleText():String=Companion.ruleText(this)
 fun coreRule():InspectionRule?=Companion.coreRule(this)
 fun toPrefs():Map<String,String> =Companion.toPrefs(this)
}
