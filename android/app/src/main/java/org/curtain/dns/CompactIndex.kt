package org.curtain.dns
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Immutable absolute-access reader. No shared cursor and at most 16 decoded keys per probe. */
class CompactIndex(input: ByteBuffer) {
 private val bytes = input.asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN)
 val count: Long
 private val blocks: Int
 private val start: Int
 private fun u(p: Int) = bytes.get(p).toInt() and 255
 init {
  require(bytes.limit() >= 64)
  require((0..7).map { u(it).toChar() }.joinToString("") == "CURTFC01")
  count = bytes.getLong(8); val n = bytes.getLong(16); val size = bytes.getLong(24)
  require(count in 0..100_000_000 && n == (count+15)/16)
  require(size >= 0 && 64+n*8+size == bytes.limit().toLong())
  blocks=n.toInt(); start=64+blocks*8
  val digest=MessageDigest.getInstance("SHA-256"); val copy=bytes.duplicate(); copy.limit(32); digest.update(copy); copy.limit(bytes.limit()); copy.position(64); digest.update(copy)
  require(digest.digest().contentEquals(ByteArray(32) { bytes.get(32+it) })) { "Index checksum mismatch" }
  var p=start; var previous=ByteArray(253); var current=ByteArray(253); var previousLength=0
  var i=0
  while(i<count.toInt()) {
   if(i%16==0) require(bytes.getLong(64+i/16*8)==(p-start).toLong())
   require(p<=bytes.limit()-3); val prefix=u(p); val tail=u(p+1); val flags=u(p+2); val length=prefix+tail
   require(prefix<=previousLength && length in 1..253 && flags in 1..63 && (i%16!=0 || prefix==0) && p+3+tail<=bytes.limit())
   System.arraycopy(previous,0,current,0,prefix)
   var j=0; while(j<tail) { current[prefix+j]=bytes.get(p+3+j); j++ }
   var label=0; var order=0; j=0
   while(j<length) {
    val c=current[j].toInt() and 255
    if(c==46) { require(label in 1..63 && current[j-1].toInt()!=45); label=0 }
    else { require(c in 97..122 || c in 48..57 || c==45); require(label!=0 || c!=45); label++ }
    if(order==0 && j<previousLength) order=c-(previous[j].toInt() and 255)
    j++
   }
   require(label in 1..63 && current[length-1].toInt()!=45)
   if(order==0) order=length-previousLength
   require(i==0 || order>0)
   val swap=previous; previous=current; current=swap; previousLength=length; p+=3+tail; i++
  }
  require(p==bytes.limit())
 }
 private fun offset(block: Int): Int {
  val off=bytes.getLong(64+block*8); require(off in 0 until (bytes.limit()-start).toLong()); return start+off.toInt()
 }
 private fun first(block:Int):String { val p=offset(block); return String(ByteArray(u(p+1)) { bytes.get(p+3+it) },Charsets.US_ASCII) }
 fun flags(host:String):Int {
  var lo=0; var hi=blocks
  while(lo<hi) { val mid=(lo+hi)/2; if(first(mid)<=host) lo=mid+1 else hi=mid }
  if(lo==0) return 0
  val block=lo-1; var p=offset(block); var key=""
  repeat(minOf(16,count.toInt()-block*16)) {
   key=key.take(u(p))+String(ByteArray(u(p+1)) { bytes.get(p+3+it) },Charsets.US_ASCII)
   val f=u(p+2); p+=3+u(p+1)
   if(key==host) return f
   if(key>host) return 0
  }; return 0
 }
 fun blocked(host:String):Boolean = blockRule(host)!=null
 /** Matching rule kind when the host is blocked (and not allowed), else null. Exact = the host's own entry; suffix = an ancestor's. */
 fun blockRule(host:String):RuleKind? {
  require(validHost(host))
  val f=flags(host); var block=f and 3 != 0; var allow=f and 24 != 0
  host.forEachIndexed { i,c -> if(c=='.') { val a=flags(host.substring(i+1)); block=block || a and 6 != 0; allow=allow || a and 48 != 0 } }
  return if(block && !allow) (if(f and 1 != 0) RuleKind.EXACT else RuleKind.SUFFIX) else null
 }
 companion object {
  fun validHost(s:String):Boolean = s.length in 1..253 && s.split('.').all { l -> l.length in 1..63 && l.first()!='-' && l.last()!='-' && l.all { it in 'a'..'z' || it in '0'..'9' || it=='-' } }
 }
}
