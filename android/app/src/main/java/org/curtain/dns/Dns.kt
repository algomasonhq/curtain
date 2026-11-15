package org.curtain.dns
object Dns {
 fun u(b:ByteArray,p:Int):Int { require(p>=0 && p+1<b.size); return ((b[p].toInt() and 255) shl 8) or (b[p+1].toInt() and 255) }
 fun put(b:ByteArray,p:Int,v:Int) { b[p]=(v ushr 8).toByte(); b[p+1]=v.toByte() }
 private fun name(b:ByteArray,initial:Int):Pair<String,Int> {
  var p=initial; var end=-1; var length=0; val seen=HashSet<Int>(); val labels=ArrayList<String>()
  while(true) {
   require(p in b.indices && seen.add(p) && seen.size<=128)
   val n=b[p].toInt() and 255
   if(n==0) { if(end<0) end=p+1; break }
   if(n and 192==192) { val target=u(b,p) and 16383; require(target>=12 && target<p); if(end<0) end=p+2; p=target; continue }
   require(n in 1..63 && p+1+n<=b.size); length+=n+1; require(length<=254)
   val label=String(b,p+1,n,Charsets.US_ASCII).lowercase(java.util.Locale.ROOT)
   require(label.all { it in 'a'..'z' || it in '0'..'9' || it=='-' || it=='_' })
   labels.add(label); p+=n+1
  }
  return labels.joinToString(".") to end
 }
 fun question(b:ByteArray):Question {
  require(b.size in 17..4096 && u(b,4)==1 && u(b,2) and 0x7800==0)
  val (host,end)=name(b,12); require(host.isNotEmpty() && end+4<=b.size && u(b,end+2)==1)
  return Question(host,u(b,end),end+4)
 }
 fun error(b:ByteArray,code:Int):ByteArray {
  val q=question(b); val r=b.copyOf(q.end)
  put(r,2,0x8080 or (u(b,2) and 0x0100) or code)
  put(r,6,0); put(r,8,0); put(r,10,0); return r
 }
 fun accepts(q:ByteArray,r:ByteArray):Boolean = try {
  val a=question(q); val b=question(r)
  u(q,0)==u(r,0) && u(r,2) and 0x8000!=0 && a.host==b.host && a.type==b.type
 } catch(_:IllegalArgumentException) { false }
}
data class Question(val host:String,val type:Int,val end:Int)
