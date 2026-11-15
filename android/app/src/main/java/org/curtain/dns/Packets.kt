package org.curtain.dns
/** Only IPv4 UDP addressed to the one routed virtual resolver. IPv6 is never captured. */
object Packets {
 private val resolver=byteArrayOf(10,111,0,2)
 fun checksum(b:ByteArray,start:Int=0,length:Int=b.size):Int {
  var sum=0; var p=start; val end=start+length
  while(p+1<end) { sum+=Dns.u(b,p); p+=2 }; if(p<end) sum+=(b[p].toInt() and 255) shl 8
  while(sum ushr 16!=0) sum=(sum and 65535)+(sum ushr 16)
  return sum.inv() and 65535
 }
 private fun pseudo(b:ByteArray,h:Int):ByteArray = b.copyOfRange(12,20)+byteArrayOf(0,17,((b.size-h) ushr 8).toByte(),(b.size-h).toByte())+b.copyOfRange(h,b.size)
 fun parse(b:ByteArray):UdpQuery? {
  if(b.size<28 || b[0].toInt() ushr 4!=4) return null
  val h=(b[0].toInt() and 15)*4
  if(h<20 || h+8>b.size || Dns.u(b,2)!=b.size || b[9].toInt()!=17 || Dns.u(b,6) and 0xbfff!=0 || checksum(b,0,h)!=0) return null
  if(!b.copyOfRange(16,20).contentEquals(resolver) || Dns.u(b,h+2)!=53 || Dns.u(b,h+4)!=b.size-h || Dns.u(b,h)==0) return null
  if(Dns.u(b,h+6)!=0 && checksum(pseudo(b,h))!=0) return null
  val dns=b.copyOfRange(h+8,b.size)
  try { if(Dns.u(dns,2) and 0x8000!=0) return null; Dns.question(dns) } catch(_:IllegalArgumentException) { return null }
  return UdpQuery(b,dns,h)
 }
 fun reply(q:UdpQuery,dns:ByteArray):ByteArray {
  require(dns.size<=4096)
  val b=ByteArray(28+dns.size); b[0]=0x45; Dns.put(b,2,b.size); b[8]=64; b[9]=17
  q.packet.copyInto(b,12,16,20); q.packet.copyInto(b,16,12,16)
  Dns.put(b,20,53); Dns.put(b,22,Dns.u(q.packet,q.ipLength)); Dns.put(b,24,8+dns.size); dns.copyInto(b,28)
  val udp=checksum(pseudo(b,20)); Dns.put(b,26,if(udp==0) 65535 else udp); Dns.put(b,10,checksum(b,0,20)); return b
 }
}
data class UdpQuery(val packet:ByteArray,val dns:ByteArray,val ipLength:Int)
