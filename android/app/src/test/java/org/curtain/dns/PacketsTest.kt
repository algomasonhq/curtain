package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
class PacketsTest {
 companion object { fun packet():ByteArray {
 val dns=DnsTest.query(); val b=ByteArray(28+dns.size); b[0]=0x45; Dns.put(b,2,b.size); b[8]=64; b[9]=17
 byteArrayOf(10,111,0,1).copyInto(b,12); byteArrayOf(10,111,0,2).copyInto(b,16)
 Dns.put(b,20,32000); Dns.put(b,22,53); Dns.put(b,24,8+dns.size); dns.copyInto(b,28)
 var sum=0; for(i in 0 until 20 step 2) sum+=Dns.u(b,i); while(sum ushr 16!=0) sum=(sum and 65535)+(sum ushr 16); Dns.put(b,10,sum.inv() and 65535); return b
 } }
 @Test fun packetRoundtripChecksums() {
 val b=packet(); val q=Packets.parse(b); assertNotNull(q)
 val r=Packets.reply(q!!,Dns.error(q.dns,3)); assertEquals(0,Packets.checksum(r,0,20)); assertEquals(53,Dns.u(r,20)); assertEquals(32000,Dns.u(r,22)); assertArrayEquals(b.copyOfRange(12,16),r.copyOfRange(16,20))
 val pseudo=r.copyOfRange(12,20)+byteArrayOf(0,17,((r.size-20) ushr 8).toByte(),(r.size-20).toByte())+r.copyOfRange(20,r.size)
 assertEquals(0,Packets.checksum(pseudo))
 }
}
