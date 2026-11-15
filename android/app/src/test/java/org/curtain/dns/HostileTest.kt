package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
import java.nio.ByteBuffer
class HostileTest {
 private fun rejected(block:()->Unit) { try { block(); fail("Accepted hostile input") } catch(_:IllegalArgumentException) {} }
 @Test fun dnsHostileBounds() {
 val q=DnsTest.query()
 for(n in 0 until q.size) rejected { Dns.question(q.copyOf(n)) }
 val loop=q.clone(); loop[12]=0xc0.toByte(); loop[13]=12; rejected { Dns.question(loop) }
 val forward=q.clone(); forward[12]=0xc0.toByte(); forward[13]=14; rejected { Dns.question(forward) }
 val many=q.clone(); many[5]=2; rejected { Dns.question(many) }
 val oversized=DnsTest.query("a".repeat(64)+".com"); rejected { Dns.question(oversized) }
 val unicode=q.clone(); unicode[13]=0xff.toByte(); rejected { Dns.question(unicode) }
 assertFalse(Dns.accepts(q,Dns.error(DnsTest.query("other.com"),3)))
 assertFalse(Dns.accepts(q,q))
 }
 @Test fun packetRejectsFragmentsIpv6WrongRouteAndCorruption() {
 val b=PacketsTest.packet()
 for(n in b.indices) assertNull(Packets.parse(b.copyOf(n)))
 for(index in listOf(0,2,6,9,10,16,22,24,26)) { val a=b.clone(); a[index]=(a[index].toInt() xor 1).toByte(); assertNull(Packets.parse(a)) }
 val six=b.clone(); six[0]=0x60; assertNull(Packets.parse(six))
 }
 @Test fun allIndexTruncationsAndMutations() {
 val a=CompactIndexTest.fixture(listOf("ads.example" to 1,"example" to 2))
 for(n in a.indices) rejected { CompactIndex(ByteBuffer.wrap(a.copyOf(n))) }
 for(n in a.indices) { val b=a.clone(); b[n]=(b[n].toInt() xor 1).toByte(); rejected { CompactIndex(ByteBuffer.wrap(b)) } }
 }
 @Test fun fullSnapshotCountAndMembership() {
 val file=java.io.File("../../native/compact-evidence/audited.fc")
 org.junit.Assume.assumeTrue("Optional published-snapshot integration input not present", file.isFile)
 java.io.RandomAccessFile(file,"r").use { f ->
 val i=CompactIndex(f.channel.map(java.nio.channels.FileChannel.MapMode.READ_ONLY,0,f.length()))
 assertEquals(9737280L,i.count); assertTrue(i.blocked("000000000000000000000000000000000000000000000000000000000000000.invalid").not())
 }
 }
 @Test fun everyFlagAndBlockBoundary() {
 val rules=(0..40).map { "a"+it.toString().padStart(2,'0')+".example" to 1 }+listOf("allow.example" to 16,"desc.example" to 4,"example" to 1,"only.example" to 32)
 val i=CompactIndex(ByteBuffer.wrap(CompactIndexTest.fixture(rules.sortedBy { it.first })))
 rules.forEach { assertEquals(it.second,i.flags(it.first)) }
 assertFalse(i.blocked("x.example")); assertTrue(i.blocked("example")); assertFalse(i.blocked("desc.example")); assertTrue(i.blocked("x.desc.example")); assertFalse(i.blocked("x.allow.example"))
 }
}
