package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
class DnsTest {
 companion object { fun query(host:String="Example.COM"):ByteArray { val o=java.io.ByteArrayOutputStream(); o.write(byteArrayOf(0x12,0x34,1,0,0,1,0,0,0,0,0,0)); host.split('.').forEach { o.write(it.length); o.write(it.toByteArray()) }; o.write(byteArrayOf(0,0,1,0,1)); return o.toByteArray() } }
 @Test fun questionAndNxdomain() {
 val q=query(); assertEquals("example.com",Dns.question(q).host)
 val r=Dns.error(q,3); assertEquals(0x12,r[0].toInt()); assertEquals(0x34,r[1].toInt()); assertEquals(3,r[3].toInt() and 15); assertTrue(Dns.accepts(q,r))
 val bad=r.clone(); bad[1]=0; assertFalse(Dns.accepts(q,bad))
 }
}
