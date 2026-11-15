package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
class CompactIndexTest {
 companion object {
 fun fixture(rules: List<Pair<String,Int>>): ByteArray {
 val out = java.io.ByteArrayOutputStream(); val offsets = mutableListOf<Long>(); var previous = ""
 rules.forEachIndexed { i, (key,flags) ->
 var prefix = 0
 if(i%16==0) offsets.add(out.size().toLong()) else while(prefix<minOf(previous.length,key.length)&&previous[prefix]==key[prefix]) prefix++
 out.write(prefix); out.write(key.length-prefix); out.write(flags); out.write(key.substring(prefix).toByteArray()); previous=key
 }
 val payload=out.toByteArray(); val b=ByteBuffer.allocate(64+offsets.size*8+payload.size).order(ByteOrder.LITTLE_ENDIAN)
 b.put("CURTFC01".toByteArray()); b.putLong(rules.size.toLong()); b.putLong(offsets.size.toLong()); b.putLong(payload.size.toLong()); b.position(64); offsets.forEach { b.putLong(it) }; b.put(payload)
 val a=b.array(); val digest=MessageDigest.getInstance("SHA-256"); digest.update(a,0,32); digest.update(a,64,a.size-64); System.arraycopy(digest.digest(),0,a,32,32); return a
 }
 }
 @Test fun exactSuffixAndAllow() {
 val i=CompactIndex(ByteBuffer.wrap(fixture(listOf("ads.example" to 1,"allow.ads.example" to 8,"example" to 2))))
 assertEquals(3L,i.count); assertEquals(1,i.flags("ads.example")); assertTrue(i.blocked("x.example")); assertFalse(i.blocked("allow.ads.example")); assertFalse(i.blocked("notexample"))
 }
}
