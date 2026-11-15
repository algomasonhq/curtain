package org.curtain.dns
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import org.junit.Assert.*
import org.junit.Test
class CorpusTest {
 @Test fun everyAuditedDomainPreservesAllFlags() {
  org.junit.Assume.assumeTrue("Optional full-corpus integration: rebuild canonical.tsv and audited.fc first", File("../../data/blocklists/canonical.tsv").isFile && File("../../native/compact-evidence/audited.fc").isFile)
  RandomAccessFile("../../native/compact-evidence/audited.fc","r").use { file ->
   val index=CompactIndex(file.channel.map(FileChannel.MapMode.READ_ONLY,0,file.length()))
   var previous=""; var flags=0; var domains=0L; var rows=0L
   val bits=mapOf("exact" to 1,"suffix" to 2,"subdomains" to 4,"allow-exact" to 8,"allow-suffix" to 16,"allow-subdomains" to 32)
   fun flush() { if(previous.isNotEmpty()) { assertEquals(previous,flags,index.flags(previous)); domains++ } }
   File("../../data/blocklists/canonical.tsv").bufferedReader().useLines { lines -> lines.forEach { line ->
    val a=line.indexOf('\t'); val b=line.indexOf('\t',a+1); val host=line.substring(a+1,b)
    if(host!=previous) { flush(); previous=host; flags=0 }
    flags=flags or bits.getValue(line.substring(0,a)); rows++
   } }; flush(); assertEquals(index.count,domains); assertEquals(11186031L,rows)
   println("Verified exact complete flags for $domains domains / $rows provenance rows")
  }
 }
}
