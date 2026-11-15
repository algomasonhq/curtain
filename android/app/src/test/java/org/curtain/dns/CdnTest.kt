package org.curtain.dns
import org.junit.Test
import org.junit.Assert.*
import java.net.ServerSocket
import java.net.SocketException
import java.nio.file.Files
import java.io.File

class CdnTest {
 private class Server(val response:(String,java.io.OutputStream)->Unit):java.io.Closeable {
  val socket=ServerSocket(0,8,java.net.InetAddress.getByName("127.0.0.1"))
  val base="http://127.0.0.1:${socket.localPort}/curtain/"
  var requests=0
  val thread=Thread {
   while(!socket.isClosed) try { socket.accept().use { client ->
    val reader=client.getInputStream().bufferedReader(); val path=reader.readLine().split(' ')[1]
    while(!reader.readLine().isNullOrEmpty()) {}
    requests++; response(path,client.getOutputStream())
   } } catch(_:SocketException) {} catch(_:java.io.IOException) {}
  }.apply { isDaemon=true; start() }
  override fun close() { socket.close(); thread.join(3000) }
 }
 @Test fun realFullSignedIndexIsDownloadedValidatedAndRestoredOffline() {
  val root=File("../../artifacts/r2/curtain")
  org.junit.Assume.assumeTrue("Optional published signed snapshot not present", File(root,"version.json").isFile)
  val server=Server { path,output ->
   val file=File(root,path.removePrefix("/curtain/"))
   output.write("HTTP/1.1 200 OK\r\nContent-Length: ${file.length()}\r\nConnection: close\r\n\r\n".toByteArray())
   file.inputStream().use { it.copyTo(output) }
  }
  val directory=Files.createTempDirectory("curtain-full").toFile()
  try {
   val client=CdnClient(server.base); val engine=UpdateEngine(directory,UpdateTrust.key)
   var received=0L
   val snapshot=client.update(engine) { n,_ -> received=n }
   assertEquals(120741632L,received); assertEquals(9737280L,snapshot.index.count)
   assertTrue(snapshot.index.blocked("doubleclick.net")); assertFalse(snapshot.index.blocked("example.com"))
   assertEquals(2,server.requests); server.close()
   assertEquals(9737280L,UpdateEngine(directory,UpdateTrust.key).restore()!!.index.count)
   println("REAL LOCAL HTTP fixture: $received bytes, ${snapshot.index.count} domains; signature/hash/full structure/offline PASS; not published")
  } finally { server.close(); directory.walkBottomUp().forEach { it.setWritable(true); it.delete() } }
 }
 @Test fun onlyConfiguredHttpsBaseOrDebugLoopbackIsAccepted() {
  assertEquals("https://cdn.clapbox.net/curtain/version.json",CdnClient().manifestUrl)
  listOf("http://cdn.clapbox.net/curtain/","https://evil.example/curtain/","https://cdn.clapbox.net/else/","https://cdn.clapbox.net/curtain/../","http://127.0.0.1.evil:8000/curtain/").forEach {
   try { CdnClient(it); fail(it) } catch(_:IllegalArgumentException) {}
  }
 }
 @Test fun redirectsHttpErrorsAndOversizedManifestsAreRejected() {
  var mode=0
  val server=Server { _,output ->
   val response=when(mode) { 0 -> "HTTP/1.1 302 Found\r\nLocation: https://evil.example/version.json\r\nContent-Length: 0\r\n\r\n"; 1 -> "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"; else -> "HTTP/1.1 200 OK\r\nContent-Length: 17000\r\n\r\n"+"x".repeat(17000) }
   output.write(response.toByteArray())
  }
  val directory=Files.createTempDirectory("curtain-http").toFile()
  try { repeat(3) { mode=it; try { CdnClient(server.base).update(UpdateEngine(directory,UpdateTrust.key)); fail() } catch(_:java.io.IOException) {} }; assertFalse(File(directory,"current.json").exists()) }
  finally { server.close(); directory.walkBottomUp().forEach { it.delete() } }
 }
}
