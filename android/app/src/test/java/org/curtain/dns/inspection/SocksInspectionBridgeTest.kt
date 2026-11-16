package org.curtain.dns.inspection

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets.US_ASCII
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class SocksInspectionBridgeTest {
 private companion object {
  const val SOCKS_VERSION=5
  const val CMD_CONNECT=1
  const val CMD_UDP_ASSOCIATE=3
  const val ATYP_IPV4=1
  const val ATYP_DOMAIN=3
  const val ATYP_IPV6=4
 }

 /** Loopback HTTP CONNECT endpoint that captures the authority and the exact first TLS record. */
 private inner class FakeInspectionProxy(private val expectedHelloBytes:Int) : Closeable {
  private val server=ServerSocket(0,50,InetAddress.getByName("127.0.0.1"))
  val port:Int get()=server.localPort
  val connected=CountDownLatch(1)
  @Volatile var authority:String?=null
  @Volatile var firstBytes:ByteArray=ByteArray(0)
  @Volatile var failure:String?=null
  private val thread=Thread({
   try {
    server.accept().use { socket ->
     socket.soTimeout=5_000
     val input=BufferedInputStream(socket.getInputStream())
     val header=readHeader(input)
     val firstLine=header.substringBefore("\r\n")
     authority=firstLine.split(' ').getOrNull(1)
     val output=socket.getOutputStream()
     output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(US_ASCII))
     output.flush()
     val first=ByteArray(expectedHelloBytes)
     var offset=0
     while(offset<first.size) {
      val read=input.read(first,offset,first.size-offset)
      if(read<0) break
      offset+=read
     }
     firstBytes=first.copyOf(offset)
     connected.countDown()
     val buffer=ByteArray(8*1024)
     while(true) {
      val read=input.read(buffer)
      if(read<0) break
      output.write(buffer,0,read)
      output.flush()
     }
    }
   } catch(e:Exception) { failure=e.toString(); connected.countDown() }
  },"fake-inspection-proxy").apply { isDaemon=true; start() }

  override fun close() {
   try { server.close() } catch(_:Exception) {}
   thread.join(2_000)
  }
 }

 private class EchoServer : Closeable {
  private val server=ServerSocket(0,50,InetAddress.getByName("127.0.0.1"))
  val port:Int get()=server.localPort
  @Volatile var accepted=0
   private set
  private val thread=Thread({
   try {
    server.accept().use { socket ->
     accepted++
     val input=socket.getInputStream()
     val output=socket.getOutputStream()
     val buffer=ByteArray(4096)
     while(true) {
      val read=input.read(buffer)
      if(read<0) break
      output.write(buffer,0,read)
      output.flush()
     }
    }
   } catch(_:Exception) {}
  },"echo-server").apply { isDaemon=true; start() }

  override fun close() {
   try { server.close() } catch(_:Exception) {}
   thread.join(2_000)
  }
 }

 private fun readHeader(input:InputStream):String {
  val output=ByteArrayOutputStream()
  var matched=0
  val terminator="\r\n\r\n".toByteArray(US_ASCII)
  while(matched<terminator.size) {
   val value=input.read()
   if(value<0) throw IOException("truncated header")
   output.write(value)
   matched=if(value==terminator[matched].toInt()) matched+1 else if(value=='\r'.code) 1 else 0
   if(output.size()>16*1024) throw IOException("header too large")
  }
  return output.toString(US_ASCII.name())
 }

 private fun readExactly(input:InputStream,count:Int):ByteArray {
  val bytes=ByteArray(count)
  var offset=0
  while(offset<count) {
   val read=input.read(bytes,offset,count-offset)
   if(read<0) throw IOException("unexpected EOF")
   offset+=read
  }
  return bytes
 }

 private fun socksNegotiate(socket:Socket) {
  socket.soTimeout=5_000
  val output=socket.getOutputStream()
  output.write(byteArrayOf(SOCKS_VERSION.toByte(),1,0))
  output.flush()
  val reply=readExactly(socket.getInputStream(),2)
  assertArrayEquals(byteArrayOf(SOCKS_VERSION.toByte(),0),reply)
 }

 private fun socksRequest(socket:Socket,command:Int,addressType:Int,address:ByteArray,port:Int):ByteArray {
  val output=socket.getOutputStream()
  val request=ByteArrayOutputStream()
  request.write(SOCKS_VERSION)
  request.write(command)
  request.write(0)
  request.write(addressType)
  when(addressType) {
   ATYP_DOMAIN -> { request.write(address.size); request.write(address) }
   else -> request.write(address)
  }
  request.write(port ushr 8)
  request.write(port and 0xff)
  output.write(request.toByteArray())
  output.flush()
  val head=readExactly(socket.getInputStream(),4)
  assertEquals(SOCKS_VERSION,head[0].toInt())
  val addressLength=when(head[3].toInt()) {
   ATYP_IPV4 -> 4
   ATYP_IPV6 -> 16
   ATYP_DOMAIN -> readExactly(socket.getInputStream(),1)[0].toInt() and 0xff
   else -> fail("unknown reply address type ${head[3]}") as Int
  }
  val body=readExactly(socket.getInputStream(),addressLength+2)
  return head+body
 }

 @Test fun liveUdpAssociationsDoNotStarveNewTcpConnections() {
  EchoServer().use { origin ->
   SocksInspectionBridge(12345,dnsQuery={ it }).use { bridge ->
    val associations=mutableListOf<Socket>()
    try {
     repeat(8) {
      val s=Socket("127.0.0.1",bridge.localPort); associations.add(s)
      socksNegotiate(s)
      val reply=socksRequest(s,CMD_UDP_ASSOCIATE,ATYP_IPV4,ipv4("0.0.0.0"),0)
      assertEquals(0,reply[1].toInt())
     }
     Socket("127.0.0.1",bridge.localPort).use { client ->
      socksNegotiate(client)
      assertEquals(0,socksRequest(client,CMD_CONNECT,ATYP_IPV4,ipv4("127.0.0.1"),origin.port)[1].toInt())
      client.getOutputStream().write("fresh TCP".toByteArray(US_ASCII))
      assertArrayEquals("fresh TCP".toByteArray(US_ASCII),readExactly(client.getInputStream(),9))
     }
    } finally { associations.forEach { it.close() } }
   }
  }
 }

 private fun domain(raw:String):ByteArray=raw.toByteArray(US_ASCII)

 private fun ipv4(raw:String):ByteArray=InetAddress.getByName(raw).address

 private fun ipv6(raw:String):ByteArray=InetAddress.getByName(raw).address

 /** Minimal TLS 1.2 ClientHello with an optional SNI extension. */
 private fun clientHello(sni:String?):ByteArray {
  val extensions=ByteArrayOutputStream()
  if(sni!=null) {
   val name=sni.toByteArray(US_ASCII)
   val entry=ByteArrayOutputStream()
   entry.write(0)
   entry.write(name.size ushr 8); entry.write(name.size and 0xff)
   entry.write(name)
   val list=entry.toByteArray()
   extensions.write(0); extensions.write(0)
   extensions.write(((list.size+2) ushr 8) and 0xff)
   extensions.write((list.size+2) and 0xff)
   extensions.write(list.size ushr 8); extensions.write(list.size and 0xff)
   extensions.write(list)
  }
  val body=ByteArrayOutputStream()
  body.write(3); body.write(3)
  body.write(ByteArray(32))
  body.write(0)
  body.write(0); body.write(2); body.write(0x13); body.write(0x01)
  body.write(1); body.write(0)
  if(extensions.size()>0) {
   val ext=extensions.toByteArray()
   body.write(ext.size ushr 8); body.write(ext.size and 0xff)
   body.write(ext)
  }
  val bodyBytes=body.toByteArray()
  val record=ByteArrayOutputStream()
  record.write(0x16)
  record.write(0x03)
  record.write(0x01)
  record.write(((bodyBytes.size+4) ushr 8) and 0xff)
  record.write((bodyBytes.size+4) and 0xff)
  record.write(1)
  record.write((bodyBytes.size ushr 16) and 0xff)
  record.write((bodyBytes.size ushr 8) and 0xff)
  record.write(bodyBytes.size and 0xff)
  record.write(bodyBytes)
  return record.toByteArray()
 }

 private fun connectTcp(bridge:SocksInspectionBridge,addressType:Int,address:ByteArray,port:Int):Socket {
  val socket=Socket("127.0.0.1",bridge.localPort)
  try {
   socksNegotiate(socket)
   val reply=socksRequest(socket,CMD_CONNECT,addressType,address,port)
   assertEquals("SOCKS CONNECT must succeed",0,reply[1].toInt())
   return socket
  } catch(e:Exception) { socket.close(); throw e }
 }

 @Test fun tlsIsRoutedThroughInspectionProxyUsingSniOnAnyPort() {
  val hello=clientHello("origin.test")
  FakeInspectionProxy(hello.size).use { proxy ->
   val direct=AtomicInteger()
   SocksInspectionBridge(proxy.port,{_,_-> direct.incrementAndGet(); throw IOException("direct forbidden")}).use { bridge ->
    assertTrue(bridge.boundAddress.isLoopbackAddress)
    connectTcp(bridge,ATYP_DOMAIN,domain("192.0.2.25"),8443).use { socket ->
     val output=socket.getOutputStream()
     output.write(hello)
     output.write("APP".toByteArray(US_ASCII))
     output.flush()
     assertTrue("inspection proxy was not contacted",proxy.connected.await(5,TimeUnit.SECONDS))
     assertEquals("origin.test:8443",proxy.authority)
     assertArrayEquals("buffered ClientHello must be replayed",hello,proxy.firstBytes)
     // Fake captures the hello separately, then echoes only the application payload.
     val echoed=readExactly(socket.getInputStream(),3)
     assertArrayEquals("APP".toByteArray(US_ASCII),echoed)
    }
    assertEquals(0,direct.get())
   }
  }
 }

 @Test fun missingSniFallsBackToOriginalDestinationIp() {
  val hello=clientHello(null)
  FakeInspectionProxy(hello.size).use { proxy ->
   SocksInspectionBridge(proxy.port).use { bridge ->
    connectTcp(bridge,ATYP_IPV4,ipv4("192.0.2.7"),9443).use { socket ->
     socket.getOutputStream().write(hello)
     socket.getOutputStream().flush()
     assertTrue(proxy.connected.await(5,TimeUnit.SECONDS))
     assertEquals("192.0.2.7:9443",proxy.authority)
    }
   }
  }
 }

 @Test fun ipv6DestinationIsAcceptedAndBracketedForConnect() {
  val hello=clientHello(null)
  FakeInspectionProxy(hello.size).use { proxy ->
   SocksInspectionBridge(proxy.port).use { bridge ->
    connectTcp(bridge,ATYP_IPV6,ipv6("::1"),9444).use { socket ->
     socket.getOutputStream().write(hello)
     socket.getOutputStream().flush()
     assertTrue(proxy.connected.await(5,TimeUnit.SECONDS))
     assertEquals("[0:0:0:0:0:0:0:1]:9444",proxy.authority)
    }
   }
  }
 }

 @Test fun malformedTlsIsClosedWithoutDirectFallbackOrProxyConnect() {
  val direct=AtomicInteger()
  FakeInspectionProxy(1).use { proxy ->
   SocksInspectionBridge(proxy.port,{_,_-> direct.incrementAndGet(); throw IOException("direct forbidden")}).use { bridge ->
    connectTcp(bridge,ATYP_DOMAIN,domain("broken.test"),8443).use { socket ->
     // TLS record header with a non-ClientHello handshake payload.
     socket.getOutputStream().write(byteArrayOf(0x16,0x03,0x01,0x00,0x08,0x02,0x00,0x00,0x04,0,0,0,0))
     socket.getOutputStream().flush()
     val result=try { socket.getInputStream().read() } catch(_:IOException) { -1 }
     assertEquals(-1,result)
    }
    assertEquals(0,direct.get())
    assertFalse("failed TLS must not reach the proxy",proxy.connected.await(300,TimeUnit.MILLISECONDS))
   }
  }
 }

 @Test fun nonTlsTcpUsesDirectConnectSocket() {
  EchoServer().use { echo ->
   val seenHost=arrayOfNulls<String>(1)
   val seenPort=IntArray(1)
   SocksInspectionBridge(9,{host,port-> seenHost[0]=host; seenPort[0]=port; Socket("127.0.0.1",port)}).use { bridge ->
    connectTcp(bridge,ATYP_DOMAIN,domain("direct.test"),echo.port).use { socket ->
     val payload="plain-tcp".toByteArray(US_ASCII)
     socket.getOutputStream().write(payload)
     socket.getOutputStream().flush()
     assertArrayEquals(payload,readExactly(socket.getInputStream(),payload.size))
    }
    assertEquals("direct.test",seenHost[0])
    assertEquals(echo.port,seenPort[0])
   }
  }
 }

 @Test fun udpAssociateHandlesDnsOnlyAndDropsNonDns() {
  val query="dns-query".toByteArray(US_ASCII)
  val answer="dns-answer".toByteArray(US_ASCII)
  val queried=AtomicInteger()
  SocksInspectionBridge(9,dnsQuery={bytes-> queried.incrementAndGet(); if(bytes.contentEquals(query)) answer else null}).use { bridge ->
   Socket("127.0.0.1",bridge.localPort).use { control ->
    socksNegotiate(control)
    val reply=socksRequest(control,CMD_UDP_ASSOCIATE,ATYP_IPV4,ipv4("0.0.0.0"),0)
    assertEquals(0,reply[1].toInt())
    val relayAddress=InetAddress.getByAddress(reply.copyOfRange(4,8))
    val relayPort=((reply[8].toInt() and 0xff) shl 8) or (reply[9].toInt() and 0xff)
    DatagramSocket().use { udp ->
     udp.soTimeout=1_500
     val header=byteArrayOf(0,0,0,ATYP_IPV4.toByte())+ipv4("8.8.8.8")+byteArrayOf(0,53)
     val packet=header+query
     udp.send(DatagramPacket(packet,packet.size,relayAddress,relayPort))
     val response=DatagramPacket(ByteArray(4096),4096)
     udp.receive(response)
     assertArrayEquals(header+answer,response.data.copyOf(response.length))

     val nonDnsHeader=byteArrayOf(0,0,0,ATYP_IPV4.toByte())+ipv4("8.8.8.8")+byteArrayOf(1,0xbb.toByte())
     val quic=nonDnsHeader+"quic".toByteArray(US_ASCII)
     udp.send(DatagramPacket(quic,quic.size,relayAddress,relayPort))
     val dropped=try { udp.receive(response); true } catch(_:SocketTimeoutException) { false }
     assertFalse("non-DNS UDP must be dropped",dropped)
    }
    assertEquals(1,queried.get())
   }
  }
 }

 @Test fun closeClosesActiveSocksTunnels() {
  EchoServer().use { echo ->
   val bridge=SocksInspectionBridge(9,{host,port-> Socket(host,port)})
   val socket=connectTcp(bridge,ATYP_DOMAIN,domain("direct.test"),echo.port)
   socket.soTimeout=5_000
   bridge.close()
   val closed=try { socket.getInputStream().read() } catch(_:IOException) { -1 }
   assertEquals(-1,closed)
   socket.close()
   bridge.close()
   try {
    Socket("127.0.0.1",bridge.localPort).close()
    fail("listener must be closed")
   } catch(_:IOException) {}
  }
 }
}
