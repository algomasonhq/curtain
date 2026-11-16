package org.curtain.dns.inspection

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.nio.charset.StandardCharsets.US_ASCII
import java.util.Collections
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Loopback SOCKS5 front end for [InspectionProxy]. TLS flows are always sent through the
 * loopback inspection proxy after the first complete ClientHello record is parsed for SNI.
 * Non-TLS TCP is connected directly with [connectSocket]. A TLS-looking flow that cannot be
 * parsed is closed and is never passed through directly.
 *
 * UDP ASSOCIATE serves DNS only and requires [dnsQuery]; every non-DNS datagram is dropped.
 */
class SocksInspectionBridge(
 private val inspectionPort:Int,
 private val connectSocket:(String,Int)->Socket={host,port->Socket().apply { connect(InetSocketAddress(host,port)) }},
 private val dnsQuery:((ByteArray)->ByteArray?)?=null
) : Closeable {
 private companion object {
  const val SOCKS_VERSION=5
  const val CMD_CONNECT=1
  const val CMD_UDP_ASSOCIATE=3
  const val ATYP_IPV4=1
  const val ATYP_DOMAIN=3
  const val ATYP_IPV6=4
  const val REP_SUCCEEDED=0
  const val REP_GENERAL_FAILURE=1
  const val REP_COMMAND_NOT_SUPPORTED=7
  const val REP_ADDRESS_TYPE_NOT_SUPPORTED=8
  const val DNS_PORT=53
  // Match the native engine's 64-session bound. UDP associations and persistent TCP each
  // hold a worker for their lifetime; an eight-worker queue lets DNS/QUIC starve new TCP.
  const val MAX_WORKERS=64
  const val SOCKET_TIMEOUT_MS=15_000
  const val CONTROL_POLL_MS=500
  const val MAX_PROXY_RESPONSE_BYTES=8*1024
  const val MAX_TLS_RECORD_BYTES=TlsClientHello.MAX_RECORD_BYTES

  val LOOPBACK:InetAddress=InetAddress.getByName("127.0.0.1")
  val UNSPECIFIED:InetAddress=InetAddress.getByName("0.0.0.0")
  val HTTP_HEADER_END="\r\n\r\n".toByteArray(US_ASCII)
 }

 init {
  require(inspectionPort in 1..65535) { "inspectionPort out of range" }
 }

 private val serverSocket=ServerSocket()
 private val resources=Collections.newSetFromMap(ConcurrentHashMap<Closeable,Boolean>())
 private val stopped=AtomicBoolean(false)
 @Volatile private var running=true
 private val executor=ThreadPoolExecutor(
  0,MAX_WORKERS,30L,TimeUnit.SECONDS,
  SynchronousQueue<Runnable>(),
  ThreadFactory { runnable -> Thread(runnable,"curtain-socks-worker").apply { isDaemon=true } },
  ThreadPoolExecutor.AbortPolicy()
 )

 val localPort:Int
 val boundAddress:InetAddress
 val port:Int get()=localPort
 val isRunning:Boolean get()=running && !serverSocket.isClosed

 private val acceptor:Thread

 init {
  serverSocket.reuseAddress=true
  serverSocket.bind(InetSocketAddress(LOOPBACK,0),50)
  require(serverSocket.inetAddress.isLoopbackAddress) { "SocksInspectionBridge may bind loopback only" }
  localPort=serverSocket.localPort
  boundAddress=serverSocket.inetAddress
  acceptor=Thread({ acceptLoop() },"curtain-socks-accept").apply { isDaemon=true; start() }
 }

 private fun acceptLoop() {
  while(running) {
   val socket=try { serverSocket.accept() } catch(_:SocketException) { break } catch(_:IOException) { if(running) continue else break }
   if(!running) { closeQuietly(socket); break }
   try {
    socket.tcpNoDelay=true
    socket.soTimeout=SOCKET_TIMEOUT_MS
    resources.add(socket)
    if(!running) { resources.remove(socket); closeQuietly(socket); break }
    executor.execute { handle(socket) }
   } catch(_:RejectedExecutionException) {
    resources.remove(socket); closeQuietly(socket)
   } catch(_:IOException) {
    resources.remove(socket); closeQuietly(socket)
   }
  }
 }

 private fun handle(client:Socket) {
  try {
   client.tcpNoDelay=true
   client.soTimeout=SOCKET_TIMEOUT_MS
   val input=PushbackInputStream(BufferedInputStream(client.getInputStream(),8*1024),MAX_TLS_RECORD_BYTES)
   val output=client.getOutputStream()

   if(!negotiate(input,output)) return
   val head=readExactly(input,4)
   if((head[0].toInt() and 0xff)!=SOCKS_VERSION || (head[2].toInt() and 0xff)!=0) return
   val command=head[1].toInt() and 0xff
   val destination=try { readDestination(input,head[3].toInt() and 0xff) } catch(_:IllegalArgumentException) {
    writeReply(output,REP_ADDRESS_TYPE_NOT_SUPPORTED,UNSPECIFIED,0)
    return
   }

   when(command) {
    CMD_CONNECT -> handleConnect(client,input,output,destination)
    CMD_UDP_ASSOCIATE -> associateUdp(client,input,output)
    else -> writeReply(output,REP_COMMAND_NOT_SUPPORTED,UNSPECIFIED,0)
   }
  } catch(_:SocketTimeoutException) {
  } catch(e:Exception) {
   System.err.println("socks-handle: $e")
  } finally {
   closeQuietly(client)
   resources.remove(client)
  }
 }

 private fun negotiate(input:InputStream,output:OutputStream):Boolean {
  val version=input.read()
  if(version!=SOCKS_VERSION) return false
  val methodCount=input.read()
  if(methodCount<=0) return false
  val methods=ByteArray(methodCount)
  readFully(input,methods,0,methods.size)
  if(methods.none { it.toInt()==0 }) {
   output.write(byteArrayOf(SOCKS_VERSION.toByte(),0xff.toByte()))
   output.flush()
   return false
  }
  output.write(byteArrayOf(SOCKS_VERSION.toByte(),0))
  output.flush()
  return true
 }

 private fun readDestination(input:InputStream,addressType:Int):Destination {
  val host=when(addressType) {
   ATYP_IPV4 -> InetAddress.getByAddress(readExactly(input,4)).hostAddress
   ATYP_IPV6 -> InetAddress.getByAddress(readExactly(input,16)).hostAddress
   ATYP_DOMAIN -> {
    val length=input.read()
    require(length in 1..255) { "invalid domain length" }
    val bytes=readExactly(input,length)
    require(bytes.all { (it.toInt() and 0xff) in 0x21..0x7e }) { "non-ASCII domain" }
    String(bytes,US_ASCII)
   }
   else -> throw IllegalArgumentException("unsupported address type")
  }
  val port=(readByte(input) shl 8) or readByte(input)
  return Destination(InspectionUrls.canonicalHost(host),port)
 }

 private fun handleConnect(client:Socket,input:PushbackInputStream,output:OutputStream,destination:Destination) {
  if(destination.port==0) {
   writeReply(output,REP_GENERAL_FAILURE,UNSPECIFIED,0)
   return
  }
  // SOCKS requires a reply before the tunnel payload, so success is sent before sniffing.
  writeReply(output,REP_SUCCEEDED,UNSPECIFIED,0)
  val sniff=sniff(input,destination) ?: return
  when(sniff) {
   is Sniff.Direct -> {
    val upstream=connectSocket(destination.host,destination.port)
    resources.add(upstream)
    try {
     upstream.tcpNoDelay=true
     relay(client,input,output,upstream)
    } finally {
     resources.remove(upstream); closeQuietly(upstream)
    }
   }
   is Sniff.Tls -> {
    val upstream=openInspection(sniff.host,destination.port)
    try {
     val proxyOutput=upstream.getOutputStream()
     proxyOutput.write(sniff.record)
     proxyOutput.flush()
     relay(client,input,output,upstream)
    } finally {
     resources.remove(upstream); closeQuietly(upstream)
    }
   }
  }
 }

 private fun sniff(input:PushbackInputStream,destination:Destination):Sniff? {
  val first=input.read()
  if(first<0) return null
  if(first!=TlsClientHello.CONTENT_TYPE_HANDSHAKE) {
   input.unread(first)
   return Sniff.Direct
  }
  val tail=readExactly(input,4)
  val header=byteArrayOf(first.toByte(),tail[0],tail[1],tail[2],tail[3])
  if((header[1].toInt() and 0xff)!=3) throw IOException("unsupported TLS record version")
  val length=((header[3].toInt() and 0xff) shl 8) or (header[4].toInt() and 0xff)
  if(length<=0 || length>MAX_TLS_RECORD_BYTES-5) throw IOException("TLS record out of bounds")
  val record=ByteArray(5+length)
  System.arraycopy(header,0,record,0,5)
  readFully(input,record,5,length)
  val sni=try { TlsClientHello.serverName(record) } catch(e:IllegalArgumentException) {
   throw IOException("malformed TLS ClientHello",e)
  }
  val host=if(sni==null) destination.host else try { InspectionUrls.canonicalHost(sni) } catch(e:IllegalArgumentException) {
   throw IOException("invalid TLS SNI",e)
  }
  return Sniff.Tls(record,host)
 }

 private fun openInspection(host:String,port:Int):Socket {
  val socket=Socket()
  resources.add(socket)
  try {
   socket.tcpNoDelay=true
   socket.soTimeout=SOCKET_TIMEOUT_MS
   socket.connect(InetSocketAddress(LOOPBACK,inspectionPort),SOCKET_TIMEOUT_MS)
   val authority=connectAuthority(host,port)
   val output=socket.getOutputStream()
   output.write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray(US_ASCII))
   output.flush()
   if(!readProxySuccess(BufferedInputStream(socket.getInputStream(),4*1024))) throw IOException("inspection CONNECT failed")
   return socket
  } catch(e:Exception) {
   resources.remove(socket); closeQuietly(socket); throw e
  }
 }

 private fun connectAuthority(host:String,port:Int):String="${InspectionUrls.urlHost(host)}:$port"

 private fun readProxySuccess(input:InputStream):Boolean {
  val header=ByteArrayOutputStream()
  var matched=0
  while(matched<HTTP_HEADER_END.size) {
   val value=input.read()
   if(value<0) return false
   header.write(value)
   if(header.size()>MAX_PROXY_RESPONSE_BYTES) return false
   matched=if(value==HTTP_HEADER_END[matched].toInt()) matched+1 else if(value=='\r'.code) 1 else 0
  }
  val firstLine=header.toString(US_ASCII.name()).substringBefore("\r\n")
  val parts=firstLine.split(' ')
  return parts.size>=2 && parts[0]=="HTTP/1.1" && parts[1]=="200"
 }

 private fun relay(client:Socket,input:InputStream,output:OutputStream,upstream:Socket) {
  client.soTimeout=0
  upstream.soTimeout=0
  val upload=Thread({
   try { pump(input,upstream.getOutputStream()) } catch(e:Exception) {
    System.err.println("socks-upload: $e")
   } finally {
    closeQuietly(upstream); closeQuietly(client)
   }
  },"curtain-socks-relay").apply { isDaemon=true; start() }
  try { pump(upstream.getInputStream(),output) } catch(e:Exception) {
   System.err.println("socks-download: $e")
  } finally {
   closeQuietly(upstream); closeQuietly(client)
  }
  try { upload.join(1_000) } catch(_:InterruptedException) { Thread.currentThread().interrupt() }
 }

 private fun pump(input:InputStream,output:OutputStream) {
  val buffer=ByteArray(16*1024)
  while(true) {
   val read=input.read(buffer)
   if(read<0) break
   output.write(buffer,0,read)
   output.flush()
  }
 }

 private fun associateUdp(client:Socket,input:InputStream,output:OutputStream) {
  val relay=DatagramSocket(InetSocketAddress(LOOPBACK,0))
  resources.add(relay)
  var worker:Thread?=null
  try {
   relay.soTimeout=CONTROL_POLL_MS
   writeReply(output,REP_SUCCEEDED,relay.localAddress,relay.localPort)
   worker=Thread({ dnsLoop(relay) },"curtain-socks-udp").apply { isDaemon=true; start() }
   client.soTimeout=CONTROL_POLL_MS
   while(running) {
    val value=try { input.read() } catch(_:SocketTimeoutException) { continue } catch(_:IOException) { break }
    if(value<0) break
   }
  } finally {
   closeQuietly(relay)
   try { worker?.join(1_000) } catch(_:InterruptedException) { Thread.currentThread().interrupt() }
   resources.remove(relay)
  }
 }

 private fun dnsLoop(relay:DatagramSocket) {
  val buffer=ByteArray(64*1024)
  var client:InetSocketAddress?=null
  while(running && !relay.isClosed) {
   val datagram=DatagramPacket(buffer,buffer.size)
   try { relay.receive(datagram) } catch(_:SocketTimeoutException) { continue } catch(_:IOException) { break }
   val from=datagram.socketAddress as? InetSocketAddress ?: continue
   if(!from.address.isLoopbackAddress) continue
   if(client==null) client=from else if(client!=from) continue
   val response=handleDnsDatagram(datagram.data,datagram.offset,datagram.length) ?: continue
   try { relay.send(DatagramPacket(response,response.size,from)) } catch(_:IOException) { break }
  }
 }

 private fun handleDnsDatagram(data:ByteArray,offset:Int,length:Int):ByteArray? {
  val end=offset+length
  if(length<4+4+2) return null
  if(data[offset].toInt()!=0 || data[offset+1].toInt()!=0) return null
  if(data[offset+2].toInt()!=0) return null // fragmented UDP is never forwarded
  var position=offset+3
  val addressType=data[position++].toInt() and 0xff
  position+=when(addressType) {
   ATYP_IPV4 -> 4
   ATYP_IPV6 -> 16
   ATYP_DOMAIN -> {
    if(position>=end) return null
    val nameLength=data[position].toInt() and 0xff
    if(nameLength==0) return null
    1+nameLength
   }
   else -> return null
  }
  if(position+2>end) return null
  val port=((data[position].toInt() and 0xff) shl 8) or (data[position+1].toInt() and 0xff)
  position+=2
  if(port!=DNS_PORT) return null
  if(position>end) return null
  val query=data.copyOfRange(position,end)
  val answer=dnsQuery?.invoke(query) ?: return null
  return data.copyOfRange(offset,position)+answer
 }

 private fun writeReply(output:OutputStream,reply:Int,address:InetAddress,port:Int) {
  val encoded=when(address) {
   is Inet4Address -> byteArrayOf(ATYP_IPV4.toByte())+address.address
   is Inet6Address -> byteArrayOf(ATYP_IPV6.toByte())+address.address
   else -> byteArrayOf(ATYP_IPV4.toByte(),0,0,0,0)
  }
  val header=ByteArrayOutputStream()
  header.write(SOCKS_VERSION); header.write(reply); header.write(0)
  header.write(encoded)
  header.write((port ushr 8) and 0xff); header.write(port and 0xff)
  output.write(header.toByteArray())
  output.flush()
 }

 private fun readByte(input:InputStream):Int {
  val value=input.read()
  if(value<0) throw IOException("unexpected EOF")
  return value
 }

 private fun readExactly(input:InputStream,count:Int):ByteArray {
  val bytes=ByteArray(count)
  readFully(input,bytes,0,count)
  return bytes
 }

 private fun readFully(input:InputStream,bytes:ByteArray,offset:Int,count:Int) {
  var position=offset
  val end=offset+count
  while(position<end) {
   val read=input.read(bytes,position,end-position)
   if(read<0) throw IOException("unexpected EOF")
   position+=read
  }
 }

 override fun close() {
  if(!stopped.compareAndSet(false,true)) return
  running=false
  closeQuietly(serverSocket)
  for(resource in resources) closeQuietly(resource)
  executor.shutdownNow()
  for(resource in resources) closeQuietly(resource)
  try { acceptor.join(2_000) } catch(_:InterruptedException) { Thread.currentThread().interrupt() }
  try { executor.awaitTermination(2,TimeUnit.SECONDS) } catch(_:InterruptedException) { Thread.currentThread().interrupt() }
  resources.clear()
 }

 private fun closeQuietly(closeable:Closeable) { try { closeable.close() } catch(_:Exception) {} }

 private data class Destination(val host:String,val port:Int)

 private sealed class Sniff {
  object Direct:Sniff()
  class Tls(val record:ByteArray,val host:String):Sniff()
 }
}
