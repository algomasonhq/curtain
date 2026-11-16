package org.curtain.dns.inspection

import java.io.*
import java.net.*
import java.util.Collections
import java.util.Locale
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okio.BufferedSink
import org.apache.http.HttpEntityEnclosingRequest
import org.apache.http.HttpRequestFactory
import org.apache.http.HttpVersion
import org.apache.http.RequestLine
import org.apache.http.config.MessageConstraints
import org.apache.http.entity.BasicHttpEntity
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.impl.DefaultBHttpServerConnection
import org.apache.http.impl.entity.StrictContentLengthStrategy
import org.apache.http.impl.io.DefaultHttpRequestParserFactory
import org.apache.http.message.BasicHttpEntityEnclosingRequest
import org.apache.http.message.BasicHttpResponse

/** Loopback CONNECT/TLS boundary; Apache HttpCore owns HTTP/1 framing, OkHttp owns origin HTTP/TLS.
 * Bounded concurrency, buffers, upload bytes, headers, idle time and requests per connection.
 * Streaming responses do not accumulate bodies in memory. No request/body retries.
 */
class InspectionProxy(
 private val ca:LocalCertificateAuthority,
 private val policy:InspectionPolicy=HostPathRules(emptyList()),
 private val log:InspectionLog=InspectionLog(),
 upstreamClient:OkHttpClient?=null,
 requestedPort:Int=0,
 private val maxWorkers:Int=16,
 queueCapacity:Int=32,
 private val socketTimeoutMs:Int=15_000,
 private val maxConnectHeaderBytes:Int=8*1024,
 private val maxRequestHeaderBytes:Int=16*1024,
 private val maxHeaderCount:Int=100,
 private val maxRequestTargetBytes:Int=8*1024,
 private val maxBodyBytes:Long=Long.MAX_VALUE,
 private val bindAddress:InetAddress=InetAddress.getByName("127.0.0.1"),
 private val maxUploadBytes:Long=64L*1024*1024,
 private val maxRequestsPerConnection:Int=1000
):Closeable {
 companion object {
  private val TOKEN=Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
  private val METHODS=setOf("GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS")
  private val HOP=setOf("connection","proxy-connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailer","transfer-encoding","upgrade")
  private val REQUEST_SKIP=HOP+setOf("host","content-length","expect")
  private val RESPONSE_SKIP=HOP+setOf("content-length")
 }
 init {
  require(requestedPort in 0..65535)
  require(maxWorkers in 1..64 && queueCapacity in 1..4096)
  require(socketTimeoutMs in 1000..120000)
  require(maxConnectHeaderBytes in 512..65536 && maxRequestHeaderBytes in 1024..262144)
  require(maxHeaderCount in 1..1024 && maxRequestTargetBytes in 128..65536)
  require(maxBodyBytes>0 && maxUploadBytes in 1..1024L*1024*1024 && maxRequestsPerConnection in 1..10000)
  require(bindAddress.isLoopbackAddress) { "InspectionProxy may bind loopback only" }
 }
 private val upstream=(upstreamClient?.newBuilder()?:OkHttpClient.Builder())
  .proxy(Proxy.NO_PROXY).followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
  .connectTimeout(socketTimeoutMs.toLong(),TimeUnit.MILLISECONDS).readTimeout(socketTimeoutMs.toLong(),TimeUnit.MILLISECONDS)
  .writeTimeout(socketTimeoutMs.toLong(),TimeUnit.MILLISECONDS).build()
 private val serverSocket=ServerSocket()
 private val sockets=Collections.newSetFromMap(ConcurrentHashMap<Socket,Boolean>())
 private val calls=Collections.newSetFromMap(ConcurrentHashMap<Call,Boolean>())
 private val stopped=AtomicBoolean(false)
 @Volatile private var running=true
 private val executor=ThreadPoolExecutor(maxWorkers,maxWorkers,30,TimeUnit.SECONDS,ArrayBlockingQueue<Runnable>(queueCapacity),
  ThreadFactory { Thread(it,"curtain-inspection-worker").apply { isDaemon=true } },ThreadPoolExecutor.AbortPolicy())
 val localPort:Int
 val boundAddress:InetAddress
 val port:Int get()=localPort
 val isRunning:Boolean get()=running&&!serverSocket.isClosed
 private val acceptor:Thread
 init {
  serverSocket.reuseAddress=true; serverSocket.bind(InetSocketAddress(bindAddress,requestedPort),50)
  localPort=serverSocket.localPort; boundAddress=serverSocket.inetAddress
  acceptor=Thread({ while(running) {
   val s=try { serverSocket.accept() } catch(_:IOException) { break }
   try {
    s.tcpNoDelay=true; s.soTimeout=socketTimeoutMs; sockets.add(s)
    if(!running) { sockets.remove(s); s.close(); break }
    executor.execute { handle(s) }
   } catch(_:Exception) { sockets.remove(s); quietly(s) }
  } },"curtain-inspection-accept").apply { isDaemon=true; start() }
 }
 private fun handle(socket:Socket) {
  var tls:SSLSocket?=null
  var established=false
  try {
   val lines=connectHeaders(socket.inputStream)
   val parts=lines[0].split(' ')
   if(parts.size!=3 || parts[2]!="HTTP/1.1") throw Failure(400,"Invalid CONNECT request")
   if(parts[0]!="CONNECT") throw Failure(405,"Only CONNECT is supported")
   val authority=try { InspectionUrls.parseAuthority(parts[1]) } catch(_:Exception) { throw Failure(400,"Invalid CONNECT authority") }
   val headers=lines.drop(1).map { val i=it.indexOf(':'); if(i<=0) throw Failure(400,"Invalid header"); it.substring(0,i).lowercase(Locale.ROOT) to it.substring(i+1).trim() }
   if(headers.any { it.first=="transfer-encoding" || (it.first=="content-length"&&it.second!="0") } || headers.count { it.first=="content-length" }>1) throw Failure(400,"Invalid CONNECT framing")
   socket.outputStream.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray()); socket.outputStream.flush(); established=true
   tls=ca.serverSslContext(authority.host).socketFactory.createSocket(socket,authority.host,authority.port,false) as SSLSocket
   tls.useClientMode=false; tls.soTimeout=socketTimeoutMs
   tls.sslParameters=tls.sslParameters.apply { applicationProtocols=arrayOf("http/1.1") }
   tls.startHandshake()
   session(tls,authority)
  } catch(e:Failure) {
   if(!established) runCatching { socket.outputStream.write("HTTP/1.1 ${e.code} ${reason(e.code)}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray()); socket.outputStream.flush() }
  } catch(_:Exception) {
  } finally { tls?.let { quietly(it) }; quietly(socket); sockets.remove(socket) }
 }
 private fun session(tls:SSLSocket,authority:InspectionUrls.Authority) {
  // Treat every method as entity-capable at the codec layer, then enforce method/body policy below.
  val factory=object:HttpRequestFactory {
   override fun newHttpRequest(line:RequestLine)=BasicHttpEntityEnclosingRequest(line)
   override fun newHttpRequest(method:String,uri:String)=BasicHttpEntityEnclosingRequest(method,uri)
  }
  val connection=DefaultBHttpServerConnection(8192,8192,null,null,
   MessageConstraints.custom().setMaxHeaderCount(maxHeaderCount).setMaxLineLength(maxRequestHeaderBytes).build(),
   StrictContentLengthStrategy(0),StrictContentLengthStrategy.INSTANCE,DefaultHttpRequestParserFactory(null,factory),null)
  connection.bind(tls)
  var count=0
  while(running && count++<maxRequestsPerConnection) {
   var started=false
   var head=false
   try {
    val request=connection.receiveRequestHeader() as HttpEntityEnclosingRequest
    val method=request.requestLine.method; val target=request.requestLine.uri
    head=method=="HEAD"
    fun values(name:String)=request.getHeaders(name).map { it.value }
    if(request.protocolVersion!=HttpVersion.HTTP_1_1) throw Failure(505,"HTTP/1.1 required")
    if(!TOKEN.matches(method)) throw Failure(400,"Invalid method")
    if(method !in METHODS) throw Failure(405,"Unsupported method")
    if(target.length>maxRequestTargetBytes) throw Failure(414,"Request target too long")
    if(!target.startsWith('/') || target.startsWith("//") || target.contains('#')) throw Failure(400,"Origin form required")
    val path=target.substringBefore('?')
    if(!InspectionUrls.validRequestPath(path)) throw Failure(400,"Unsafe request path")
    if(request.allHeaders.sumOf { it.name.length+it.value.length+4 }+target.length+method.length+15>maxRequestHeaderBytes) throw Failure(431,"Headers too large")
    for(h in request.allHeaders) if(!safeName(h.name)||!safeValue(h.value)) throw Failure(400,"Invalid header")
    val hosts=values("Host")
    if(hosts.size!=1) throw Failure(400,"Exactly one Host required")
    val host=try { InspectionUrls.parseAuthority(hosts.single()) } catch(_:Exception) { throw Failure(400,"Invalid Host") }
    if(host!=authority) throw Failure(400,"Host does not match CONNECT")
    val lengths=values("Content-Length"); val encodings=values("Transfer-Encoding")
    if(lengths.size>1 || encodings.size>1 || (lengths.isNotEmpty()&&encodings.isNotEmpty())) throw Failure(400,"Ambiguous framing")
    val length=if(lengths.isEmpty()) 0L else lengths.single().let { s ->
     if(s.isEmpty() || s.length>18 || s.any { it !in '0'..'9' }) throw Failure(400,"Invalid Content-Length")
     s.toLongOrNull()?:throw Failure(400,"Invalid Content-Length")
    }
    if(encodings.isNotEmpty()&&!encodings.single().equals("chunked",true)) throw Failure(400,"Unsupported transfer coding")
    val hasBody=length>0||encodings.isNotEmpty()
    if((method=="GET"||head)&&hasBody) throw Failure(400,"GET/HEAD body unsupported")
    if(length>maxUploadBytes) throw Failure(413,"Upload too large")
    val expectations=values("Expect")
    if(expectations.isNotEmpty() && (expectations.size!=1||!expectations.single().equals("100-continue",true))) throw Failure(417,"Unsupported expectation")
    if(values("Upgrade").isNotEmpty()) throw Failure(501,"WebSocket/Upgrade not supported")
    val close=values("Connection").flatMap { it.split(',') }.any { it.trim().equals("close",true) } || count==maxRequestsPerConnection
    val url="https://${InspectionUrls.urlHost(authority.host)}"+(if(authority.port!=443) ":${authority.port}" else "")+target
    val decision=try { policy.decide(authority.host,path) } catch(_:Exception) { throw Failure(502,"Policy unavailable") }
    fun local(code:Int,body:ByteArray):Boolean {
     // Never drain an untrusted upload on a locally denied/replaced request. Close instead.
     log.record(InspectionEntry(System.currentTimeMillis(),url,decision.action,code))
     started=true; sendBytes(connection,code,body,head,close||hasBody)
     return !close&&!hasBody
    }
    when(decision.action) {
     InspectionAction.BLOCK -> { if(!local(403,"Blocked by Curtain inspection\n".toByteArray())) return; continue }
     InspectionAction.REPLACE -> { if(!local(200,decision.body)) return; continue }
     else -> Unit
    }
    connection.receiveRequestEntity(request)
    if(expectations.isNotEmpty()) { connection.sendResponseHeader(BasicHttpResponse(HttpVersion.HTTP_1_1,100,"Continue")); connection.flush() }
    val body=if(method in setOf("POST","PUT","PATCH") || hasBody) object:RequestBody() {
     override fun contentType()=request.getFirstHeader("Content-Type")?.value?.toMediaTypeOrNull()
     override fun contentLength()=if(encodings.isEmpty()) length else -1L
     override fun isOneShot()=true
     override fun writeTo(sink:BufferedSink) {
      val input=request.entity.content
      val buffer=ByteArray(8192); var total=0L
      while(true) { val n=input.read(buffer); if(n<0) break; total+=n; if(total>maxUploadBytes) throw IOException("Upload limit exceeded"); sink.write(buffer,0,n) }
     }
    } else null
    val builder=Request.Builder().url(url).method(method,body)
    val nominated=(values("Connection")+values("Proxy-Connection")).flatMap { it.split(',') }.map { it.trim().lowercase(Locale.ROOT) }.toSet()
    if(nominated.any { it in setOf("host","content-length","transfer-encoding") }) throw Failure(400,"Framing header nominated by Connection")
    for(h in request.allHeaders) if(h.name.lowercase(Locale.ROOT) !in REQUEST_SKIP+nominated) builder.addHeader(h.name,h.value)
    val call=upstream.newCall(builder.build()); calls.add(call)
    if(!running) { call.cancel(); calls.remove(call); return }
    try {
     call.execute().use { response ->
      val noBody=head||response.code==204||response.code==304||response.code in 100..199
      val known=response.body?.contentLength()?:0L
      if(!noBody&&known>maxBodyBytes) throw Failure(502,"Upstream response too large")
      val reply=BasicHttpResponse(HttpVersion.HTTP_1_1,response.code,reason(response.code))
      val responseNominated=(response.headers.values("Connection")+response.headers.values("Proxy-Connection")).flatMap { it.split(',') }.map { it.trim().lowercase(Locale.ROOT) }.toSet()
      for((name,value) in response.headers) if(name.lowercase(Locale.ROOT) !in RESPONSE_SKIP+responseNominated && safeName(name)&&safeValue(value)) reply.addHeader(name,value)
      reply.setHeader("Connection",if(close) "close" else "keep-alive")
      if(head) response.header("Content-Length")?.let { if(it.toLongOrNull()!=null) reply.setHeader("Content-Length",it) }
      if(!noBody) {
       if(known>=0) reply.setHeader("Content-Length",known.toString()) else reply.setHeader("Transfer-Encoding","chunked")
       val input=response.body?.byteStream()?:ByteArrayInputStream(ByteArray(0))
       reply.entity=object:BasicHttpEntity() {
        override fun writeTo(out:OutputStream) {
         val buffer=ByteArray(8192); var total=0L
         while(true) {
          val n=input.read(buffer); if(n<0) break
          total+=n; if(total>maxBodyBytes) throw IOException("Response limit exceeded")
          out.write(buffer,0,n); out.flush()
         }
         if(known>=0 && total!=known) throw IOException("Truncated origin")
        }
       }.apply { contentLength=known; isChunked=known<0 }
      }
      log.record(InspectionEntry(System.currentTimeMillis(),url,InspectionAction.ALLOW,response.code))
      started=true; connection.sendResponseHeader(reply); connection.flush()
      if(!noBody) connection.sendResponseEntity(reply)
      connection.flush()
     }
    } finally { calls.remove(call) }
    if(close) return
   } catch(_:org.apache.http.ConnectionClosedException) { return
   } catch(_:SocketTimeoutException) { return
   } catch(e:Exception) {
    // Once streaming headers have gone out, abort WITHOUT a terminal chunk or another status.
    // Clients must observe framing failure, never silently accept a truncated success.
    if(!started) runCatching { val code=if(e is Failure) e.code else if(e is org.apache.http.HttpException) 400 else 502; sendBytes(connection,code,((e as? Failure)?.message?:"Bad Gateway").plus("\n").toByteArray(),head,true) }
    return
   }
  }
 }
 private fun sendBytes(c:DefaultBHttpServerConnection,code:Int,bytes:ByteArray,head:Boolean,close:Boolean) {
  val response=BasicHttpResponse(HttpVersion.HTTP_1_1,code,reason(code))
  response.setHeader("Content-Type","text/plain; charset=utf-8"); response.setHeader("Content-Length",bytes.size.toString())
  response.setHeader("Connection",if(close) "close" else "keep-alive")
  if(code==405) response.setHeader("Allow",METHODS.joinToString(", "))
  response.entity=ByteArrayEntity(bytes)
  c.sendResponseHeader(response); if(!head) c.sendResponseEntity(response); c.flush()
 }
 /** CONNECT preface only. Does not consume a single byte of the following TLS ClientHello. */
 private fun connectHeaders(input:InputStream):List<String> {
  val lines=ArrayList<String>(); var total=0
  while(true) {
   val line=ByteArrayOutputStream()
   while(true) {
    val b=input.read(); if(b<0) throw Failure(400,"Truncated CONNECT")
    if(++total>maxConnectHeaderBytes) throw Failure(431,"CONNECT headers too large")
    if(b==13) { if(input.read()!=10) throw Failure(400,"Invalid CONNECT line"); total++; break }
    if(b==10 || b<32&&b!=9 || b==127) throw Failure(400,"Invalid CONNECT header")
    line.write(b)
   }
   val text=line.toString("ISO-8859-1")
   if(text.isEmpty()) { if(lines.isEmpty()) throw Failure(400,"Empty CONNECT"); return lines }
   if(lines.size>32||text.startsWith(' ')||text.startsWith('\t')) throw Failure(400,"Invalid CONNECT headers")
   lines.add(text)
  }
 }
 private fun safeName(s:String)=s.length in 1..256&&TOKEN.matches(s)
 private fun safeValue(s:String)=s.length<=maxRequestHeaderBytes&&s.none { it=='\r'||it=='\n'||it=='\u0000'||it=='\u007f'||it.code<32&&it!='\t' }
 private class Failure(val code:Int,message:String):IOException(message)
 private fun reason(code:Int)=when(code) { 200->"OK"; 204->"No Content"; 304->"Not Modified"; 400->"Bad Request"; 403->"Forbidden"; 405->"Method Not Allowed"; 413->"Content Too Large"; 414->"URI Too Long"; 417->"Expectation Failed"; 431->"Request Header Fields Too Large"; 501->"Not Implemented"; 502->"Bad Gateway"; 505->"HTTP Version Not Supported"; else->"Response" }
 private fun quietly(c:Closeable) { try { c.close() } catch(_:Exception) {} }
 override fun close() {
  if(!stopped.compareAndSet(false,true)) return
  running=false; quietly(serverSocket)
  for(call in calls) call.cancel()
  for(socket in sockets) quietly(socket)
  executor.shutdownNow()
  for(call in calls) call.cancel()
  for(socket in sockets) quietly(socket)
  try { acceptor.join(2000); executor.awaitTermination(2,TimeUnit.SECONDS) } catch(_:InterruptedException) { Thread.currentThread().interrupt() }
  sockets.clear()
 }
}
