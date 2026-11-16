package org.curtain.dns.inspection

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket

class InspectionProxyTest {
 private class Origin(val server:MockWebServer,val ca:HeldCertificate)

 private fun newOrigin():Origin {
  val ca=HeldCertificate.Builder()
   .commonName("Curtain Test Origin CA")
   .duration(365,TimeUnit.DAYS)
   .certificateAuthority(0)
   .build()
  val leaf=HeldCertificate.Builder()
   .commonName("127.0.0.1")
   .addSubjectAlternativeName("127.0.0.1")
   .addSubjectAlternativeName("localhost")
   .duration(30,TimeUnit.DAYS)
   .signedBy(ca)
   .build()
  val certificates=HandshakeCertificates.Builder().heldCertificate(leaf,ca.certificate).build()
  val server=MockWebServer()
  server.useHttps(certificates.sslSocketFactory(),false)
  server.start(InetAddress.getByName("127.0.0.1"),0)
  return Origin(server,ca)
 }

 private fun withTempDirectory(body:(File)->Unit) {
  val directory=Files.createTempDirectory("curtain-inspection-proxy").toFile()
  try { body(directory) } finally { directory.walkBottomUp().forEach { it.delete() } }
 }

 private fun upstreamTrusting(ca:HeldCertificate):OkHttpClient {
  val trust=HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate).build()
  return OkHttpClient.Builder()
   .sslSocketFactory(trust.sslSocketFactory(),trust.trustManager)
   .readTimeout(10,TimeUnit.SECONDS)
   .build()
 }

 private fun proxyClient(ca:LocalCertificateAuthority,proxy:InspectionProxy):OkHttpClient {
  val trust=HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate()).build()
  return OkHttpClient.Builder()
   .proxy(Proxy(Proxy.Type.HTTP,InetSocketAddress("127.0.0.1",proxy.localPort)))
   .sslSocketFactory(trust.sslSocketFactory(),trust.trustManager)
   .readTimeout(10,TimeUnit.SECONDS)
   .build()
 }

 private fun originUrl(origin:Origin,path:String):String = "https://127.0.0.1:${origin.server.port}$path"

 private fun rawTunnelStatus(
  ca:LocalCertificateAuthority,
  proxy:InspectionProxy,
  originPort:Int,
  request:String
 ):String {
  Socket("127.0.0.1",proxy.localPort).use { raw ->
   raw.soTimeout=5_000
   val authority="127.0.0.1:$originPort"
   raw.getOutputStream().write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray(US_ASCII))
   raw.getOutputStream().flush()
   val connectReader=BufferedReader(InputStreamReader(raw.getInputStream(),US_ASCII))
   assertEquals("HTTP/1.1 200 Connection Established",connectReader.readLine())
   while(true) { val line=connectReader.readLine(); if(line.isNullOrEmpty()) break }

   val trust=HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate()).build()
   val tls=trust.sslSocketFactory().createSocket(raw,"127.0.0.1",originPort,true) as SSLSocket
   tls.use {
    tls.soTimeout=5_000
    tls.startHandshake()
    tls.outputStream.write(request.toByteArray(US_ASCII))
    tls.outputStream.flush()
    return BufferedReader(InputStreamReader(tls.inputStream,US_ASCII)).readLine() ?: ""
   }
  }
 }

 @Test fun allowedRequestIsForwardedThroughRealTls() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   val payload="origin-\u2713".toByteArray(Charsets.UTF_8)
   origin.server.enqueue(MockResponse().setResponseCode(200).setHeader("Content-Type","text/plain; charset=utf-8").setBody(Buffer().write(payload)))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca)).use { proxy ->
    assertTrue(proxy.boundAddress.isLoopbackAddress)
    val client=proxyClient(ca,proxy)
    client.newCall(Request.Builder().url(originUrl(origin,"/allowed?x=1")).build()).execute().use { response ->
     assertEquals(200,response.code)
     assertArrayEquals(payload,response.body!!.bytes())
     assertEquals("keep-alive",response.header("Connection"))
     assertEquals(null,response.header("Transfer-Encoding"))
     assertEquals(payload.size.toString(),response.header("Content-Length"))
    }
   }
   assertEquals(1,origin.server.requestCount)
   val recorded=origin.server.takeRequest()
   assertEquals("/allowed?x=1",recorded.path)
   assertEquals("GET",recorded.method)
  } finally { origin.server.shutdown() }
 }

 @Test fun headIsForwardedWithoutAResponseBody() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setResponseCode(200).setBody("not-for-head"))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca)).use { proxy ->
    proxyClient(ca,proxy).newCall(Request.Builder().url(originUrl(origin,"/head")).head().build()).execute().use { response ->
     assertEquals(200,response.code)
     assertEquals(0,response.body!!.bytes().size)
    }
   }
   assertEquals(1,origin.server.requestCount)
   assertEquals("HEAD",origin.server.takeRequest().method)
  } finally { origin.server.shutdown() }
 }

 @Test fun blockAndReplaceStayLocalAndLogFullUrlAndAction() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setBody("origin-secret"))
   val replacement="local-\u2713\n".toByteArray(Charsets.UTF_8)
   val rules=HostPathRules(
    InspectionRule("127.0.0.1","/private",InspectionAction.BLOCK),
    InspectionRule("127.0.0.1","/replace",InspectionAction.REPLACE,replacement)
   )
   val log=InspectionLog(10).apply { setEnabled(true) }
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,rules,log,upstreamTrusting(origin.ca)).use { proxy ->
    val client=proxyClient(ca,proxy)
    client.newCall(Request.Builder().url(originUrl(origin,"/private/data?secret=1")).build()).execute().use { response ->
     assertEquals(403,response.code)
     assertArrayEquals("Blocked by Curtain inspection\n".toByteArray(Charsets.UTF_8),response.body!!.bytes())
    }
    client.newCall(Request.Builder().url(originUrl(origin,"/replace/deep?x=1")).build()).execute().use { response ->
     assertEquals(200,response.code)
     assertArrayEquals(replacement,response.body!!.bytes())
     assertTrue(response.header("Content-Type")!!.startsWith("text/plain"))
    }
    val entries=log.recent(10)
    assertEquals(2,entries.size)
    val block=entries.first { it.action==InspectionAction.BLOCK }
    assertEquals("https://127.0.0.1:${origin.server.port}/private/data?secret=1",block.url)
    assertEquals(403,block.status)
    val replace=entries.first { it.action==InspectionAction.REPLACE }
    assertEquals("https://127.0.0.1:${origin.server.port}/replace/deep?x=1",replace.url)
    assertEquals(200,replace.status)
    log.setEnabled(false)
    assertEquals(0,log.recent(10).size)
   }
   assertEquals(0,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun unsupportedMethodIsExplicit405AndNeverForwarded() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setBody("origin-secret"))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca)).use { proxy ->
    val request=Request.Builder().url(originUrl(origin,"/trace")).method("TRACE",null).build()
    proxyClient(ca,proxy).newCall(request).execute().use { response ->
     assertEquals(405,response.code)
     assertTrue(response.header("Allow")!!.contains("GET"))
     assertTrue(response.header("Allow")!!.contains("HEAD"))
    }
   }
   assertEquals(0,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun tunnelRejectsHostMismatchSmugglingAndGetBodiesBeforeOrigin() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setBody("origin-secret"))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca)).use { proxy ->
    val port=origin.server.port
    val badHost="GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n"
    val duplicateLength="GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    val transferEncoding="GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
    val bodyOnGet="GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nContent-Length: 1\r\nConnection: close\r\n\r\nA"
    assertEquals("HTTP/1.1 400 Bad Request",rawTunnelStatus(ca,proxy,port,badHost))
    assertEquals("HTTP/1.1 400 Bad Request",rawTunnelStatus(ca,proxy,port,duplicateLength))
    assertEquals("HTTP/1.1 400 Bad Request",rawTunnelStatus(ca,proxy,port,transferEncoding))
    assertEquals("HTTP/1.1 400 Bad Request",rawTunnelStatus(ca,proxy,port,bodyOnGet))
   }
   assertEquals(0,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun untrustedOriginIs502WithoutAnyBypass() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setBody("origin-secret"))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog()).use { proxy ->
    proxyClient(ca,proxy).newCall(Request.Builder().url(originUrl(origin,"/untrusted")).build()).execute().use { response ->
     assertEquals(502,response.code)
     assertNotEquals("origin-secret",response.body!!.string())
    }
   }
   assertEquals(0,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun clientWithoutInspectionTrustFailsHandshake() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setBody("origin-secret"))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca)).use { proxy ->
    val untrusting=OkHttpClient.Builder()
     .proxy(Proxy(Proxy.Type.HTTP,InetSocketAddress("127.0.0.1",proxy.localPort)))
     .readTimeout(10,TimeUnit.SECONDS)
     .build()
    try {
     untrusting.newCall(Request.Builder().url(originUrl(origin,"/client-trust")).build()).execute().use {
      fail("Client without inspection CA trust must not succeed")
     }
    } catch(_:IOException) {}
   }
   assertEquals(0,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun upstreamClientProxyConfigurationIsNotInherited() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setBody("origin-ok"))
   val trust=HandshakeCertificates.Builder().addTrustedCertificate(origin.ca.certificate).build()
   val configuredUpstream=OkHttpClient.Builder()
    .proxy(Proxy(Proxy.Type.HTTP,InetSocketAddress("127.0.0.1",9)))
    .sslSocketFactory(trust.sslSocketFactory(),trust.trustManager)
    .build()
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),configuredUpstream).use { proxy ->
    proxyClient(ca,proxy).newCall(Request.Builder().url(originUrl(origin,"/no-inherited-proxy")).build()).execute().use { response ->
     assertEquals(200,response.code)
     assertEquals("origin-ok",response.body!!.string())
    }
   }
   assertEquals(1,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun upstreamRedirectIsReturnedNotFollowed() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   origin.server.enqueue(MockResponse().setResponseCode(302).setHeader("Location","/next"))
   origin.server.enqueue(MockResponse().setBody("followed"))
   val ca=LocalCertificateAuthority(directory)
   InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca)).use { proxy ->
    val client=proxyClient(ca,proxy).newBuilder().followRedirects(false).followSslRedirects(false).build()
    client.newCall(Request.Builder().url(originUrl(origin,"/redirect")).build()).execute().use { response ->
     assertEquals(302,response.code)
     assertEquals("/next",response.header("Location"))
     assertNotEquals("followed",response.body!!.string())
    }
   }
   assertEquals(1,origin.server.requestCount)
  } finally { origin.server.shutdown() }
 }

 @Test fun closeIsDeterministicIdempotentAndClosesActiveTunnels() = withTempDirectory { directory ->
  val origin=newOrigin()
  try {
   val ca=LocalCertificateAuthority(directory)
   val proxy=InspectionProxy(ca,HostPathRules(),InspectionLog(),upstreamTrusting(origin.ca))
   val socket=Socket("127.0.0.1",proxy.localPort)
   socket.soTimeout=5_000
   val authority="127.0.0.1:${origin.server.port}"
   socket.getOutputStream().write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray(US_ASCII))
   socket.getOutputStream().flush()
   val reader=BufferedReader(InputStreamReader(socket.getInputStream(),US_ASCII))
   assertEquals("HTTP/1.1 200 Connection Established",reader.readLine())
   while(true) { val line=reader.readLine(); if(line.isNullOrEmpty()) break }

   proxy.close()
   val closed=try { socket.getInputStream().read() } catch(_:IOException) { -1 }
   assertEquals(-1,closed)
   socket.close()
   proxy.close()

   try {
    Socket("127.0.0.1",proxy.localPort).close()
    fail("Listener must be closed")
   } catch(_:IOException) {}
  } finally { origin.server.shutdown() }
 }
}
