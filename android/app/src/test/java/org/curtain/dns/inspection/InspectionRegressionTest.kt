package org.curtain.dns.inspection

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.nio.file.Files

/** Independent real-TLS regressions from review; no transport mocks or permissive trust. */
class InspectionRegressionTest {
 private lateinit var currentProxy:InspectionProxy
 private fun runTls(policy:InspectionPolicy=HostPathRules(), maxBody:Long=1024, test:(MockWebServer,OkHttpClient,String)->Unit) {
  val dir=Files.createTempDirectory("curtain-review-").toFile()
  val origin=MockWebServer().apply { protocols=listOf(okhttp3.Protocol.HTTP_1_1) }
  val cert=HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
  val server=HandshakeCertificates.Builder().heldCertificate(cert).build()
  origin.useHttps(server.sslSocketFactory(),false)
  origin.start()
  val upstreamTrust=HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
  val upstream=OkHttpClient.Builder().sslSocketFactory(upstreamTrust.sslSocketFactory(),upstreamTrust.trustManager).build()
  try {
   val ca=LocalCertificateAuthority(dir)
   InspectionProxy(ca,policy,InspectionLog(),upstream,maxBodyBytes=maxBody).use { proxy ->
    currentProxy=proxy
    val trust=HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate()).build()
    val client=OkHttpClient.Builder().proxy(Proxy(Proxy.Type.HTTP,InetSocketAddress("127.0.0.1",proxy.localPort)))
     .sslSocketFactory(trust.sslSocketFactory(),trust.trustManager).build()
    test(origin,client,origin.url("/").toString().removeSuffix("/"))
   }
  } finally { origin.shutdown(); upstream.connectionPool.evictAll(); dir.deleteRecursively() }
 }
 @Test fun threeRequestByteEvidence() = runTls(HostPathRules(
  InspectionRule("localhost","/blocked",InspectionAction.BLOCK),
  InspectionRule("localhost","/modified",InspectionAction.REPLACE,"Curtain replacement ✓\n".toByteArray())
 )) { origin,client,url ->
  val original="Origin allowed ✓\n".toByteArray()
  origin.enqueue(MockResponse().setBody(okio.Buffer().write(original)))
  val cases=listOf(Triple("/allowed",200,original),Triple("/blocked",403,"Blocked by Curtain inspection\n".toByteArray()),Triple("/modified",200,"Curtain replacement ✓\n".toByteArray()))
  for((path,status,expected) in cases) {
   client.newCall(Request.Builder().url(url+path).build()).execute().use { response ->
    val bytes=response.body!!.bytes()
    assertEquals(status,response.code); assertArrayEquals(expected,bytes)
    println("REAL_TLS_EVIDENCE path=$path status=${response.code} bytes=${bytes.size} hex=${bytes.joinToString("") { "%02x".format(it.toInt() and 255) }}")
   }
  }
  assertEquals(1,origin.requestCount)
  println("REAL_TLS_EVIDENCE originRequestCount=${origin.requestCount}; blocked/replaced contactedOrigin=false")
 }
 @Test fun closeCancelsBlockedUpstreamWorker() = runTls { origin,client,url ->
  val workersBefore=Thread.getAllStackTraces().keys.count { it.isAlive && it.name=="curtain-inspection-worker" }
  val release=java.util.concurrent.CountDownLatch(1)
  origin.dispatcher=object:okhttp3.mockwebserver.Dispatcher() {
   override fun dispatch(request:okhttp3.mockwebserver.RecordedRequest):MockResponse {
    release.await(10,java.util.concurrent.TimeUnit.SECONDS)
    return MockResponse().setBody("late")
   }
  }
  val call=client.newCall(Request.Builder().url("$url/wait").build())
  val request=Thread { try { call.execute().close() } catch(_:java.io.IOException) {} }
  request.start()
  try {
   assertNotNull(origin.takeRequest(5,java.util.concurrent.TimeUnit.SECONDS))
   currentProxy.close()
   assertEquals("Stop must not leave upstream relay workers blocked",workersBefore,
    Thread.getAllStackTraces().keys.count { it.isAlive && it.name=="curtain-inspection-worker" })
  } finally { release.countDown(); request.join(5000) }
 }
 @Test fun truncatedKnownLengthOriginMustFailBodyFraming() = runTls { origin,client,url ->
  origin.enqueue(MockResponse().setBody("x".repeat(256)).setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY))
  client.newCall(Request.Builder().url("$url/truncated").build()).execute().use {
   assertEquals(200,it.code)
   try { it.body!!.bytes(); fail("Truncated streaming origin must fail framing") } catch(_:java.io.IOException) {}
  }
 }
 @Test fun headReplacementMustNotWriteBodyOnWire() = runTls(HostPathRules(
  InspectionRule("localhost","/modified",InspectionAction.REPLACE,"not-for-head".toByteArray())
 )) { _,client,url ->
  val authority=java.net.URI(url).rawAuthority
  val proxyAddress=client.proxy!!.address() as InetSocketAddress
  java.net.Socket().use { raw ->
   raw.connect(proxyAddress); raw.soTimeout=5000
   raw.getOutputStream().write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n".toByteArray())
   var last4=""; while(!last4.endsWith("\r\n\r\n")) { val b=raw.getInputStream().read(); check(b>=0); last4=(last4+b.toChar()).takeLast(4) }
   val tls=client.sslSocketFactory.createSocket(raw,"localhost",java.net.URI(url).port,true) as javax.net.ssl.SSLSocket
   tls.use {
    it.startHandshake(); it.outputStream.write("HEAD /modified HTTP/1.1\r\nHost: $authority\r\nConnection: close\r\n\r\n".toByteArray()); it.outputStream.flush()
    val wire=it.inputStream.readBytes().toString(Charsets.UTF_8)
    assertEquals("HEAD response must end at headers", "",wire.substringAfter("\r\n\r\n"))
    assertTrue(wire.startsWith("HTTP/1.1 200"))
   }
  }
 }
 @Test fun chunkedOversizeMustNotReturnSilentlyTruncatedSuccess() = runTls(maxBody=64) { origin,client,url ->
  origin.enqueue(MockResponse().setChunkedBody("x".repeat(256),16))
  client.newCall(Request.Builder().url("$url/large").build()).execute().use {
   assertEquals(200,it.code)
   try { it.body!!.bytes(); fail("Oversized stream must fail, not emit a valid terminal chunk") } catch(_:java.io.IOException) {}
  }
 }
 @Test fun throwingPolicyMustNotLeakRequestToOrigin() = runTls(InspectionPolicy { _,_-> error("policy unavailable") }) { origin,client,url ->
  origin.enqueue(MockResponse().setBody("must-not-leak"))
  client.newCall(Request.Builder().url("$url/private").build()).execute().use {
   assertEquals(502,it.code)
   assertFalse(it.body!!.string().contains("must-not-leak"))
  }
  assertEquals(0,origin.requestCount)
 }
}
