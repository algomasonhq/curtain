package org.curtain.dns.inspection

import okhttp3.*
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/** Real TLS origin and real inspection TLS. No fake transport or production trust bypass. */
class BrowsingTest {
 private fun fixture(test:(MockWebServer,OkHttpClient,String)->Unit) {
  val dir=Files.createTempDirectory("curtain-browsing").toFile()
  val origin=MockWebServer().apply { protocols=listOf(Protocol.HTTP_1_1) }
  val cert=HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
  origin.useHttps(HandshakeCertificates.Builder().heldCertificate(cert).build().sslSocketFactory(),false)
  origin.start()
  val trust=HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
  val upstream=OkHttpClient.Builder().sslSocketFactory(trust.sslSocketFactory(),trust.trustManager).build()
  try {
   val ca=LocalCertificateAuthority(dir)
   InspectionProxy(ca,HostPathRules(InspectionRule("localhost","/blocked",InspectionAction.BLOCK),InspectionRule("localhost","/modified",InspectionAction.REPLACE,"replacement".toByteArray())),InspectionLog(),upstream).use { p ->
    val localTrust=HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate()).build()
    val client=OkHttpClient.Builder().proxy(Proxy(Proxy.Type.HTTP,InetSocketAddress("127.0.0.1",p.port)))
     .sslSocketFactory(localTrust.sslSocketFactory(),localTrust.trustManager).retryOnConnectionFailure(false).readTimeout(8,TimeUnit.SECONDS).build()
    try { test(origin,client,origin.url("/").toString().removeSuffix("/")) } finally { client.connectionPool.evictAll() }
   }
  } finally { origin.shutdown(); upstream.connectionPool.evictAll(); dir.deleteRecursively() }
 }
 @Test fun postLargeBodyEchoAndPersistentConnection() = fixture { origin,client,url ->
  origin.dispatcher=object:okhttp3.mockwebserver.Dispatcher() {
   override fun dispatch(r:RecordedRequest)=MockResponse().setBody(r.body.clone())
  }
  val payload=ByteArray(2*1024*1024+17) { (it%251).toByte() }
  val connections=java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Connection,Boolean>())
  val c=client.newBuilder().eventListener(object:EventListener() { override fun connectionAcquired(call:Call,connection:Connection) { connections.add(connection) } }).build()
  repeat(2) {
   c.newCall(Request.Builder().url("$url/echo?request=$it").post(payload.toRequestBody()).build()).execute().use { r ->
    assertEquals(200,r.code); assertArrayEquals(payload,r.body!!.bytes())
   }
  }
  assertEquals("Both downstream requests must reuse the same TLS connection",1,connections.size)
  assertEquals(2,origin.requestCount)
 }
 @Test fun chunkedUploadIsDecodedAndPostPolicyNeverReachesOrigin() = fixture { origin,client,url ->
  origin.dispatcher=object:okhttp3.mockwebserver.Dispatcher() { override fun dispatch(r:RecordedRequest)=MockResponse().setBody(r.body.clone()) }
  val body=object:RequestBody() {
   override fun contentType():MediaType?=null
   override fun writeTo(sink:okio.BufferedSink) { repeat(2048) { sink.writeUtf8("chunk-$it\n") } }
  }
  client.newCall(Request.Builder().url("$url/echo").post(body).build()).execute().use { r ->
   assertEquals(200,r.code); assertTrue(r.body!!.string().endsWith("chunk-2047\n"))
  }
  for((path,status) in listOf("/blocked" to 403,"/modified" to 200)) {
   client.newCall(Request.Builder().url(url+path).post("secret".toRequestBody()).build()).execute().use { r -> assertEquals(status,r.code) }
  }
  assertEquals(1,origin.requestCount)
 }
 @Test fun responseStreamsBeforeOriginFinishesAndLargerThanOldCap() = fixture { origin,client,url ->
  val payload="s".repeat(2*1024*1024+3)
  origin.enqueue(MockResponse().setChunkedBody(payload,8192).throttleBody(8192,15,TimeUnit.MILLISECONDS))
  val begin=System.nanoTime()
  client.newCall(Request.Builder().url("$url/stream").build()).execute().use { r ->
   assertEquals(200,r.code)
   assertEquals('s'.code,r.body!!.byteStream().read())
   assertTrue("First byte must arrive without buffering the full ~4s stream",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-begin)<2500)
   assertEquals(payload.length-1,r.body!!.byteStream().readBytes().size)
  }
 }
 @Test fun browserParallelConnectionsDoNotWaitForIdlePeers() = fixture { origin,client,url ->
  repeat(6) { origin.enqueue(MockResponse().setBody("parallel")) }
  val clients=List(6) { client.newBuilder().connectionPool(ConnectionPool()).callTimeout(5,TimeUnit.SECONDS).build() }
  try {
   for((n,c) in clients.withIndex()) c.newCall(Request.Builder().url("$url/parallel?n=$n").build()).execute().use { assertEquals("parallel",it.body!!.string()) }
  } finally { clients.forEach { it.connectionPool.evictAll() } }
 }
 @Test fun commonMethodsPreserveBodiesAndNoContentFraming() = fixture { origin,client,url ->
  origin.dispatcher=object:okhttp3.mockwebserver.Dispatcher() { override fun dispatch(r:RecordedRequest)=if(r.path=="/empty") MockResponse().setResponseCode(204) else MockResponse().setBody(r.method+":"+r.body.readUtf8()) }
  for(method in listOf("PUT","PATCH","DELETE","OPTIONS")) {
   client.newCall(Request.Builder().url("$url/method").method(method,"body".toRequestBody()).build()).execute().use { r -> assertEquals("$method:body",r.body!!.string()) }
  }
  client.newCall(Request.Builder().url("$url/empty").build()).execute().use { r -> assertEquals(204,r.code); assertEquals(0,r.body!!.bytes().size) }
  client.newCall(Request.Builder().url("$url/after").build()).execute().use { r -> assertEquals("GET:",r.body!!.string()) }
 }
}
