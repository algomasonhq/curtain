package org.curtain.dns

import android.app.Instrumentation
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.tls.HandshakeCertificates
import java.net.Proxy
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/** Private-emulator test only: trust public installation CA in this client, never weaken upstream trust.
 * No explicit proxy, bindSocket or bindProcessToNetwork: packets must traverse the default VPN TUN.
 */
class InspectionVpnSmoke(private val runner:Instrumentation, private val originPort:Int=0, private val originCertificate:String="") {
 private val context get()=runner.targetContext
 private val report=StringBuilder()
 private val service="org.curtain.dns.InspectionVpnService"
 private fun intent(action:String)=Intent().setClassName(context.packageName,service).setAction(action)
 private fun state(name:String):Any? {
  val cls=Class.forName(service)
  val companion=cls.getField("Companion").get(null)
  return companion.javaClass.getMethod("get"+name.replaceFirstChar { it.uppercaseChar() }).invoke(companion)
 }
 private fun until(label:String,seconds:Int=45,predicate:()->Boolean) {
  val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds.toLong())
  while(System.nanoTime()<deadline) { if(predicate()) return; Thread.sleep(100) }
  error("Timeout $label; service=${runCatching { state("message") }.getOrNull()}")
 }
 private fun stop(cm:ConnectivityManager) {
  context.startService(intent("org.curtain.dns.INSPECTION_VPN_STOP"))
  until("Stop processed") { state("active")==false && state("starting")==false }
  until("Stop removes real VPN and restores kernel route") {
   cm.allNetworks.none { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true } &&
    cm.activeNetwork?.let { cm.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) }==true &&
    DatagramSocket().use { s -> s.connect(InetAddress.getByName("10.111.0.2"),53); s.localAddress.hostAddress!="10.111.0.1" }
  }
  check(state("active")==false)
  report.append("Stop removed actual VPN network\n")
 }
 private fun start(cm:ConnectivityManager) {
  context.startForegroundService(intent("org.curtain.dns.INSPECTION_VPN_START"))
  until("full VPN active",90) { state("active")==true }
  until("default VPN + IPv4 default route") {
   val n=cm.activeNetwork
   cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true &&
    cm.getLinkProperties(n)?.routes?.any { it.isDefaultRoute && it.destination.address is java.net.Inet4Address }==true
  }
  // Verify the kernel route with a freshly connected unbound socket, not only advertised LP.
  until("kernel route source") {
   DatagramSocket().use { s -> s.connect(InetAddress.getByName("10.111.0.2"),53); s.localAddress.hostAddress=="10.111.0.1" }
  }
  report.append("Default VPN advertised and fresh unbound socket uses TUN source\n")
 }
 private fun client():OkHttpClient {
  val trust=HandshakeCertificates.Builder().addTrustedCertificate(InspectionCa.authority(context).certificate()).build()
  return OkHttpClient.Builder().proxy(Proxy.NO_PROXY).sslSocketFactory(trust.sslSocketFactory(),trust.trustManager)
   .protocols(listOf(okhttp3.Protocol.HTTP_1_1)).connectTimeout(30,TimeUnit.SECONDS).readTimeout(40,TimeUnit.SECONDS)
   .callTimeout(60,TimeUnit.SECONDS).retryOnConnectionFailure(false).build()
 }
 private fun request(client:OkHttpClient,path:String,code:Int,body:String?=null) {
  client.newCall(Request.Builder().url("https://example.com$path").header("Connection","close").build()).execute().use { r ->
   val bytes=r.body!!.bytes(); check(r.code==code) { "$path status=${r.code}: ${String(bytes)}" }
   if(body!=null) check(bytes.contentEquals(body.toByteArray())) { "$path wrong bytes" }
   else check(String(bytes).contains("Example Domain")) { "Origin body missing" }
   report.append("VPN TLS https://example.com$path ${r.code} ${bytes.size} bytes\n")
  }
 }
 private fun localRequest(path:String,code:Int,body:String?=null) {
  client().newCall(Request.Builder().url("https://10.0.2.2:$originPort$path").build()).execute().use { r ->
   val bytes=r.body!!.bytes()
   check(r.code==code) { "local $path status=${r.code}: ${String(bytes)}" }
   if(body!=null) check(bytes.contentEquals(body.toByteArray())) { "local $path wrong bytes" }
   val hex=bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
   report.append("Unproxied VPN local TLS $path ${r.code} ${bytes.size} bytes hex=$hex\n")
  }
 }
 private fun localBrowsing() {
  val connections=java.util.Collections.newSetFromMap(java.util.IdentityHashMap<okhttp3.Connection,Boolean>())
  val c=client().newBuilder().eventListener(object:okhttp3.EventListener() {
   override fun connectionAcquired(call:okhttp3.Call,connection:okhttp3.Connection) { connections.add(connection) }
  }).build()
  val payload=ByteArray(2*1024*1024+17) { (it%251).toByte() }
  val base="https://10.0.2.2:$originPort"
  repeat(2) { n ->
   val body=object:okhttp3.RequestBody() {
    override fun contentType():okhttp3.MediaType?=null
    override fun contentLength()=if(n==0) payload.size.toLong() else -1L
    override fun writeTo(sink:okio.BufferedSink) { sink.write(payload) }
   }
   c.newCall(Request.Builder().url("$base/echo?n=$n").post(body).build()).execute().use { r ->
    check(r.code==200); check(r.body!!.bytes().contentEquals(payload)) { "Large POST echo differs" }
   }
  }
  c.newCall(Request.Builder().url("$base/stream").build()).execute().use { r ->
   check(r.code==200)
   val input=r.body!!.byteStream(); check(input.read()=='s'.code)
   var total=1L; val buffer=ByteArray(8192)
   while(true) { val n=input.read(buffer); if(n<0) break; for(i in 0 until n) check(buffer[i]=='s'.code.toByte()); total+=n }
   check(total==3L*1024*1024+3)
  }
  check(connections.size==1) { "Persistent downstream TLS connection not reused: ${connections.size}" }
  report.append("Real TUN browsing: 2,097,169-byte fixed + chunked POST echoes, 3,145,731-byte stream, three requests on one TLS connection PASS\n")
  c.connectionPool.evictAll()
 }
 /** Test APK only: inject this one ephemeral origin trust into the actual running proxy.
  * Keeps the existing protected socket factory and hostname verifier; production has no test hook.
  * Hidden API access is enabled by shell on this disposable AOSP emulator, not on phones.
  */
 private fun trustFixtureOrigin() {
  val at=Class.forName("android.app.ActivityThread")
  val thread=at.getDeclaredMethod("currentActivityThread").invoke(null)
  val field=at.getDeclaredField("mServices").apply { isAccessible=true }
  val instance=(field.get(thread) as Map<*,*>).values.single { it?.javaClass?.name==service }!!
  val proxyField=instance.javaClass.getDeclaredField("proxy").apply { isAccessible=true }
  val proxy=proxyField.get(instance)!!
  val upstreamField=proxy.javaClass.getDeclaredField("upstream").apply { isAccessible=true }
  val existing=upstreamField.get(proxy) as OkHttpClient
  val cert=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
   java.io.ByteArrayInputStream(android.util.Base64.decode(originCertificate,android.util.Base64.DEFAULT))) as java.security.cert.X509Certificate
  val trust=HandshakeCertificates.Builder().addTrustedCertificate(cert).build()
  upstreamField.set(proxy,existing.newBuilder().sslSocketFactory(trust.sslSocketFactory(),trust.trustManager).build())
  report.append("Test APK injected ephemeral local-origin trust only; protected socket factory/hostname verification retained\n")
 }
 private fun query(host:String,resolverAddress:String="10.111.0.2"):ByteArray {
  val o=java.io.ByteArrayOutputStream(); o.write(byteArrayOf(0x33,0x45,1,0,0,1,0,0,0,0,0,0))
  host.split('.').forEach { o.write(it.length); o.write(it.toByteArray()) }; o.write(byteArrayOf(0,0,1,0,1)); val q=o.toByteArray()
  return DatagramSocket().use { s -> s.soTimeout=20000; s.connect(InetAddress.getByName(resolverAddress),53)
   s.send(DatagramPacket(q,q.size)); val p=DatagramPacket(ByteArray(4096),4096); s.receive(p)
   p.data.copyOf(p.length).also { check(Dns.accepts(q,it)) }
  }
 }
 fun run() {
  val cm=context.getSystemService(ConnectivityManager::class.java)
  val saved=InspectionSettingsPrefs.load(context)
  try {
   // ACCESS_NETWORK_STATE is a normal manifest permission; do not adopt shell identity
   // around VpnService.prepare, which verifies the caller's package/UID.
   check(android.net.VpnService.prepare(context)==null) { "Private emulator VPN appop not granted" }
   // Loading the signed real corpus uses existing production updater; never inject invented rules.
   IndexStore.load(context)
   until("real signed index",360) { IndexStore.snapshot!=null }
   check(IndexStore.index!!.blocked("doubleclick.net"))
   InspectionUrlLogPrefs.set(context,true)
   InspectionSettingsPrefs.save(context,InspectionSettings("example.com","/blocked"))
   start(cm)
   try {
    OkHttpClient.Builder().proxy(Proxy.NO_PROXY).callTimeout(20,TimeUnit.SECONDS).build()
     .newCall(Request.Builder().url("https://example.com/").build()).execute().close()
    error("Untrusted installation CA unexpectedly accepted")
   } catch(_:javax.net.ssl.SSLException) { report.append("Android client without installation CA rejects interception\n") }
   val c=client()
   request(c,"/",200)
   request(c,"/blocked",403,"Blocked by Curtain inspection\n")
   check(Dns.u(query("doubleclick.net"),2) and 15==3) { "DNS block not preserved" }
   check(Dns.u(query("example.com"),2) and 15==0) { "DNS allow failed" }
   check(Dns.u(query("doubleclick.net","fc00::2"),2) and 15==3) { "IPv6 TUN DNS block failed" }
   report.append("IPv6 TUN UDP DNS NXDOMAIN verified\n")
   report.append("Actual VPN UDP DNS block NXDOMAIN + allow preserved\n")
   val entries=InspectionUrlLogUi.log!!.recent()
   check(entries.any { it.url=="https://example.com/blocked" && it.status==403 })
   check(entries.any { it.url=="https://example.com/" && it.status==200 })
   report.append("Full URL + block/allow actions present in opt-in log\n")
   stop(cm)
   InspectionSettingsPrefs.save(context,InspectionSettings("example.com","","/modified","Curtain VPN replacement ✓\n"))
   start(cm)
   request(client(),"/modified",200,"Curtain VPN replacement ✓\n")
   check(InspectionUrlLogUi.log!!.recent().any { it.url=="https://example.com/modified" && it.action==org.curtain.dns.inspection.InspectionAction.REPLACE })
   stop(cm)
   if(originPort>0) {
    InspectionSettingsPrefs.save(context,InspectionSettings("10.0.2.2","/blocked"))
    start(cm)
    localRequest("/untrusted",502) // production upstream rejects our ephemeral origin before trust injection
    trustFixtureOrigin()
    localRequest("/allowed",200,"Origin allowed ✓\n")
    localRequest("/blocked",403,"Blocked by Curtain inspection\n")
    localBrowsing()
    stop(cm)
    InspectionSettingsPrefs.save(context,InspectionSettings("10.0.2.2","","/modified","Curtain replacement ✓\n"))
    start(cm); trustFixtureOrigin()
    localRequest("/modified",200,"Curtain replacement ✓\n")
    stop(cm)
   }
   // Retained DNS-only mode must still have only resolver /32, real DNS block and ordinary HTTPS.
   context.startForegroundService(Intent(context,DnsVpnService::class.java))
   until("DNS-only active") { DnsVpnService.active }
   until("DNS-only route installed") { DatagramSocket().use { s -> s.connect(InetAddress.getByName("10.111.0.2"),53); s.localAddress.hostAddress=="10.111.0.1" } }
   check(cm.getLinkProperties(cm.activeNetwork)!!.routes.none { it.isDefaultRoute })
   check(Dns.u(query("doubleclick.net"),2) and 15==3)
   OkHttpClient.Builder().proxy(Proxy.NO_PROXY).build().newCall(Request.Builder().url("https://example.com/").build()).execute().use { check(it.code==200) }
   context.startService(Intent(context,DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
   until("DNS-only Stop") { cm.allNetworks.none { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true } }
   report.append("DNS-only /32 regression: DNS block, normal HTTPS, Stop PASS\n")
   repeat(3) {
    context.startForegroundService(intent("org.curtain.dns.INSPECTION_VPN_START"))
    until("start observed") { state("starting")==true || state("active")==true }
    stop(cm)
    until("old start worker released") { Thread.getAllStackTraces().keys.none { it.isAlive && it.name=="curtain-inspection-vpn-start" } }
    runner.waitForIdleSync()
    check(state("active")==false && state("starting")==false)
    check(!hev.htproxy.TProxyService.TProxyIsRunning())
   }
   report.append("Three start/Stop cycles: no worker resurrection, native engine stopped, no VPN network\n")
   OkHttpClient.Builder().proxy(Proxy.NO_PROXY).build().newCall(Request.Builder().url("https://example.com/").build()).execute().use { check(it.code==200) }
   report.append("Normal unproxied platform-trusted HTTPS after final Stop PASS\n")
   report.append("Test-only client CA provisioning used; interactive CA installer NOT exercised\nPASS\n")
   runner.finish(-1,Bundle().apply { putString("stream",report.toString()) })
  } catch(e:Throwable) {
   runner.finish(0,Bundle().apply { putString("stream",report.toString()+"FAIL: "+e.toString()+"\n"+e.stackTraceToString()) })
  } finally {
   runCatching { context.startService(intent("org.curtain.dns.INSPECTION_VPN_STOP")) }
   runCatching { context.startService(Intent(context,DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)) }
   InspectionSettingsPrefs.save(context,saved); InspectionUrlLogPrefs.set(context,false)
   runner.uiAutomation.dropShellPermissionIdentity()
  }
 }
}
