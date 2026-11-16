package org.curtain.dns
import android.app.Instrumentation
import android.content.Intent
import android.os.Bundle
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/** No production test hooks; run only after shell grants this private emulator VPN consent. */
class SmokeInstrumentation:Instrumentation() {
 private var fixture:String?=null
 private var inspection=false
 private var caLifecycle=false
 private var originPort=0
 private var originCertificate=""
 override fun onCreate(arguments:Bundle?) { fixture=arguments?.getString("fixture"); inspection=arguments?.getString("inspection")=="true"; caLifecycle=arguments?.getString("caLifecycle")=="true"; originPort=arguments?.getString("originPort")?.toInt() ?: 0; originCertificate=arguments?.getString("originCertificate") ?: ""; super.onCreate(arguments); start() }
 override fun onStart() {
  if(caLifecycle) { CaLifecycleSmoke(this).run(); return }
  if(inspection) { InspectionVpnSmoke(this,originPort,originCertificate).run(); return }
  val report=StringBuilder()
  try {
   val context=targetContext
   // A legitimate BOOT_COMPLETED receiver may initialize WorkManager before
   // instrumentation onStart; absence of the eager provider is the invariant.
   val providers=context.packageManager.getPackageInfo(context.packageName,android.content.pm.PackageManager.GET_PROVIDERS).providers.orEmpty()
   check(providers.none { it.name=="androidx.startup.InitializationProvider" }) { "Eager startup provider must be absent" }
   report.append("No eager startup provider; WorkManager initialized=${androidx.work.WorkManager.isInitialized()}\n")
   if(fixture!=null) UpdateEndpoint.fixtureBase=fixture
   check(IndexStore.snapshot==null) { "Expected a fresh process" }
   val activity=startActivitySync(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
   val deadline=System.nanoTime()+360_000_000_000L
   while(IndexStore.index==null && IndexStore.error==null && System.nanoTime()<deadline) Thread.sleep(100)
   check(IndexStore.index?.count==9737280L) { "Index not ready: ${IndexStore.error}" }; report.append("Full audited mmap loaded: 9737280 domains\n")
   check(android.net.VpnService.prepare(context)==null) { "VPN consent not granted on emulator" }
   // Deterministic regression: connect before VPN establishment without sending.
   // This socket retains the underlying source even after the VPN route appears.
   val preRouteSocket=DatagramSocket().apply { connect(InetAddress.getByAddress(byteArrayOf(10,111,0,2)),53) }
   check(preRouteSocket.localAddress.hostAddress!="10.111.0.1")
   report.append("Regression socket captured before VPN: ${preRouteSocket.localAddress.hostAddress}\n")
   context.startForegroundService(Intent(context,DnsVpnService::class.java))
   repeat(100) { if(!DnsVpnService.active) Thread.sleep(100) }
   check(DnsVpnService.active) { DnsVpnService.message }
   uiAutomation.adoptShellPermissionIdentity("android.permission.ACCESS_NETWORK_STATE")
   val cm=context.getSystemService(android.net.ConnectivityManager::class.java)
   val networkDeadline=System.nanoTime()+20_000_000_000L
   while(System.nanoTime()<networkDeadline) {
    val net=cm.activeNetwork
    val caps=cm.getNetworkCapabilities(net)
    val lp=cm.getLinkProperties(net)
    if(caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)==true && lp?.routes?.any { it.destination.toString()=="10.111.0.2/32" }==true) break
    Thread.sleep(100)
   }
   val readyNet=cm.activeNetwork
   check(cm.getNetworkCapabilities(readyNet)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)==true && cm.getLinkProperties(readyNet)?.routes?.any { it.destination.toString()=="10.111.0.2/32" }==true) { "VPN and advertised resolver route not ready" }
   uiAutomation.dropShellPermissionIdentity()
   report.append("Foreground VPN established; VPN default and advertised resolver route ready\n")
   // LinkProperties describes the intended route before netd necessarily installs it.
   // Qualify the actual unbound socket, and never send a test DNS name via Wi-Fi.
   fun resolverSocket(initial:DatagramSocket?=null):DatagramSocket {
    val routeDeadline=System.nanoTime()+20_000_000_000L
    var candidate=initial
    var rejected=0
    while(System.nanoTime()<routeDeadline) {
     val socket=candidate ?: DatagramSocket(); candidate=null
     try {
      if(!socket.isConnected) socket.connect(InetAddress.getByAddress(byteArrayOf(10,111,0,2)),53)
      if(socket.localAddress.hostAddress=="10.111.0.1") {
       report.append("Kernel resolver route ready; rejected pre-route sockets=$rejected\n")
       return socket
      }
     } catch(_:java.net.SocketException) { /* Route may not exist yet. */ }
     socket.close(); rejected++; Thread.sleep(100)
    }
    error("Kernel resolver route did not become ready within 20 seconds")
   }
   check(preRouteSocket.localAddress.hostAddress!="10.111.0.1") { "Pre-route socket unexpectedly migrated" }
   val readySocket=resolverSocket(preRouteSocket)
   check(preRouteSocket.isClosed) { "Pre-route socket must be discarded, not reused" }
   readySocket.close()
   report.append("Regression PASS: stale underlying-network socket rejected and closed\n")
   fun query(host:String):ByteArray {
    val o=java.io.ByteArrayOutputStream(); o.write(byteArrayOf(0x12,0x34,1,0,0,1,0,0,0,0,0,0)); host.split('.').forEach { o.write(it.length); o.write(it.toByteArray()) }; o.write(byteArrayOf(0,0,1,0,1)); val q=o.toByteArray()
    resolverSocket().use { socket -> socket.soTimeout=15000; report.append("Probe socket source=${socket.localAddress.hostAddress}; active=${DnsVpnService.active}; running=${DnsVpnService.runningVersion}; busy=${IndexStore.busy}\n"); socket.send(DatagramPacket(q,q.size)); val p=DatagramPacket(ByteArray(4096),4096); try { socket.receive(p) } catch(e:java.net.SocketTimeoutException) { report.append("Timeout source=${socket.localAddress.hostAddress}; active=${DnsVpnService.active}; message=${DnsVpnService.message}\n"); Thread.getAllStackTraces().filter { it.key.name.contains("curtain") || it.key.name.startsWith("pool-") }.forEach { (t,s) -> report.append("Thread ${t.name} ${t.state}: ${s.joinToString(" <- ")}\n") }; throw e }; val r=p.data.copyOf(p.length); check(Dns.accepts(q,r)); return r }
   }
   check(IndexStore.index!!.blocked("doubleclick.net")); val blocked=query("doubleclick.net"); check(Dns.u(blocked,2) and 15==3); report.append("Real TUN UDP blocked name: NXDOMAIN and ID preserved\n")
   check(!IndexStore.index!!.blocked("example.com")); val allowed=query("example.com"); check(Dns.u(allowed,2) and 15==0 && Dns.u(allowed,6)>0); report.append("Real TUN UDP allowed name: public upstream answer and ID preserved\n")
   val connection=java.net.URL("https://example.com/").openConnection() as javax.net.ssl.HttpsURLConnection
   connection.connectTimeout=15000; connection.readTimeout=15000
   try { check(connection.responseCode==200); report.append("Normal HTTPS reachable while DNS-only VPN active\n") } finally { connection.disconnect() }
   context.startService(Intent(context,DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)); repeat(100) { if(DnsVpnService.active) Thread.sleep(100) }; check(!DnsVpnService.active)
   uiAutomation.adoptShellPermissionIdentity("android.permission.ACCESS_NETWORK_STATE")
   fun vpnPresent()=cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)==true }
   repeat(100) { if(vpnPresent()) Thread.sleep(100) }
   check(!vpnPresent()) { "VPN network remains after Stop" }
   uiAutomation.dropShellPermissionIdentity(); report.append("Stop removed active status and actual VPN network from allNetworks\n")
   runOnMainSync { activity.finish() }
   finish(-1,Bundle().apply { putString("stream",report.toString()+"PASS\n") })
  } catch(e:Throwable) { finish(0,Bundle().apply { putString("stream",report.toString()+"FAIL: "+android.util.Log.getStackTraceString(e)) }) }
 }
}
