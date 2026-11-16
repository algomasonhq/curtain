package org.curtain.dns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import hev.htproxy.TProxyService
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import org.curtain.dns.inspection.HostPathRules
import org.curtain.dns.inspection.InspectionLog
import org.curtain.dns.inspection.InspectionProxy
import org.curtain.dns.inspection.SocksInspectionBridge

/** Opt-in full-route transport. DNS-only service and signed index format remain independent.
 * Worker prepares only local resources. Main owns all TUN/native transitions, so stale workers
 * cannot establish a VPN or stop a later generation. Native borrows, never owns, our TUN fd.
 */
class InspectionVpnService:VpnService() {
 companion object {
  const val ACTION_START="org.curtain.dns.INSPECTION_VPN_START"
  const val ACTION_STOP="org.curtain.dns.INSPECTION_VPN_STOP"
  const val TUN_IPV4="10.111.0.1"
  const val TUN_DNS_V4="10.111.0.2"
  const val TUN_IPV6="fc00::1"
  const val TUN_DNS_V6="fc00::2"
  const val TUN_MTU=8500
  @Volatile var active=false; private set
  @Volatile var starting=false; private set
  @Volatile var indexReady=false; private set
  @Volatile var message="Off • full-route inspection VPN (opt-in, default off)"; private set
 }
 private val main=Handler(Looper.getMainLooper())
 @Volatile private var generation=0L
 private var worker:Thread?=null
 private var monitor:Thread?=null
 private var proxy:InspectionProxy?=null
 private var bridge:SocksInspectionBridge?=null
 private var tunnel:ParcelFileDescriptor?=null
 private var nativeStarted=false
 private var config:File?=null
 private val udpSockets=ConcurrentHashMap.newKeySet<DatagramSocket>()
 private val tcpSockets=ConcurrentHashMap.newKeySet<Socket>()
 // Inherit VpnService.onBind: Android needs its Binder to deliver onRevoke.
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
  if(intent?.action==ACTION_STOP) { stopVpn(); stopSelf(); return START_NOT_STICKY }
  if(intent?.action!=ACTION_START) { stopSelf(); return START_NOT_STICKY }
  if(org.curtain.dns.inspection.CaRotation.isPending(CaRotationPrefs.load(this))) {
   message="CA rotation pending — finish or cancel it before starting inspection"; stopSelf(); return START_NOT_STICKY
  }
  if(active||starting) return START_NOT_STICKY
  val token=++generation
  starting=true; message="Starting full-route inspection VPN…"
  try { enterForeground() } catch(e:Exception) {
   starting=false; message="Foreground start failed: ${e.javaClass.simpleName}"; stopSelf(); return START_NOT_STICKY
  }
  worker=Thread({ prepareEngine(token) },"curtain-inspection-vpn-start").also { it.start() }
  return START_NOT_STICKY
 }
 private fun prepareEngine(token:Long) {
  var p:InspectionProxy?=null
  var b:SocksInspectionBridge?=null
  val log=InspectionLog(500)
  try {
   val ca=InspectionCa.authority(this)
   val settings=InspectionSettingsPrefs.load(this)
   settings.validate()?.let { error(it) }
   val cm=getSystemService(ConnectivityManager::class.java)
   val net=cm.allNetworks.firstOrNull { n ->
    cm.getNetworkCapabilities(n)?.let { c -> c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) }==true
   } ?: error("No underlying Internet network")
   val dns=cm.getLinkProperties(net)?.dnsServers?.firstOrNull() ?: InetAddress.getByName("1.1.1.1")
   val snapshot=IndexStore.snapshot
   val session=snapshot?.let { FilterSession(it) }
   val resolver=QueryResolver(session?.let { it::blockRule } ?: { _ -> null },
    { q -> relayDns(q,net,dns,token) }, { QueryLog.shared })
   val client=OkHttpClient.Builder().socketFactory(ProtectedSocketFactory { socket ->
    if(token!=generation) false else protect(socket).also { if(it) net.bindSocket(socket) }
   }).dns(object:okhttp3.Dns { override fun lookup(hostname:String)=net.getAllByName(hostname).toList() }).build()
   p=InspectionProxy(ca,HostPathRules(*listOfNotNull(settings.coreRule()).toTypedArray()),log,client)
   b=SocksInspectionBridge(p.localPort,{ host,port -> connectDirect(host,port,net,token) },{ q ->
    if(token==generation) resolver.handle(q) else null
   })
   val preparedProxy=p; val preparedBridge=b
   main.post {
    if(token!=generation) { closeLocal(preparedProxy,preparedBridge,log,null); return@post }
    try {
     check(prepare(this)==null) { "VPN permission missing" }
     proxy=preparedProxy; bridge=preparedBridge
     val cfg=File(cacheDir,"inspection-vpn-$token.yml"); config=cfg
     cfg.writeText("""tunnel:
  name: curtain-inspection
  mtu: $TUN_MTU
  ipv4: $TUN_IPV4
  ipv6: '$TUN_IPV6'
  icmp: 'off'
socks5:
  port: ${preparedBridge.localPort}
  address: 127.0.0.1
  udp: 'udp'
misc:
  max-session-count: 64
  connect-timeout: 10000
  tcp-read-write-timeout: 60000
  udp-read-write-timeout: 15000
  log-file: null
  log-level: warn
""")
     tunnel=Builder().setSession("Curtain full-route inspection").setMtu(TUN_MTU)
      .addAddress(TUN_IPV4,32).addAddress(TUN_IPV6,128)
      .addDnsServer(TUN_DNS_V4).addDnsServer(TUN_DNS_V6)
      .addRoute("0.0.0.0",0).addRoute("::",0).setUnderlyingNetworks(arrayOf(net))
      .setBlocking(false).establish() ?: error("VPN not established")
     check(TProxyService.TProxyStartService(cfg.absolutePath,tunnel!!.fd)) { "Native engine start failed" }
     nativeStarted=true
     indexReady=snapshot!=null; active=true; starting=false
     message="Running • full-route IPv4+IPv6 TCP/TLS • DNS ${if(indexReady) "filtered" else "unfiltered (index not ready)"} • other UDP blocked"
     InspectionUrlLogUi.log=log; log.setEnabled(InspectionUrlLogPrefs.enabled(this))
     monitor=Thread({ monitorEngine(token) },"curtain-inspection-vpn-monitor").also { it.start() }
     enterForeground()
    } catch(e:Throwable) {
     stopVpn(); message="Could not start inspection VPN: ${e.message ?: e.javaClass.simpleName}"; stopSelf()
    }
   }
  } catch(e:Throwable) {
   closeLocal(p,b,log,null)
   main.post { if(token==generation) { stopVpn(); message="Could not prepare inspection VPN: ${e.message ?: e.javaClass.simpleName}"; stopSelf() } }
  }
 }
 private fun connectDirect(host:String,port:Int,net:Network,token:Long):Socket {
  check(token==generation) { "Stopped" }
  val socket=ProtectedSocketFactory { protect(it).also { ok -> if(ok) net.bindSocket(it) } }.createSocket()
  tcpSockets.removeIf { it.isClosed }; tcpSockets.add(socket)
  try {
   check(token==generation) { "Stopped" }
   socket.connect(InetSocketAddress(net.getAllByName(host).first(),port),10_000)
   return socket
  } catch(e:Exception) { tcpSockets.remove(socket); socket.close(); throw e }
 }
 private fun relayDns(query:ByteArray,net:Network,dns:InetAddress,token:Long):ByteArray? {
  val socket=DatagramSocket(); udpSockets.add(socket)
  try {
   if(token!=generation) return null
   check(protect(socket)); net.bindSocket(socket)
   socket.soTimeout=2500; socket.connect(InetSocketAddress(dns,53))
   socket.send(DatagramPacket(query,query.size))
   val deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(2500)
   while(token==generation) {
    val left=TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime()); if(left<=0) return null
    socket.soTimeout=left.toInt().coerceAtLeast(1)
    val packet=DatagramPacket(ByteArray(4097),4097); socket.receive(packet)
    if(packet.length>4096) continue
    val response=packet.data.copyOf(packet.length)
    if(Dns.accepts(query,response)) return response
   }
   return null
  } finally { udpSockets.remove(socket); socket.close() }
 }
 private fun monitorEngine(token:Long) {
  try {
   while(token==generation) {
    Thread.sleep(1000)
    if(!TProxyService.TProxyIsRunning()) {
     main.post { if(token==generation) { stopVpn(); message="Inspection VPN engine stopped"; stopSelf() } }; return
    }
   }
  } catch(_:InterruptedException) {}
 }
 /** Main-thread native transitions are serialized. Join native before releasing our borrowed fd.
  * Slow local listener cleanup owns only the captured generation, never the global engine.
  */
 private fun stopVpn() {
  generation++
  worker?.interrupt(); worker=null; monitor?.interrupt(); monitor=null
  if(nativeStarted) { runCatching { TProxyService.TProxyStopService() }; nativeStarted=false }
  runCatching { tunnel?.close() }; tunnel=null
  udpSockets.forEach { it.close() }; udpSockets.clear()
  tcpSockets.forEach { runCatching { it.close() } }; tcpSockets.clear()
  val p=proxy; val b=bridge; val cfg=config; val log=InspectionUrlLogUi.log
  proxy=null; bridge=null; config=null
  log?.setEnabled(false); InspectionUrlLogUi.log=null
  active=false; starting=false; indexReady=false
  message="Off • full-route inspection VPN (opt-in, default off)"
  stopForeground(STOP_FOREGROUND_REMOVE)
  closeLocal(p,b,log,cfg)
 }
 private fun closeLocal(p:InspectionProxy?,b:SocksInspectionBridge?,log:InspectionLog?,cfg:File?) {
  log?.setEnabled(false)
  Thread({ runCatching { b?.close() }; runCatching { p?.close() }; cfg?.delete() },"curtain-inspection-local-cleanup").start()
 }
 private fun enterForeground() {
  val manager=getSystemService(NotificationManager::class.java)
  manager.createNotificationChannel(NotificationChannel("inspection-vpn","Full-route inspection VPN",NotificationManager.IMPORTANCE_LOW))
  val open=PendingIntent.getActivity(this,0,Intent(this,InspectionActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
  val stop=PendingIntent.getService(this,4,Intent(this,InspectionVpnService::class.java).setAction(ACTION_STOP),PendingIntent.FLAG_IMMUTABLE)
  val notification=Notification.Builder(this,"inspection-vpn").setSmallIcon(android.R.drawable.ic_lock_lock)
   .setContentTitle("Curtain full-route inspection VPN").setContentText(message).setContentIntent(open)
   .addAction(Notification.Action.Builder(null,"Stop",stop).build()).setOngoing(true).build()
  startForeground(4,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
 }
 override fun onRevoke() { stopVpn(); message="VPN permission revoked • stopped"; stopSelf() }
 override fun onDestroy() { stopVpn(); super.onDestroy() }
}
