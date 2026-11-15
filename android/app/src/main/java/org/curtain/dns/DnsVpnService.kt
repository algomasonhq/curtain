package org.curtain.dns
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

class DnsVpnService:VpnService() {
 companion object {
  const val ACTION_STOP="org.curtain.dns.STOP"
  @Volatile var active=false; private set
  @Volatile var starting=false; private set
  @Volatile var runningVersion:Long?=null; private set
  @Volatile var message="Stopped • DNS-only filter ready"; private set
 }
 @Volatile private var tun:ParcelFileDescriptor?=null
 private var reader:Thread?=null
 private var pool:ThreadPoolExecutor?=null
 private val sockets=ConcurrentHashMap.newKeySet<DatagramSocket>()
 private val outputLock=Any()
 @Volatile private var stopping=false
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
  if(intent?.action==ACTION_STOP) { message="Stopped • DNS-only filter ready"; cleanup(); stopSelf(); return START_NOT_STICKY }
  if(active || starting) return START_NOT_STICKY
  val snapshot=IndexStore.snapshot
  if(snapshot==null) { message="Index not ready; VPN was not started"; stopSelf(); return START_NOT_STICKY }
  val session=FilterSession(snapshot)
  starting=true; stopping=false
  try {
   val manager=getSystemService(NotificationManager::class.java)
   manager.createNotificationChannel(NotificationChannel("dns","DNS-only filtering",NotificationManager.IMPORTANCE_LOW))
   val open=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
   val notification=Notification.Builder(this,"dns").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("Curtain DNS-only filter").setContentText("Experimental list • no HTTPS inspection").setContentIntent(open).setOngoing(true).build()
   startForeground(1,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
   check(prepare(this)==null) { "VPN permission missing" }
   val descriptor=Builder().setSession("Curtain DNS-only").setMtu(1500).addAddress("10.111.0.1",32).addDnsServer("10.111.0.2").addRoute("10.111.0.2",32).allowFamily(OsConstants.AF_INET6).setBlocking(false).establish() ?: error("VPN not established")
   tun=descriptor
   val executor=ThreadPoolExecutor(4,4,0L,TimeUnit.MILLISECONDS,ArrayBlockingQueue(32),ThreadPoolExecutor.AbortPolicy()); pool=executor
   runningVersion=session.version; active=true; starting=false; message="Running • DNS-only VPN"
   reader=Thread({ runTunnel(descriptor,executor,session) },"curtain-dns-reader").also { it.start() }
  } catch(_:Exception) { message="Could not start DNS VPN. Check VPN permission / other VPNs."; cleanup(); stopSelf() }
  return START_NOT_STICKY
 }
 private fun runTunnel(fd:ParcelFileDescriptor,executor:ThreadPoolExecutor,session:FilterSession) {
  try {
   val input=FileInputStream(fd.fileDescriptor); val output=FileOutputStream(fd.fileDescriptor); val buf=ByteArray(65535)
   val poll=android.system.StructPollfd().apply { this.fd=fd.fileDescriptor; events=OsConstants.POLLIN.toShort() }
   while(!stopping && tun===fd) {
    if(android.system.Os.poll(arrayOf(poll),250)==0) continue
    if(stopping || tun!==fd) break
    val n=input.read(buf); if(n<0) break
    val q=Packets.parse(buf.copyOf(n)) ?: continue
    try { executor.execute {
     val response=try { answer(q.dns,fd,session) } catch(_:Exception) { Dns.error(q.dns,2) }
     try { synchronized(outputLock) { if(!stopping && tun===fd) output.write(Packets.reply(q,response)) } } catch(_:Exception) { failTunnel(fd) }
    } } catch(_:java.util.concurrent.RejectedExecutionException) { synchronized(outputLock) { if(!stopping && tun===fd) output.write(Packets.reply(q,Dns.error(q.dns,2))) } }
   }
   failTunnel(fd)
  } catch(_:Exception) { failTunnel(fd) }
 }
 private fun failTunnel(fd:ParcelFileDescriptor) { android.os.Handler(mainLooper).post { if(!stopping && tun===fd) { message="DNS VPN stopped after an I/O error"; cleanup(); stopSelf() } } }
 private fun answer(query:ByteArray,fd:ParcelFileDescriptor,session:FilterSession):ByteArray =
  QueryResolver(session::blockRule,{ q -> relay(q,fd) },{ QueryLog.shared }).handle(query)
 /** Upstream response, or null on timeout/stop. */
 private fun relay(query:ByteArray,fd:ParcelFileDescriptor):ByteArray? {
  val socket=DatagramSocket(); sockets.add(socket)
  try {
   if(stopping || tun!==fd) error("Stopped")
   check(protect(socket)); socket.soTimeout=2500
   socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(1,1,1,1)),53))
   socket.send(DatagramPacket(query,query.size))
   val deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(2500)
   while(!stopping) {
    val left=TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime()); if(left<=0) break
    socket.soTimeout=left.toInt().coerceAtLeast(1)
    val packet=DatagramPacket(ByteArray(4097),4097); socket.receive(packet)
    if(packet.length>4096) continue
    val response=packet.data.copyOf(packet.length)
    if(Dns.accepts(query,response)) return response
   }
   return null
  } finally { sockets.remove(socket); socket.close() }
 }
 @Synchronized private fun cleanup() {
  stopping=true; active=false; starting=false; runningVersion=null
  try { tun?.close() } catch(_:Exception) {}; tun=null
  sockets.forEach { it.close() }; sockets.clear(); pool?.shutdownNow(); pool=null
  reader?.interrupt(); reader=null; stopForeground(STOP_FOREGROUND_REMOVE)
 }
 override fun onRevoke() { message="VPN permission revoked • stopped"; cleanup(); stopSelf() }
 override fun onDestroy() { if(active || starting) message="Stopped • DNS-only filter ready"; cleanup(); super.onDestroy() }
}
