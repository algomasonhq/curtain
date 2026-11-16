package org.curtain.dns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import org.curtain.dns.inspection.HostPathRules
import org.curtain.dns.inspection.InspectionLog
import org.curtain.dns.inspection.InspectionProxy
import org.curtain.dns.inspection.LocalCertificateAuthority

/** Only public certificate access; the engine owns the no-backup installation key. */
object InspectionCa {
 fun directory(c:Context)=File(c.noBackupFilesDir,"inspection")
 fun authority(c:Context)=LocalCertificateAuthority(directory(c))
 fun fingerprintSha256(cert:X509Certificate):String = MessageDigest.getInstance("SHA-256")
  .digest(cert.encoded).joinToString(":") { "%02X".format(it.toInt() and 0xff) }
}

/** Explicit user-started loopback proxy, independent of the unchanged DNS-only VPN. */
class InspectionService:Service() {
 companion object {
  const val ACTION_START="org.curtain.dns.INSPECTION_START"
  const val ACTION_STOP="org.curtain.dns.INSPECTION_STOP"
  const val LISTEN_HOST="127.0.0.1"
  @Volatile var active=false; private set
  @Volatile var starting=false; private set
  @Volatile var listenPort=0; private set
  @Volatile var message="Off • local HTTPS inspection proxy"; private set
 }
 private val main=Handler(Looper.getMainLooper())
 // All generation/resource publication happens on main, including Stop/onDestroy. An old
 // start worker can never resurrect a stopped service or overwrite a newer session.
 private var generation=0L
 private var worker:Thread?=null
 private var proxy:InspectionProxy?=null
 override fun onBind(intent:Intent?):IBinder?=null
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
  if(intent?.action==ACTION_STOP) { stopEngine(); stopSelf(); return START_NOT_STICKY }
  if(intent?.action!=ACTION_START) { stopSelf(); return START_NOT_STICKY }
  if(org.curtain.dns.inspection.CaRotation.isPending(CaRotationPrefs.load(this))) {
   message="CA rotation pending — finish or cancel it before starting inspection"; stopSelf(); return START_NOT_STICKY
  }
  if(active||starting) return START_NOT_STICKY
  val token=++generation
  starting=true; active=false; message="Starting local HTTPS inspection proxy…"
  try { enterForeground() } catch(e:Exception) {
   starting=false; message="Foreground start failed: ${e.message}"; stopSelf(); return START_NOT_STICKY
  }
  worker=Thread({
   var created:InspectionProxy?=null
   var log:InspectionLog?=null
   var failure:String?=null
   try {
    val ca=InspectionCa.authority(this)
    val settings=InspectionSettingsPrefs.load(this)
    settings.validate()?.let { error(it) }
    val rule=settings.coreRule()
    log=InspectionLog(500).also { it.setEnabled(InspectionUrlLogPrefs.enabled(this)) }
    created=InspectionProxy(ca,HostPathRules(*listOfNotNull(rule).toTypedArray()),log)
   } catch(e:Exception) { failure=e.message ?: e.javaClass.simpleName }
   val resource=created; val entries=log; val error=failure
   main.post {
    if(token!=generation) { resource?.close(); entries?.setEnabled(false) }
    else if(resource==null) {
     entries?.setEnabled(false); starting=false; active=false
     message="Could not start local HTTPS inspection proxy: $error"
     stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    } else {
     proxy=resource; InspectionUrlLogUi.log=entries
     // Re-read the preference in case the user toggled logging while CA creation ran.
     entries?.setEnabled(InspectionUrlLogPrefs.enabled(this))
     listenPort=resource.localPort; starting=false; active=true
     message="Listening on $LISTEN_HOST:$listenPort • loopback only, not system-wide"
     enterForeground()
    }
   }
  },"curtain-inspection-start").also { it.start() }
  return START_NOT_STICKY
 }
 private fun stopEngine() {
  generation++
  worker?.interrupt(); worker=null
  proxy?.close(); proxy=null
  InspectionUrlLogUi.log?.setEnabled(false); InspectionUrlLogUi.log=null
  active=false; starting=false; listenPort=0; message="Off • local HTTPS inspection proxy"
  stopForeground(STOP_FOREGROUND_REMOVE)
 }
 private fun enterForeground() {
  val manager=getSystemService(NotificationManager::class.java)
  manager.createNotificationChannel(NotificationChannel("inspection","Local HTTPS inspection",NotificationManager.IMPORTANCE_LOW))
  val open=PendingIntent.getActivity(this,0,Intent(this,InspectionActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
  val stop=PendingIntent.getService(this,1,Intent(this,InspectionService::class.java).setAction(ACTION_STOP),PendingIntent.FLAG_IMMUTABLE)
  val notification=Notification.Builder(this,"inspection").setSmallIcon(android.R.drawable.ic_lock_lock)
   .setContentTitle("Curtain local HTTPS inspection").setContentText(message).setContentIntent(open)
   .addAction(Notification.Action.Builder(null,"Stop",stop).build()).setOngoing(true).build()
  startForeground(2,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
 }
 override fun onDestroy() { stopEngine(); super.onDestroy() }
}
