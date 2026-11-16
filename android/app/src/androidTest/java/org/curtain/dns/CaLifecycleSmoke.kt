package org.curtain.dns

import android.app.Instrumentation
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import org.curtain.dns.inspection.AndroidCaStoreProbe
import org.curtain.dns.inspection.CaRotation
import java.util.concurrent.TimeUnit

/** Private disposable emulator only. No root/admin/CA-store writes: real widgets, document UI and
 * platform Settings installer. The old CA must already have been removed through Settings. */
class CaLifecycleSmoke(private val runner:Instrumentation) {
 private val context get()=runner.targetContext
 private val report=StringBuilder()
 private fun until(label:String,seconds:Int=45,predicate:()->Boolean) {
  val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds.toLong())
  while(System.nanoTime()<deadline) { if(predicate()) return; Thread.sleep(300) }
  error("Timeout: $label; active=${runner.uiAutomation.rootInActiveWindow?.packageName}")
 }
 private fun nodes():List<AccessibilityNodeInfo> {
  val out=ArrayList<AccessibilityNodeInfo>()
  fun visit(n:AccessibilityNodeInfo?) { if(n==null) return; out.add(n); for(i in 0 until n.childCount) visit(n.getChild(i)) }
  visit(runner.uiAutomation.rootInActiveWindow); return out
 }
 private fun click(text:String,scroll:Boolean=true) {
  repeat(12) {
   val all=nodes();val found=all.firstOrNull { it.text?.toString()==text && it.isEnabled }
   if(found!=null) {
    var candidate:AccessibilityNodeInfo?=found
    while(candidate!=null && !candidate.isClickable) candidate=candidate.parent
    if(candidate?.performAction(AccessibilityNodeInfo.ACTION_CLICK)==true) { Thread.sleep(800); return }
   }
   if(scroll) {
    val start=android.os.SystemClock.uptimeMillis()
    fun event(action:Int,y:Float) {
     val e=android.view.MotionEvent.obtain(start,android.os.SystemClock.uptimeMillis(),action,160f,y,0)
     e.source=android.view.InputDevice.SOURCE_TOUCHSCREEN
     runner.uiAutomation.injectInputEvent(e,true); e.recycle()
    }
    event(android.view.MotionEvent.ACTION_DOWN,550f)
    for(i in 1..10) { Thread.sleep(40); event(android.view.MotionEvent.ACTION_MOVE,550f-37f*i) }
    event(android.view.MotionEvent.ACTION_UP,180f)
   }
   Thread.sleep(700)
  }
  error("Cannot click $text; visible=${nodes().mapNotNull { it.text }}")
 }
 private fun widget(activity:android.app.Activity,name:String):Button =
  activity.javaClass.getDeclaredField(name).apply { isAccessible=true }.get(activity) as Button
 private fun clickWidget(activity:android.app.Activity,name:String) {
  runner.runOnMainSync { val b=widget(activity,name); check(b.isEnabled) { "$name disabled" }; check(b.performClick()) }
 }
 fun run() {
  try {
   val info=runner.uiAutomation.serviceInfo
   info.flags=info.flags or android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
   runner.uiAutomation.serviceInfo=info
   val before=InspectionCa.authority(context)
   val state=CaRotationPrefs.load(context)
   val oldFp=state.oldFingerprint
   check(oldFp.isNotBlank())
   check(AndroidCaStoreProbe.installedFingerprints()?.contains(oldFp)==false) { "Remove old CA via Settings first" }
   val activity=runner.startActivitySync(Intent(context,InspectionActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
   if(CaRotation.isPending(state)) {
    check(oldFp==before.fingerprintSha256())
    until("confirm enabled after fresh removal observation") { widget(activity,"rotationConfirm").isEnabled }
    check(!widget(activity,"export").isEnabled)
    clickWidget(activity,"rotationConfirm")
    until("completed persisted old/new record") { CaRotation.hasCompletedRecord(CaRotationPrefs.load(context)) }
    report.append("Actual in-app confirm widget: fresh AndroidCAStore absence gate, exact old/new record PASS\n")
   } else {
    check(CaRotation.hasCompletedRecord(state) && state.newFingerprint==before.fingerprintSha256())
    report.append("Resumed prior actual-widget rotation; process restart kept the exact replacement root, no additional CA generated PASS\n")
   }
   val after=InspectionCa.authority(context)
   check(after.fingerprintSha256()!=oldFp)
   check(CaRotationPrefs.load(context).newFingerprint==after.fingerprintSha256())
   check(InspectionCa.directory(context).listFiles()!!.map { it.name }==listOf("inspection-ca.pem"))
   report.append("Exactly one atomic root file; OLD ${state.oldSubject} $oldFp\nNEW ${after.subjectDistinguishedName()} ${after.fingerprintSha256()}\n")
   until("new public export enabled") { widget(activity,"export").isEnabled }
   fun downloads():Set<String> = runner.uiAutomation.executeShellCommand("ls -1 /sdcard/Download").use { fd ->
    android.os.ParcelFileDescriptor.AutoCloseInputStream(fd).use { it.bufferedReader().readLines().filter { n -> n.startsWith("curtain-")&&n.endsWith(".crt") }.toSet() }
   }
   val existing=downloads()
   clickWidget(activity,"export")
   click("SAVE",false)
   var publicName=""
   until("new document public certificate matches replacement") {
    val added=downloads()-existing
    if(added.size!=1) false else {
     publicName=added.single()
     check(publicName.matches(Regex("[A-Za-z0-9 .()_-]+\\.crt")))
     // UiAutomation executes argv, not a shell: quotes do not escape spaces. Let find pass
     // the observed document path as a single argument to cat instead of guessing a file name.
     val pattern=publicName.replace(' ','?')
     val public=runner.uiAutomation.executeShellCommand("find /sdcard/Download -maxdepth 1 -name $pattern -exec cat {} ;").use { fd ->
      android.os.ParcelFileDescriptor.AutoCloseInputStream(fd).use { it.readBytes() }
     }
     check(!public.toString(Charsets.US_ASCII).contains("PRIVATE KEY"))
     runCatching {
      val cert=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(public.inputStream()) as java.security.cert.X509Certificate
      AndroidCaStoreProbe.sha256Fingerprint(cert)==after.fingerprintSha256()
     }.getOrDefault(false)
    }
   }
   report.append("Real ACTION_CREATE_DOCUMENT/Save public-only export $publicName matches new fingerprint PASS\n")
   context.startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
   click("More security & privacy");click("Encryption & credentials");click("Install a certificate");click("CA certificate")
   click("INSTALL ANYWAY",false);click(publicName,false)
   until("new CA installed by actual Settings UI") { AndroidCaStoreProbe.installedFingerprints()?.contains(after.fingerprintSha256())==true }
   check(AndroidCaStoreProbe.installedFingerprints()?.contains(oldFp)==false)
   context.startActivity(Intent("com.android.settings.TRUSTED_CREDENTIALS_USER").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
   until("trusted User list") { nodes().any { it.viewIdResourceName=="com.android.settings:id/trusted_credential_subject_primary" } }
   val entries=nodes().filter { it.viewIdResourceName=="com.android.settings:id/trusted_credential_subject_primary" }
   check(entries.size==1 && entries.single().text.toString()=="Curtain local inspection CA")
   report.append("Actual Settings CA warning/file picker/install: new fingerprint present, old absent, exactly one user CA PASS\nPASS\n")
   runner.finish(-1,Bundle().apply { putString("stream",report.toString()) })
  } catch(e:Throwable) {
   runner.finish(0,Bundle().apply { putString("stream",report.toString()+"FAIL: "+e.stackTraceToString()) })
  }
 }
}
