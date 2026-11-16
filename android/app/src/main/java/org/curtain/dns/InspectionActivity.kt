package org.curtain.dns
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.curtain.dns.inspection.AndroidCaStoreProbe
import org.curtain.dns.inspection.CaRotation
import org.curtain.dns.inspection.CaRotationState
import org.curtain.dns.inspection.InspectionLog

/**
 * Separate loopback-proxy and opt-in full-route VPN controls, with installation CA onboarding.
 * Status refreshes through a bounded handler that runs only while resumed.
 */
class InspectionActivity:Activity() {
  private lateinit var status:TextView; private lateinit var startStop:Button
  private lateinit var vpnSwitch:Switch; private lateinit var vpnStatus:TextView
 private lateinit var fingerprint:TextView; private lateinit var export:Button
 private lateinit var rotationStatus:TextView; private lateinit var rotationBegin:Button
 private lateinit var rotationConfirm:Button; private lateinit var rotationCancel:Button
 private lateinit var rotationGate:TextView
 private lateinit var host:EditText; private lateinit var blockPath:EditText; private lateinit var replacePath:EditText; private lateinit var body:EditText
 private lateinit var validation:TextView
 private lateinit var urlLog:Switch; private lateinit var urlLogView:TextView
  private val handler=Handler(Looper.getMainLooper())
  @Volatile private var suppressVpnSwitch=false
 private val tick=object:Runnable { override fun run() { renderStatus(); renderVpnStatus(); renderUrlLog(); renderRotation(); maybeProbe(); handler.postDelayed(this,1000) } }
 @Volatile private var pem:String?=null
 @Volatile private var rotationState=CaRotationState()
 @Volatile private var installedFingerprints:Set<String>?=null
 @Volatile private var probeInFlight=false
 @Volatile private var rotationBusy=false

 override fun onCreate(savedInstanceState:Bundle?) {
  super.onCreate(savedInstanceState)
  val layout=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(24,48,24,24) }
  layout.setOnApplyWindowInsetsListener { v,i -> val bars=i.getInsets(android.view.WindowInsets.Type.systemBars()); v.setPadding(24,bars.top+24,24,bars.bottom+24); i }
  layout.addView(TextView(this).apply { text="HTTPS inspection"; textSize=24f })
  status=TextView(this).apply { textSize=15f; setPadding(0,16,0,8) }; layout.addView(status)
  startStop=Button(this).apply { setOnClickListener { toggle() } }; layout.addView(startStop)
  layout.addView(TextView(this).apply { text="Standalone proxy requires an explicit client proxy; the separate inspection VPN captures TCP without client proxy settings. Both require CA trust. Supports HTTP/1.1 GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS, persistent connections, streamed uploads (up to 64 MiB) and streamed responses. HTTP/2 downstream and WebSocket upgrades are not supported. Non-DNS UDP/QUIC is blocked; browsers must fall back to TCP."; textSize=12f; setPadding(0,0,0,16) })
  layout.addView(TextView(this).apply { text="Certificate (CA)"; textSize=18f })
  fingerprint=TextView(this).apply { textSize=12f; setPadding(0,8,0,8) }; layout.addView(fingerprint)
  export=Button(this).apply { text="Export CA certificate (.crt)"; isAllCaps=false; setOnClickListener { exportCa() } }; layout.addView(export)
  layout.addView(TextView(this).apply { text="The CA signing key stays in app-private noBackupFilesDir storage and is never exported. Exporting the public certificate does not install or trust it."; textSize=11f; setPadding(0,0,0,16) })
  layout.addView(TextView(this).apply { text=INSTALL_TEXT; textSize=12f; setPadding(0,0,0,16) })
  rotationGate=TextView(this).apply { textSize=12f; setTextColor(Color.rgb(198,40,40)); setPadding(0,0,0,8); visibility=android.view.View.GONE }
  layout.addView(rotationGate)
  layout.addView(TextView(this).apply { text="Rotate CA (explicit, advanced)"; textSize=18f })
  rotationStatus=TextView(this).apply { textSize=12f; typeface=android.graphics.Typeface.MONOSPACE; setPadding(0,8,0,8) }
  layout.addView(rotationStatus)
  layout.addView(TextView(this).apply { text=ROTATION_TEXT; textSize=11f; setPadding(0,0,0,8) })
  rotationBegin=Button(this).apply { text="Begin CA rotation…"; isAllCaps=false; setOnClickListener { beginRotationFlow() } }
  layout.addView(rotationBegin)
  rotationConfirm=Button(this).apply { text="Old CA removed — delete the old key and generate the new CA"; isAllCaps=false; setOnClickListener { confirmRotationFlow() } }
  layout.addView(rotationConfirm)
  rotationCancel=Button(this).apply { text="Cancel rotation (keep current CA)"; isAllCaps=false; setOnClickListener { cancelRotationFlow() } }
  layout.addView(rotationCancel)
  layout.addView(TextView(this).apply { text="Full-route inspection VPN (opt-in)"; textSize=18f })
  layout.addView(TextView(this).apply { text=VPN_TEXT; textSize=12f; setPadding(0,0,0,8) })
  vpnSwitch=Switch(this).apply {
   textSize=14f; text="Inspect the device's default-route traffic through the VPN (off by default)"
   setOnCheckedChangeListener { _,on -> if(!suppressVpnSwitch) vpnToggle(on) }
  }
  layout.addView(vpnSwitch)
  vpnStatus=TextView(this).apply { textSize=12f; setPadding(0,8,0,16) }; layout.addView(vpnStatus)
  layout.addView(Button(this).apply { text="Open certificate/security settings"; isAllCaps=false; setOnClickListener {
   try { startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)) }
   catch(e:android.content.ActivityNotFoundException) { Toast.makeText(this@InspectionActivity,"Open Android Security settings manually",Toast.LENGTH_LONG).show() }
  } })
  layout.addView(TextView(this).apply { text="Local rule (one exact host)"; textSize=18f })
  host=field("Exact host, e.g. example.com — no scheme, port or wildcard",false)
  blockPath=field("Block path prefix, e.g. /ads — encoded path, segment prefix",false)
  replacePath=field("Replace path prefix, e.g. /ads — leave empty to block instead",false)
  body=field("Replacement body shown instead (required for replace)",true)
  listOf(host,blockPath,replacePath,body).forEach { layout.addView(it) }
  validation=TextView(this).apply { textSize=12f; setPadding(0,8,0,0) }; layout.addView(validation)
  layout.addView(Button(this).apply { text="Save rule"; isAllCaps=false; setOnClickListener { saveRule() } })
  layout.addView(TextView(this).apply { text="Applies when the proxy starts. If it is running, stop it and start again to apply."; textSize=11f; setPadding(0,0,0,16) })
  urlLog=Switch(this).apply { text="Inspected URL log (off by default)"; textSize=14f; isChecked=InspectionUrlLogPrefs.enabled(this@InspectionActivity); setOnCheckedChangeListener { _,on -> InspectionUrlLogPrefs.set(this@InspectionActivity,on); renderUrlLog() } }
  layout.addView(urlLog)
  urlLogView=TextView(this).apply { typeface=android.graphics.Typeface.MONOSPACE; textSize=11f; setPadding(0,8,0,8) }; layout.addView(urlLogView)
  setContentView(ScrollView(this).also { it.addView(layout) })
  loadRule(); loadCertificate()
  rotationState=CaRotationPrefs.load(this); installedFingerprints=null; renderRotation()
 }
 private fun field(hint:String,multiline:Boolean):EditText = EditText(this).apply {
  this.hint=hint; textSize=14f
  inputType=if(multiline) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
  if(multiline) minLines=2
 }
 private fun toggle() {
  if(CaRotation.isPending(rotationState)) {
   Toast.makeText(this,"Finish or cancel the pending CA rotation first — services must not run during rotation",Toast.LENGTH_LONG).show(); return
  }
  if(InspectionVpnService.active||InspectionVpnService.starting) {
   Toast.makeText(this,"Stop the inspection VPN before starting the standalone proxy",Toast.LENGTH_LONG).show(); return
  }
  if(InspectionService.active||InspectionService.starting)
   startService(Intent(this,InspectionService::class.java).setAction(InspectionService.ACTION_STOP))
  else startForegroundService(Intent(this,InspectionService::class.java).setAction(InspectionService.ACTION_START))
  renderStatus()
 }
 /** Full-VPN opt-in: on = request VPN permission, then start only after the user grants it;
  *  off = stop exactly the active full-route inspection service (DNS-only is untouched). */
 private fun vpnToggle(on:Boolean) {
  if(on && (rotationBusy || CaRotation.isPending(rotationState))) {
   Toast.makeText(this,"Finish or cancel CA rotation first",Toast.LENGTH_LONG).show(); renderVpnStatus(); return
  }
  InspectionVpnPrefs.set(this,on)
  if(on) {
   if(InspectionService.active||InspectionService.starting) {
    Toast.makeText(this,"Stop the standalone proxy before starting the inspection VPN",Toast.LENGTH_LONG).show()
    renderVpnStatus(); return
   }
   if(InspectionVpnService.active||InspectionVpnService.starting) return
   try {
    val intent=android.net.VpnService.prepare(this)
    if(intent!=null) startActivityForResult(intent,REQUEST_FULL_VPN)
    else startForegroundService(Intent(this,InspectionVpnService::class.java).setAction(InspectionVpnService.ACTION_START))
   } catch(e:Exception) {
    Toast.makeText(this,"Could not request VPN permission: ${e.message ?: e.javaClass.simpleName}",Toast.LENGTH_LONG).show()
   }
  } else if(InspectionVpnService.active||InspectionVpnService.starting) {
   startService(Intent(this,InspectionVpnService::class.java).setAction(InspectionVpnService.ACTION_STOP))
  }
  renderStatus()
 }
 private fun renderStatus() {
  val s=when {
   InspectionService.starting -> "◌ Starting local HTTPS inspection proxy…"
   InspectionService.active && InspectionService.listenPort>0 -> "● Running • listening on ${InspectionService.LISTEN_HOST}:${InspectionService.listenPort} • loopback only, not system-wide"
   else -> "○ ${InspectionService.message}"
  }
  status.text=s
  status.setTextColor(if(InspectionService.active) Color.rgb(46,125,50) else Color.DKGRAY)
  startStop.text=when { InspectionService.starting->"Starting…"; InspectionService.active->"Stop"; else->"Start" }
 }

 /** Full-VPN status mirror: switch reflects the service state, status text from the service. */
 private fun renderVpnStatus() {
  val on=InspectionVpnService.active||InspectionVpnService.starting
  suppressVpnSwitch=true; vpnSwitch.isChecked=on; suppressVpnSwitch=false
  vpnStatus.text=when {
   InspectionVpnService.starting -> "◌ Starting full-route inspection VPN…"
   InspectionVpnService.active -> "● ${InspectionVpnService.message}"
   else -> "○ ${InspectionVpnService.message}"
  }
  vpnStatus.setTextColor(if(InspectionVpnService.active) Color.rgb(46,125,50) else Color.DKGRAY)
 }

 /** CA load/fingerprint happen off the main thread; results are posted back here. */
 private fun loadCertificate() {
  Thread({
   val ca=try { InspectionCa.authority(this@InspectionActivity) } catch(_:Exception) { null }
   val fp=ca?.let { InspectionCa.fingerprintSha256(it.certificate()) }; val pem=ca?.certificatePem()
   val subject=ca?.subjectDistinguishedName()
   runOnUiThread { this.pem=pem; renderCertificate(fp,subject) }
  },"curtain-inspection-ca").start()
 }
 private fun renderCertificate(fp:String?,subject:String?) {
  fingerprint.text=when {
   fp==null -> "CA unavailable. An unreadable stored CA is never silently replaced."
   else -> "Subject: $subject\nSHA-256 fingerprint of this installation's CA:\n$fp"
  }
  // Export and new-install guidance are gated while a rotation is pending: the old root is on its
  // way out and (re)installing it would defeat the rotation.
  val gated=CaRotation.exportGated(rotationState)
  export.isEnabled=fp!=null && !gated
  rotationGate.visibility=if(gated) android.view.View.VISIBLE else android.view.View.GONE
  if(gated) rotationGate.text="CA rotation is pending — exporting and installing the CA certificate are blocked until the rotation is completed or cancelled."
 }
 private fun exportCa() {
  if(pem==null) return
  if(CaRotation.exportGated(rotationState)) {
   Toast.makeText(this,"Blocked while a CA rotation is pending — finish or cancel the rotation first",Toast.LENGTH_LONG).show(); return
  }
  startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT)
   .addCategory(Intent.CATEGORY_OPENABLE)
   .setType("application/x-x509-ca-cert")
   .putExtra(Intent.EXTRA_TITLE,"curtain-inspection-ca.crt"),2)
 }
 @Deprecated("Document picker callback") override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?) {
  super.onActivityResult(requestCode,resultCode,data)
  if(requestCode==REQUEST_FULL_VPN) {
   if(resultCode==RESULT_OK) {
    // Explicit start only after the user grants VPN permission.
    startForegroundService(Intent(this,InspectionVpnService::class.java).setAction(InspectionVpnService.ACTION_START))
   } else {
    InspectionVpnPrefs.set(this,false)
    Toast.makeText(this,"VPN permission not granted — full-route inspection stays off",Toast.LENGTH_LONG).show()
   }
   renderVpnStatus(); return
  }
  if(requestCode==2 && resultCode==RESULT_OK && data?.data!=null) {
   if(rotationBusy || CaRotation.exportGated(rotationState)) { Toast.makeText(this,"Export blocked while CA rotation is pending",Toast.LENGTH_LONG).show(); return }
   val text=pem
   if(text==null) { Toast.makeText(this,"No CA certificate available",Toast.LENGTH_SHORT).show(); return }
   try {
    // Public certificate PEM only; the signing key never leaves app-private storage.
    contentResolver.openOutputStream(data!!.data!!)?.use { it.write(text.toByteArray(Charsets.US_ASCII)) } ?: error("no output stream")
    Toast.makeText(this,"Exported the public CA only — install it via Settings (see instructions); exporting does not trust it",Toast.LENGTH_LONG).show()
   } catch(e:Exception) { Toast.makeText(this,"Export failed: ${e.message ?: e.javaClass.simpleName}",Toast.LENGTH_LONG).show() }
  }
 }
 // ---- explicit CA rotation -------------------------------------------------------------------

 private fun servicesRunning()=InspectionService.active||InspectionService.starting||InspectionVpnService.active||InspectionVpnService.starting

 private fun saveRotation() { CaRotationPrefs.save(this,rotationState); renderRotation() }

 /** Reads Android's trusted-certificate store off the main thread, only while a rotation is
  *  pending and only one probe at a time. null = unreadable → fail closed. */
 private fun maybeProbe() {
  if(!CaRotation.isPending(rotationState)||probeInFlight) return
  probeInFlight=true
  Thread({
   val fingerprints=AndroidCaStoreProbe.installedFingerprints()
   runOnUiThread { installedFingerprints=fingerprints; probeInFlight=false; renderRotation() }
  },"curtain-ca-removal-probe").start()
 }

 /** Step 1: record the exact old identity (subject + fingerprint) and enter the pending phase.
  *  Refuses while any inspection service is running: a running proxy holds the old authority and
  *  rotation must not run during services. Generates nothing. */
 private fun beginRotationFlow() {
  if(rotationBusy) return
  if(CaRotation.isPending(rotationState)) return
  if(servicesRunning()) {
   Toast.makeText(this,"Stop the inspection proxy/VPN before rotating the CA",Toast.LENGTH_LONG).show(); return
  }
  rotationBegin.isEnabled=false
  Thread({
   try {
    val ca=InspectionCa.authority(this@InspectionActivity)
    val subject=ca.subjectDistinguishedName(); val fp=ca.fingerprintSha256()
    runOnUiThread { rotationState=CaRotation.begin(rotationState,subject,fp,System.currentTimeMillis()); saveRotation() }
   } catch(e:Exception) {
    runOnUiThread {
     rotationBegin.isEnabled=true
     Toast.makeText(this@InspectionActivity,"Cannot begin rotation: ${e.message ?: e.javaClass.simpleName}",Toast.LENGTH_LONG).show()
    }
   }
  },"curtain-ca-rotation-begin").start()
 }

 /** Step 3 (only offered after the removal probe reports the old fingerprint absent): explicit
  *  user confirmation that deletes the stored old key on an exact fingerprint match, then builds
  *  the replacement authority — which is what generates the new root — and records both exact
  *  identities. Re-checks services; discards the activity's cached authority PEM. */
 private fun confirmRotationFlow() {
  val state=rotationState
  if(!CaRotation.isPending(state)) return
  if(CaRotation.oldCaAbsent(state,installedFingerprints)!=true) {
   Toast.makeText(this,"Blocked: the old CA is still present (or the store could not be read)",Toast.LENGTH_LONG).show(); return
  }
  if(servicesRunning()) {
   Toast.makeText(this,"A service started during the rotation — stop it and retry",Toast.LENGTH_LONG).show(); return
  }
  if(rotationBusy) return
  rotationBusy=true; renderRotation()
  Thread({
   try {
    val ca=InspectionCa.authority(this@InspectionActivity)
    val current=CaRotation.canonicalFingerprint(ca.fingerprintSha256())
    val expected=CaRotation.canonicalFingerprint(state.oldFingerprint)
    if(current!=expected) throw IllegalStateException("the installed CA changed — rotation aborted, nothing deleted")
    // Probe again at the mutation boundary, never rely on the cached UI observation.
    val replacement=ca.rotateAfterRemoval(state.oldFingerprint,true) { AndroidCaStoreProbe.installedFingerprints() }
    runOnUiThread {
     rotationState=CaRotation.completeGeneration(state,replacement.subjectDistinguishedName(),
      replacement.fingerprintSha256(),System.currentTimeMillis())
     rotationBusy=false; pem=null; loadCertificate(); saveRotation()
     Toast.makeText(this@InspectionActivity,"New CA generated — export and install the new certificate",Toast.LENGTH_LONG).show()
    }
   } catch(e:Exception) {
    runOnUiThread {
     rotationBusy=false; renderRotation()
     Toast.makeText(this@InspectionActivity,"Rotation failed, old state kept: ${e.message ?: e.javaClass.simpleName}",Toast.LENGTH_LONG).show()
    }
   }
  },"curtain-ca-rotation-confirm").start()
 }

 private fun cancelRotationFlow() {
  if(rotationBusy) return
  if(!CaRotation.isPending(rotationState)) return
  rotationState=CaRotation.cancel(rotationState)
  saveRotation()
  Toast.makeText(this,"Rotation cancelled — the current CA is unchanged",Toast.LENGTH_SHORT).show()
 }

 /** Pending rotation UI: exact old subject/fingerprint, live removal status, and gates. */
 private fun renderRotation() {
  val state=rotationState
  val pending=CaRotation.isPending(state)
  rotationStatus.text=when {
   pending -> {
    val proof=when(CaRotation.oldCaAbsent(state,installedFingerprints)) {
     true -> "Removal check: the old CA is no longer in Android's certificate store as seen by this app. If you confirm it is gone in Settings, you may proceed."
     false -> "Old CA is still present. Remove it in Settings → Security → Encryption & credentials → Trusted credentials → User, then return here."
     null -> "Removal check: unreadable (unknown) — generating a new CA stays blocked until the store can be read."
    }
    "ROTATION PENDING\nOld CA:\n${CaRotation.displayOld(state)}\n$proof"
   }
   CaRotation.hasCompletedRecord(state) -> "Last rotation completed:\nOLD CA\n${CaRotation.displayOld(state)}\nNEW CA\n${CaRotation.displayNew(state)}"
   else -> "No rotation in progress. The current CA stays installed and working until you explicitly begin a rotation."
  }
  rotationBegin.isEnabled=!pending&&!probeInFlight&&!rotationBusy&&!servicesRunning()
  rotationConfirm.isEnabled=pending&&CaRotation.oldCaAbsent(state,installedFingerprints)==true&&!servicesRunning()&&!rotationBusy
  rotationCancel.isEnabled=pending&&!rotationBusy
  export.isEnabled=pem!=null&&!pending&&!rotationBusy
  rotationGate.visibility=if(pending) android.view.View.VISIBLE else android.view.View.GONE
  if(pending) rotationGate.text="Rotation pending: export/new CA installation stays blocked until the old CA is removed and replacement is confirmed."
 }

 private fun loadRule() {
  val s=InspectionSettingsPrefs.load(this)
  host.setText(s.host); blockPath.setText(s.blockPathPrefix); replacePath.setText(s.replacePathPrefix); body.setText(s.replacementBody)
 }
 private fun saveRule() {
  val s=InspectionSettings.sanitized(InspectionSettings(host.text.toString(),blockPath.text.toString(),replacePath.text.toString(),body.text.toString()))
  val problem=s.validate()
  if(problem!=null) { validation.setTextColor(Color.rgb(198,40,40)); validation.text="Not saved — $problem"; return }
  InspectionSettingsPrefs.save(this,s)
  validation.setTextColor(Color.rgb(46,125,50))
  validation.text="Saved — ${s.ruleText()}."+(if(InspectionService.active||InspectionService.starting) " Stop and start the proxy to apply." else " Applies on next start.")
 }
 private fun renderUrlLog() {
  val log=InspectionUrlLogUi.log
  val on=InspectionUrlLogPrefs.enabled(this)
  urlLogView.text=when {
   log!=null && log.enabled -> log.recent(200).joinToString("\n") { "${it.url} • ${it.action} • ${it.status}" }.ifEmpty { "URL log on; no inspected URLs yet." }
   on -> "URL log recording is on; no inspection engine is running."
   else -> "URL log is off. Nothing is recorded."
  }
 }
 override fun onResume() { super.onResume(); rotationState=CaRotationPrefs.load(this); renderRotation(); loadCertificate(); handler.post(tick) }
 override fun onPause() { handler.removeCallbacks(tick); super.onPause() }

 companion object {
  const val REQUEST_FULL_VPN=3
  private val INSTALL_TEXT="""Make Android trust this CA (modern Android does not let apps install it directly):
1. Export the CA certificate above.
2. Open Android Settings → Security & privacy (or Security) → More security settings → Encryption & credentials → Install a certificate → CA certificate (names vary by device).
3. Pick the exported curtain-inspection-ca.crt and confirm the warning. Android warns for good reason — a CA can sign for any site — but this one is used only by this app's local proxy on this device.
4. Start either the separate inspection VPN (no client proxy setting needed) or the standalone proxy (configure its shown 127.0.0.1:<port> in your client).
Use the same CA after restarts and app updates; exporting again does not create another CA. Apps that reject user CAs or pin certificates may fail. Bodies are never logged; the full URL/action log is opt-in and cleared when disabled."""
  private val VPN_TEXT="""Opt-in and off by default. When enabled and started, the device's default IPv4+IPv6 traffic is routed through this app's VPN: TCP connections (including TLS) are inspected using this installation's CA — only apps that trust this CA are decrypted, apps that pin certificates fail visibly. DNS answers are filtered with the signed experimental blocklist index when it is ready; if the index is not ready, DNS is relayed unfiltered and the status says so explicitly. Non-DNS UDP is blocked. The DNS-only filter and the loopback proxy above remain separate options that keep working unchanged."""
  private val ROTATION_TEXT="""Keep this CA for normal restarts and updates. Rotate only when you explicitly want a replacement:
1. Stop inspection and tap Begin. No new CA is generated; export is blocked.
2. In Android Settings → Security → Encryption & credentials → Trusted credentials → User, remove the CA matching the old subject and SHA-256 fingerprint below.
3. Return here and confirm removal. The app checks the store again before atomically replacing its old private key. Export/install the new certificate only afterwards.
Android reserves automatic CA removal for managed device/profile owners and their delegates. This app uses ordinary user-confirmed Settings, not device administration. Cancel keeps the existing CA unchanged."""
 }
}

object InspectionSettingsPrefs {
 private const val FILE="inspection_rules"
 fun load(c:Context)=InspectionSettings.fromPrefs(c.getSharedPreferences(FILE,Context.MODE_PRIVATE).all)
 fun save(c:Context,s:InspectionSettings) {
  val e=c.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit(); e.clear()
  InspectionSettings.toPrefs(s).forEach { (k,v) -> e.putString(k,v) }
  e.apply()
 }
}

object InspectionUrlLogPrefs {
 private const val FILE="inspection_logging"; private const val KEY="inspection_url_log"
 fun enabled(c:Context)=c.getSharedPreferences(FILE,Context.MODE_PRIVATE).getBoolean(KEY,false)
 fun set(c:Context,on:Boolean) {
  c.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit().putBoolean(KEY,on).apply()
  InspectionUrlLogUi.log?.setEnabled(on)   // core InspectionLog clears itself when disabled
 }
}

/** Persists the CA rotation state machine (org.curtain.dns.inspection.CaRotationState). A rotation
 *  is explicit and survives process death: pending means the user must remove the old CA in
 *  Android Settings and the app gates export/new install until removal is confirmed or the user
 *  cancels. Corrupt persisted state falls back to idle (never permanently gated). */
object CaRotationPrefs {
 private const val FILE="inspection_ca_rotation"
 fun load(c:Context):CaRotationState=CaRotation.fromPrefs(c.getSharedPreferences(FILE,Context.MODE_PRIVATE).all)
 fun save(c:Context,s:CaRotationState) {
  val e=c.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit(); e.clear()
  CaRotation.toPrefs(s).forEach { (k,v) -> e.putString(k,v) }
  check(e.commit()) { "Could not persist CA rotation state" }
 }
}

/** Records the full-route inspection VPN opt-in (default off). It never starts the VPN by
 *  itself: starting is always an explicit user action with VPN permission granted. */
object InspectionVpnPrefs {
 private const val FILE="inspection_vpn"; private const val KEY="inspection_full_route_vpn"
 fun enabled(c:Context)=c.getSharedPreferences(FILE,Context.MODE_PRIVATE).getBoolean(KEY,false)
 fun set(c:Context,on:Boolean) { c.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit().putBoolean(KEY,on).apply() }
}

/** UI handle to the core inspected-URL log (org.curtain.dns.inspection.InspectionLog: bounded
 *  in-memory, separate from the DNS query log, no bodies, disabled clears). The service assigns
 *  [log] while a proxy session is being started; null when the proxy is not running. */
object InspectionUrlLogUi {
 @Volatile var log:InspectionLog?=null
}
