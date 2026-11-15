package org.curtain.dns
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView

class MainActivity: Activity() {
 private lateinit var status:TextView; private lateinit var button:Button; private lateinit var update:Button
 private val handler=Handler(Looper.getMainLooper())
 private val refresh=object:Runnable { override fun run() { render(); handler.postDelayed(this,400) } }
 override fun onCreate(savedInstanceState:Bundle?) {
  super.onCreate(savedInstanceState)
  val layout=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(32,48,32,24) }
  layout.setOnApplyWindowInsetsListener { v,i -> val bars=i.getInsets(android.view.WindowInsets.Type.systemBars()); v.setPadding(32,bars.top+24,32,bars.bottom+24); i }
  layout.addView(TextView(this).apply { text="Curtain"; textSize=30f })
  status=TextView(this).apply { textSize=18f; setPadding(0,24,0,24) }; layout.addView(status)
  button=Button(this).apply { text="Start"; setOnClickListener { if(DnsVpnService.active || DnsVpnService.starting) startService(Intent(this@MainActivity,DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)) else consent() } }; layout.addView(button)
  update=Button(this).apply { text="Update now / Retry"; setOnClickListener { IndexStore.requestUpdate(this@MainActivity) } }; layout.addView(update)
  layout.addView(Switch(this).apply { text="Query log (debug, in memory)"; isChecked=QueryLogPrefs.enabled(this@MainActivity); setOnCheckedChangeListener { _,on -> QueryLogPrefs.set(this@MainActivity,on) } })
  layout.addView(Button(this).apply { text="View query log"; setOnClickListener { startActivity(Intent(this@MainActivity,QueryLogActivity::class.java)) } })
  layout.addView(TextView(this).apply { text="DNS-only private test • Android 15+\n\nDownloads the full experimental aggressive rules from cdn.clapbox.net (about 115 MiB). No rules bundled or fake fallback. First-run Start is disabled until signature, hash and all records verify. Updates check roughly every 48 hours when Android permits; Update now retries. A running session keeps its original rules until explicit stop/start. False positives expected; source licenses pending review. Not for redistribution.\n\nFilters ordinary system UDP DNS through a local VPN. Allowed DNS goes directly to Cloudflare 1.1.1.1, not a Curtain backend. No account or syncing. Optional Query log (off by default) keeps recent DNS names in memory only; turning it off clears it.\n\nCustom / encrypted DNS and direct IPs can bypass this. IPv4 and IPv6 web traffic stays on the normal network. No HTTPS inspection, certificates, URL filtering, SafeSearch or YouTube restriction. Certificate pinning is unchanged.\n\nUDP DNS only: TCP fallback / oversized answers are not supported. Strict Private DNS may prevent resolution; disable it for this private test. This is not complete protection."; textSize=15f })
  val scroll=android.widget.ScrollView(this); scroll.addView(layout); setContentView(scroll)
  IndexStore.load(this)
 }
 private fun consent() { if(IndexStore.index==null) return; val intent=VpnService.prepare(this); if(intent!=null) startActivityForResult(intent,1) else startVpn() }
 private fun startVpn() { if(IndexStore.index!=null) startForegroundService(Intent(this,DnsVpnService::class.java)) }
 @Deprecated("Platform consent callback") override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?) { super.onActivityResult(requestCode,resultCode,data); if(requestCode==1 && resultCode==RESULT_OK) startVpn() }
 private fun render() {
  val view=UpdateUi.render(IndexStore.snapshot,DnsVpnService.runningVersion,DnsVpnService.starting,IndexStore.busy || IndexStore.queued,IndexStore.progress,IndexStore.error,DnsVpnService.message)
  status.text=view.text
  button.isEnabled=view.canStart; button.text=if(DnsVpnService.active || DnsVpnService.starting) "Stop" else "Start"
  update.isEnabled=view.canUpdate; update.text=if(IndexStore.error!=null) "Retry update" else "Update now"
 }
 override fun onResume() { super.onResume(); handler.post(refresh) }
 override fun onPause() { handler.removeCallbacks(refresh); super.onPause() }
}
