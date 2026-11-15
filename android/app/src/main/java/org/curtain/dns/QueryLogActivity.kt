package org.curtain.dns
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.TextWatcher
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** In-memory DNS query log viewer (newest 200, auto-refresh ~1s). Nothing is stored or sent from here except explicit Copy/Share. */
class QueryLogActivity:Activity() {
 private lateinit var state:Switch; private lateinit var summary:TextView; private lateinit var empty:TextView; private lateinit var list:ListView; private lateinit var search:EditText
 private val buttons=HashMap<QueryFilter,Button>()
 private var filter=QueryFilter.ALL
 private var shown:List<QueryEntry> = emptyList()
 private val fmt=SimpleDateFormat("HH:mm:ss.SSS",Locale.US)
 private val handler=Handler(Looper.getMainLooper())
 private val tick=object:Runnable { override fun run() { render(); handler.postDelayed(this,1000) } }
 private var updating=false
 private val adapter=object:BaseAdapter() {
  override fun getCount()=shown.size
  override fun getItem(i:Int)=shown[i]
  override fun getItemId(i:Int)=i.toLong()
  override fun getView(i:Int,v:View?,p:ViewGroup?):View {
   val t=(v as? TextView) ?: TextView(this@QueryLogActivity).apply { typeface=Typeface.MONOSPACE; textSize=12f; setPadding(8,6,8,6) }
   t.text=row(shown[i]); return t
  }
 }
 private fun actionColor(a:QueryAction)=when(a) { QueryAction.BLOCKED->Color.rgb(198,40,40); QueryAction.ALLOWED->Color.rgb(46,125,50); QueryAction.UPSTREAM_ERROR->Color.rgb(230,126,0); QueryAction.OVERRIDDEN->Color.rgb(21,101,192) }
 private fun row(e:QueryEntry):CharSequence {
  val sb=SpannableStringBuilder("${fmt.format(Date(e.ts))}  ")
  val start=sb.length; sb.append(QueryExport.label(e.action).padEnd(7)); sb.setSpan(ForegroundColorSpan(actionColor(e.action)),start,sb.length,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE); sb.setSpan(StyleSpan(Typeface.BOLD),start,sb.length,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
  sb.append(" ${QueryTypes.name(e.qtype).padEnd(5)} ")
  val d=sb.length; sb.append(e.host.take(120)); sb.setSpan(StyleSpan(Typeface.BOLD),d,sb.length,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
  sb.append("\n    rcode=${if(e.rcode<0) "none" else e.rcode.toString()} • ${e.latencyMs} ms"+(e.rule?.let { " • $it rule" } ?: ""))
  return sb
 }
 override fun onCreate(savedInstanceState:Bundle?) {
  super.onCreate(savedInstanceState)
  val layout=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(24,48,24,24) }
  layout.setOnApplyWindowInsetsListener { v,i -> val bars=i.getInsets(android.view.WindowInsets.Type.systemBars()); v.setPadding(24,bars.top+24,24,bars.bottom+24); i }
  layout.addView(TextView(this).apply { text="DNS query log"; textSize=24f })
  state=Switch(this).apply { text="Query log"; textSize=16f; isChecked=QueryLog.shared.enabled; setOnCheckedChangeListener { _,on -> if(!updating) { QueryLogPrefs.set(this@QueryLogActivity,on); render() } } }
  layout.addView(state)
  summary=TextView(this).apply { textSize=15f; setPadding(0,8,0,8) }; layout.addView(summary)
  val chips=LinearLayout(this).apply { orientation=LinearLayout.HORIZONTAL }
  fun chip(label:String,f:QueryFilter) { val b=Button(this).apply { text=label; isAllCaps=false; setOnClickListener { filter=f; render() } }; buttons[f]=b; chips.addView(b,LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f)) }
  chip("All",QueryFilter.ALL); chip("Blocked",QueryFilter.BLOCKED); chip("Allowed",QueryFilter.ALLOWED); chip("Errors",QueryFilter.ERRORS)
  layout.addView(chips)
  search=EditText(this).apply { hint="Search domain"; setSingleLine(); inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS; addTextChangedListener(object:TextWatcher { override fun afterTextChanged(s:Editable?) { render() }; override fun beforeTextChanged(s:CharSequence?,a:Int,b:Int,c:Int) {}; override fun onTextChanged(s:CharSequence?,a:Int,b:Int,c:Int) {} }) }
  layout.addView(search)
  val actions=LinearLayout(this).apply { orientation=LinearLayout.HORIZONTAL }
  fun action(label:String,f:()->Unit) { actions.addView(Button(this).apply { text=label; isAllCaps=false; setOnClickListener { f() } },LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f)) }
  action("Refresh") { render() }; action("Clear") { QueryLog.shared.clear(); render() }; action("Copy") { copy() }; action("Share") { share() }
  layout.addView(actions)
  empty=TextView(this).apply { textSize=16f; setPadding(16,48,16,16); gravity=android.view.Gravity.CENTER }
  list=ListView(this).apply { adapter=this@QueryLogActivity.adapter; emptyView=empty; divider=null }
  layout.addView(list,LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,1f)); layout.addView(empty,LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,1f))
  layout.addView(TextView(this).apply { text="DNS names only, in memory (last 2000). Cannot see URLs, paths or HTTPS contents. Apps using DoH/DoT/Private DNS bypass the VPN resolver and do not appear."; textSize=11f; setPadding(0,8,0,0) })
  setContentView(layout)
 }
 private fun copy() {
  if(shown.isEmpty()) { Toast.makeText(this,"Nothing to copy",Toast.LENGTH_SHORT).show(); return }
  getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Curtain DNS query log",QueryExport.text(shown)))
  Toast.makeText(this,"Copied ${shown.size} entries",Toast.LENGTH_SHORT).show()
 }
 private fun share() {
  if(shown.isEmpty()) { Toast.makeText(this,"Nothing to share",Toast.LENGTH_SHORT).show(); return }
  startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_SUBJECT,"Curtain DNS query log").putExtra(Intent.EXTRA_TEXT,QueryExport.text(shown)),"Share visible entries"))
 }
 override fun onResume() { super.onResume(); handler.post(tick) }
 override fun onPause() { handler.removeCallbacks(tick); super.onPause() }
 private fun render() {
  val log=QueryLog.shared; val c=log.counts(); val on=log.enabled
  if(state.isChecked!=on) { updating=true; state.isChecked=on; updating=false }
  summary.text=(if(on) "● ON — recording DNS queries" else "○ OFF — nothing is recorded")+"\n${c.total} total • ${c.blocked} blocked • ${c.allowed} allowed • ${c.errors} errors (since cleared)"
  summary.setTextColor(if(on) Color.rgb(46,125,50) else Color.DKGRAY)
  buttons.forEach { (f,b) -> b.setTypeface(null,if(f==filter) Typeface.BOLD else Typeface.NORMAL); b.alpha=if(f==filter) 1f else 0.6f }
  shown=log.recent(filter,200,search.text.toString())
  adapter.notifyDataSetChanged()
  empty.text=when {
   !on -> "Query log is off.\nTurn on Query log, then browse."
   c.total==0L -> "Nothing recorded yet.\nStart Curtain's VPN and browse; queries appear here."
   else -> "No entries match this filter/search."
  }
 }
}
