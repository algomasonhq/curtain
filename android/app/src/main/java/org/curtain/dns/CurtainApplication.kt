package org.curtain.dns
import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.work.Configuration
import java.io.File
/** WorkManager is initialized on demand by the background loader, not a startup provider. */
class CurtainApplication:Application(),Configuration.Provider {
 override val workManagerConfiguration:Configuration
  get()=Configuration.Builder().setMinimumLoggingLevel(android.util.Log.WARN).build()
 override fun onCreate() {
  super.onCreate()
  // Debug (debuggable) builds only: JSON-lines dump readable with run-as, written only while the toggle is on.
  val dump=if(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE!=0) JsonlFile(File(filesDir,"querylog.jsonl")) else null
  QueryLog.shared=QueryLog(2000,{ android.util.Log.i("CurtainDNS",it) },{ dump?.append(it) },{ dump?.delete() })
  val on=QueryLogPrefs.enabled(this)
  QueryLog.shared.setEnabled(on)   // toggle off (default) also removes any stale dump
 }
}
object QueryLogPrefs {
 private const val FILE="curtain"; private const val KEY="query_log"
 fun enabled(c:Context)=c.getSharedPreferences(FILE,Context.MODE_PRIVATE).getBoolean(KEY,false)
 fun set(c:Context,on:Boolean) { c.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit().putBoolean(KEY,on).apply(); QueryLog.shared.setEnabled(on) }
}
