package org.curtain.dns
import android.content.Context
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.locks.ReentrantLock

/** One background operation at a time. A failed check never clears the last verified snapshot. */
object IndexStore {
 @Volatile var snapshot:IndexSnapshot?=null; private set
 val index get()=snapshot?.index
 @Volatile var error:String?=null; private set
 @Volatile var busy=false; private set
 @Volatile var queued=false; private set
 @Volatile var progress="Checking stored rules…"; private set
 private val lock=ReentrantLock()
 private val loader=Executors.newSingleThreadExecutor()
 private var initialized=false
 private var engine:UpdateEngine?=null
 private fun initialize(context:Context) {
  if(initialized) return
  engine=UpdateEngine(File(context.applicationContext.noBackupFilesDir,"rules"),UpdateTrust.key)
  try { snapshot=engine!!.restore() } catch(e:Exception) { error="Stored index rejected: ${e.message?.take(120)}" }
  initialized=true
 }
 fun load(context:Context) {
  val app=context.applicationContext
  loader.execute {
   lock.lock()
   try { busy=true; initialize(app) } finally { busy=false; lock.unlock() }
   UpdateWorker.schedule(app)
   if(snapshot==null && error==null) requestUpdate(app)
  }
 }
 fun requestUpdate(context:Context) {
  if(busy) return
  queued=true; progress="Update queued; waiting for network / scheduler…"
  UpdateWorker.request(context.applicationContext)
 }
 /** False means another initializer/updater owns the operation; WorkManager should defer. */
 fun updateBlocking(context:Context):Boolean {
  if(!lock.tryLock()) return false
  try {
   busy=true; queued=false; error=null; progress="Checking signed CDN manifest…"
   initialize(context)
   val result=CdnClient().update(engine!!) { n,total ->
    progress=if(n==total) "Download complete; verifying hash and every rule…" else "Downloading ${n/(1024*1024)} / ${(total+1048575)/1048576} MiB…"
   }
   snapshot=result; error=null; progress="Rules v${result.version} verified"
   return true
  } catch(e:Exception) { error=(e.message ?: e.javaClass.simpleName).take(180); throw e }
  finally { busy=false; queued=false; lock.unlock() }
 }
}
