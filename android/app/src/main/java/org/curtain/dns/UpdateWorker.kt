package org.curtain.dns
import android.content.Context
import androidx.work.*
import java.util.concurrent.TimeUnit

class UpdateWorker(context:Context,parameters:WorkerParameters):Worker(context,parameters) {
 override fun doWork():Result = try { if(IndexStore.updateBlocking(applicationContext)) Result.success() else Result.retry() } catch(_:Exception) { Result.retry() }
 companion object {
  private fun constraints()=Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).setRequiresStorageNotLow(true).build()
  fun schedule(context:Context) {
   val work=PeriodicWorkRequest.Builder(UpdateWorker::class.java,48,TimeUnit.HOURS).setInitialDelay(48,TimeUnit.HOURS).setConstraints(constraints()).setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.MINUTES).build()
   WorkManager.getInstance(context).enqueueUniquePeriodicWork("curtain-rules-48h",ExistingPeriodicWorkPolicy.KEEP,work)
  }
  fun request(context:Context) {
   val work=OneTimeWorkRequest.Builder(UpdateWorker::class.java).setConstraints(constraints()).setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.MINUTES).build()
   WorkManager.getInstance(context).enqueueUniqueWork("curtain-rules-manual",ExistingWorkPolicy.REPLACE,work)
  }
 }
}
