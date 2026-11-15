package org.curtain.dns
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/** No redirects, ambient credentials or user-selected hosts; deadline and bounded reads. */
class CdnClient(private val base:String=UpdateEndpoint.base) {
 init { require(UpdateEndpoint.allowed(base)) { "Unapproved update base" } }
 val manifestUrl get()=base+"version.json"
 private fun open(path:String,maximum:Long,deadline:Long):InputStream {
  val connection=URL(base+path).openConnection() as HttpURLConnection
  connection.instanceFollowRedirects=false; connection.connectTimeout=10000; connection.readTimeout=15000
  connection.useCaches=false; connection.setRequestProperty("Accept-Encoding","identity")
  try {
   if(connection.responseCode!=200) throw IOException("CDN HTTP ${connection.responseCode}")
   if(connection.contentLengthLong>maximum) throw IOException("CDN response exceeds size limit")
   if(connection.contentEncoding!=null && connection.contentEncoding!="identity") throw IOException("Unexpected content encoding")
   return object:FilterInputStream(connection.inputStream) {
    private var received=0L
    private fun checkCount(n:Int):Int {
     if(System.nanoTime()>deadline) throw IOException("Update deadline exceeded")
     if(n>0) received+=n
     if(received>maximum) throw IOException("CDN response exceeds size limit")
     return n
    }
    override fun read():Int { val n=super.read(); checkCount(if(n<0) -1 else 1); return n }
    override fun read(b:ByteArray,off:Int,len:Int):Int=checkCount(`in`.read(b,off,len))
    override fun close() { try { super.close() } finally { connection.disconnect() } }
   }
  } catch(e:Exception) { connection.disconnect(); throw e }
 }
 fun update(engine:UpdateEngine,progress:(Long,Long)->Unit={_,_->}):IndexSnapshot {
  val deadline=System.nanoTime()+TimeUnit.MINUTES.toNanos(15)
  val manifest=open("version.json",UpdateManifest.MAX_MANIFEST.toLong(),deadline).use { it.readBytes().toString(Charsets.UTF_8) }
  return engine.update(manifest,{ m -> open(m.file,m.size,deadline) },progress)
 }
}
