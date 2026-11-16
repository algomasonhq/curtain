package org.curtain.dns.inspection

/** Full inspected https URL and action only. Request/response bodies are never stored here. */
data class InspectionEntry(val ts:Long,val url:String,val action:InspectionAction,val status:Int)

/**
 * Separate bounded in-memory inspected-URL log. Off by default; disabling clears it. The optional
 * callback runs only while enabled and never receives bodies or key material.
 */
class InspectionLog(
 private val capacity:Int=512,
 private val callback:((InspectionEntry)->Unit)?=null
) {
 init { require(capacity in 1..100_000) { "capacity must be 1..100000" } }

 @Volatile var enabled:Boolean=false
  private set

 private val lock=Any()
 private val ring=arrayOfNulls<InspectionEntry>(capacity)
 private var next=0
 private var size=0

 fun setEnabled(on:Boolean) {
  if(on) { synchronized(lock) { enabled=true }; return }
  synchronized(lock) {
   enabled=false
   ring.fill(null); next=0; size=0
  }
 }

 fun record(entry:InspectionEntry) {
  if(!enabled) return
  synchronized(lock) {
   if(!enabled) return
   ring[next]=entry
   next=(next+1)%capacity
   if(size<capacity) size++
  }
  try { callback?.invoke(entry) } catch(_:Exception) {}
 }

 fun clear() {
  synchronized(lock) { ring.fill(null); next=0; size=0 }
 }

 /** Newest first, bounded by both [limit] and [capacity]. */
 fun recent(limit:Int=capacity):List<InspectionEntry> {
  if(limit<=0) return emptyList()
  return synchronized(lock) {
   val count=minOf(limit,size,capacity)
   val result=ArrayList<InspectionEntry>(count)
   var i=0
   while(i<count) {
    val entry=ring[(next-1-i+2*capacity)%capacity]
    if(entry==null) break
    result.add(entry); i++
   }
   result
  }
 }
}
