package org.curtain.dns
/** Strong reference keeps the original mapping alive until all session workers finish. */
class FilterSession(private val snapshot:IndexSnapshot) {
 val version get()=snapshot.version
 fun blocked(host:String)=snapshot.index.blocked(host)
 fun blockRule(host:String)=snapshot.index.blockRule(host)
}
data class UpdateUi(val text:String,val canStart:Boolean,val canUpdate:Boolean) {
 companion object {
  fun render(snapshot:IndexSnapshot?,runningVersion:Long?,starting:Boolean,busy:Boolean,progress:String,error:String?,vpnMessage:String):UpdateUi {
   val state=when {
    runningVersion!=null -> "Running rules v$runningVersion • DNS-only VPN"
    starting -> "Starting DNS-only VPN…"
    snapshot!=null -> "$vpnMessage\nReady rules v${snapshot.version} • ${snapshot.index.count} domains"
    else -> "Index unavailable • Start disabled"
   }
   val pending=if(runningVersion!=null && snapshot!=null && runningVersion!=snapshot.version) "\nRules v${snapshot.version} ready; apply on next explicit stop/start." else ""
   val detail=if(busy) "\n$progress" else if(error!=null) "\nUpdate failed: $error\nUpdate now / Retry. Existing verified rules, if any, remain usable offline." else ""
   return UpdateUi(state+pending+detail,snapshot!=null || runningVersion!=null || starting,!busy)
  }
 }
}
