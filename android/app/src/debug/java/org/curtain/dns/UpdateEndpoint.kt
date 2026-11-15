package org.curtain.dns
import java.net.URI
/** Only instrumentation in this private debug build can set an in-memory loopback fixture base. */
object UpdateEndpoint {
 @Volatile var fixtureBase:String?=null
 val base get()=fixtureBase ?: UpdateTrust.BASE
 fun allowed(base:String):Boolean {
  if(base==UpdateTrust.BASE) return true
  val uri=URI(base)
  return uri.scheme=="http" && uri.host in setOf("127.0.0.1","10.0.2.2") && uri.port in 1..65535 && uri.rawPath=="/curtain/" && uri.userInfo==null && uri.query==null && uri.fragment==null
 }
}
