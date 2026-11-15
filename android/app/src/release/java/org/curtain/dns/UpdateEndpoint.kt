package org.curtain.dns
object UpdateEndpoint {
 val base get()=UpdateTrust.BASE
 fun allowed(base:String)=base==UpdateTrust.BASE
}
