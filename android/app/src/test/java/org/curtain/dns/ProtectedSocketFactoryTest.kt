package org.curtain.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket

class ProtectedSocketFactoryTest {
 @Test fun protectsBeforeConnect() {
  val listener=ServerSocket(0,1,InetAddress.getLoopbackAddress())
  listener.use {
   var protected=false
   val factory=ProtectedSocketFactory { socket ->
    assertFalse(socket.isConnected); assertTrue("Android protect requires a materialized fd",socket.isBound); protected=true; true
   }
   factory.createSocket(InetAddress.getLoopbackAddress(),listener.localPort).use { assertTrue(protected); assertTrue(it.isConnected) }
   listener.accept().close()
  }
 }
 @Test fun failedProtectionClosesSocket() {
  var created:Socket?=null
  val factory=ProtectedSocketFactory { created=it; false }
  try { factory.createSocket(); fail("must reject failed protection") } catch(_:IOException) {}
  assertTrue(created!!.isClosed)
 }
 @Test fun failedConnectClosesProtectedSocket() {
  val port=ServerSocket(0).use { it.localPort }
  var created:Socket?=null
  val factory=ProtectedSocketFactory { created=it; true }
  try { factory.createSocket(InetAddress.getLoopbackAddress(),port); fail("closed port connected") } catch(_:IOException) {}
  assertTrue("failed connect leaked the protected fd",created!!.isClosed)
 }
}
