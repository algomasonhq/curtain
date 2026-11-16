package org.curtain.dns

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.SocketFactory

/** Materialize the Android socket fd by binding before protect, always before connect.
 * A plain Socket() is lazy: protect(Socket()) can return false for an invalid fd.
 */
class ProtectedSocketFactory(private val protector:(Socket)->Boolean):SocketFactory() {
 private fun newProtected(local:SocketAddress=InetSocketAddress(0)):Socket {
  val socket=Socket()
  try {
   socket.bind(local)
   if(!protector(socket)) throw IOException("socket protection failed; refusing to route through the VPN")
   return socket
  } catch(e:Exception) { try { socket.close() } catch(_:Exception) {}; throw e }
 }
 private fun connect(socket:Socket,endpoint:SocketAddress):Socket {
  try { socket.connect(endpoint,15_000); return socket }
  catch(e:Exception) { try { socket.close() } catch(_:Exception) {}; throw e }
 }
 override fun createSocket():Socket=newProtected()
 override fun createSocket(host:String,port:Int):Socket=connect(newProtected(),InetSocketAddress(host,port))
 override fun createSocket(host:String,port:Int,localHost:InetAddress,localPort:Int):Socket=
  connect(newProtected(InetSocketAddress(localHost,localPort)),InetSocketAddress(host,port))
 override fun createSocket(host:InetAddress,port:Int):Socket=connect(newProtected(),InetSocketAddress(host,port))
 override fun createSocket(address:InetAddress,port:Int,localAddress:InetAddress,localPort:Int):Socket=
  connect(newProtected(InetSocketAddress(localAddress,localPort)),InetSocketAddress(address,port))
}
