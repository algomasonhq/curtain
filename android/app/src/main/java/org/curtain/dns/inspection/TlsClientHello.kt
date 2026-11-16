package org.curtain.dns.inspection

import java.nio.charset.StandardCharsets.US_ASCII

/**
 * Parser for exactly one complete TLS record whose payload starts with ClientHello.
 * Returns null for a valid ClientHello without SNI. Malformed or fragmented records throw.
 */
internal object TlsClientHello {
 const val CONTENT_TYPE_HANDSHAKE=0x16
 const val MAX_RECORD_BYTES=64*1024

 fun serverName(record:ByteArray):String? {
  require(record.size>=5 && record.size<=MAX_RECORD_BYTES) { "invalid TLS record size" }
  require((record[0].toInt() and 0xff)==CONTENT_TYPE_HANDSHAKE) { "not a TLS handshake record" }
  require((record[1].toInt() and 0xff)==3) { "unsupported TLS record version" }
  val length=((record[3].toInt() and 0xff) shl 8) or (record[4].toInt() and 0xff)
  require(length>0 && length<=record.size-5) { "invalid TLS record length" }

  val reader=Reader(record,5,length)
  require(reader.u8()==1) { "not a ClientHello" }
  val handshakeLength=reader.u24()
  require(handshakeLength>0 && handshakeLength<=reader.remaining) { "fragmented ClientHello" }

  reader.u16() // legacy_version
  reader.skip(32) // random
  reader.skip(reader.u8()) // session_id
  reader.skip(reader.u16()) // cipher_suites
  reader.skip(reader.u8()) // compression_methods
  if(reader.remaining==0) return null

  val extensionsLength=reader.u16()
  require(extensionsLength<=reader.remaining) { "invalid extensions length" }
  val extensionsEnd=reader.position+extensionsLength
  while(reader.position<extensionsEnd) {
   require(extensionsEnd-reader.position>=4) { "truncated extension" }
   val type=reader.u16()
   val length=reader.u16()
   require(length<=extensionsEnd-reader.position) { "truncated extension body" }
   val bodyStart=reader.position
   if(type==0) return parseServerName(Reader(record,bodyStart,length))
   reader.position=bodyStart+length
  }
  return null
 }

 private fun parseServerName(reader:Reader):String? {
  require(reader.remaining>=2) { "truncated SNI extension" }
  val listLength=reader.u16()
  require(listLength<=reader.remaining) { "truncated SNI list" }
  val listEnd=reader.position+listLength
  while(reader.position<listEnd) {
   require(listEnd-reader.position>=3) { "truncated SNI entry" }
   val nameType=reader.u8()
   val nameLength=reader.u16()
   require(nameLength<=listEnd-reader.position) { "truncated SNI name" }
   if(nameType==0) {
    require(nameLength>0) { "empty SNI host name" }
    val bytes=reader.bytes(nameLength)
    require(bytes.all { (it.toInt() and 0xff) in 0x21..0x7e }) { "non-ASCII SNI host name" }
    return String(bytes,US_ASCII)
   }
   reader.skip(nameLength)
  }
  return null
 }

 private class Reader(private val data:ByteArray,var position:Int,private val length:Int) {
  private val end=position+length
  val remaining:Int get()=end-position

  fun u8():Int {
   require(position<end) { "truncated TLS ClientHello" }
   return data[position++].toInt() and 0xff
  }

  fun u16():Int=(u8() shl 8) or u8()

  fun u24():Int=(u8() shl 16) or (u8() shl 8) or u8()

  fun skip(count:Int) {
   require(count>=0 && count<=remaining) { "truncated TLS ClientHello" }
   position+=count
  }

  fun bytes(count:Int):ByteArray {
   require(count>=0 && count<=remaining) { "truncated TLS ClientHello" }
   val result=data.copyOfRange(position,position+count)
   position+=count
   return result
  }
 }
}
