package org.curtain.dns

import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.util.Base64

/** Signed ASCII manifest contract shared with tools/prepare_update.py. Reject ambiguous JSON. */
data class UpdateManifest(val version:Long,val file:String,val size:Long,val hash:String,val signature:String) {
 fun canonical()="{\"bytes\":$size,\"file\":\"$file\",\"format\":1,\"sha256\":\"$hash\",\"version\":$version}"
 fun json()=canonical().dropLast(1)+",\"signature\":\"$signature\"}"
 companion object {
  const val MAX_MANIFEST=16*1024
  const val MAX_DATA=512L*1024*1024
  fun parse(text:String,key:PublicKey):UpdateManifest {
   require(text.length<=MAX_MANIFEST && text.all { it.code in setOf(9,10,13) || it.code in 32..126 }) { "Invalid manifest encoding/size" }
   // Only the publisher's unescaped ASCII strings and canonical unsigned integers are accepted.
   val token=Regex("\\s*\"([a-z0-9]+)\"\\s*:\\s*(\"[A-Za-z0-9/+.=_-]*\"|[0-9]+)\\s*")
   val body=text.trim().also { require(it.startsWith('{') && it.endsWith('}')) }.drop(1).dropLast(1)
   val fields=linkedMapOf<String,String>()
   body.split(',').forEach { part ->
    val m=token.matchEntire(part) ?: error("Malformed manifest")
    require(fields.put(m.groupValues[1],m.groupValues[2])==null) { "Duplicate manifest field" }
   }
   require(fields.keys==setOf("bytes","file","format","sha256","version","signature")) { "Unexpected manifest fields" }
   fun number(name:String):Long { val value=fields.getValue(name); require(Regex("[1-9][0-9]*").matches(value)); return value.toLong() }
   fun string(name:String):String { val value=fields.getValue(name); require(value.startsWith('"') && value.endsWith('"')); return value.drop(1).dropLast(1) }
   require(number("format")==1L) { "Unsupported index format" }
   val v=number("version"); val size=number("bytes"); val path=string("file"); val hash=string("sha256"); val sig=string("signature")
   require(size in 64..MAX_DATA && Regex("indexes/[0-9]{6,19}\\.fc").matches(path) && Regex("[0-9a-f]{64}").matches(hash)) { "Invalid index metadata" }
   val result=UpdateManifest(v,path,size,hash,sig)
   val signature=Base64.getDecoder().decode(sig); require(signature.size==64)
   require(UpdateTrust.verify(key,result.canonical().toByteArray(Charsets.UTF_8),signature)) { "Manifest signature rejected" }
   return result
  }
 }
}

data class IndexSnapshot(val metadata:UpdateManifest,val index:CompactIndex,val file:File) { val version get()=metadata.version }

/** Owns publication, not readers. Published files are never rewritten or deleted, even after upgrade. */
class UpdateEngine(private val directory:File,private val key:PublicKey) {
 init { check(directory.mkdirs() || directory.isDirectory) }
 private val pointer=File(directory,"current.json")
 private fun accepted():UpdateManifest? = if(pointer.exists()) UpdateManifest.parse(pointer.readText(),key) else null
 private fun target(m:UpdateManifest)=File(directory,"snapshot-${m.version}-${m.hash}.fc")
 private fun validate(file:File,m:UpdateManifest):IndexSnapshot {
  require(file.length()==m.size) { "Index length mismatch" }
  val digest=MessageDigest.getInstance("SHA-256")
  file.inputStream().use { input -> val buf=ByteArray(1024*1024); while(true) { val n=input.read(buf); if(n<0) break; digest.update(buf,0,n) } }
  require(digest.digest().joinToString("") { "%02x".format(it) }==m.hash) { "Index hash mismatch" }
  val index=RandomAccessFile(file,"r").use { CompactIndex(it.channel.map(FileChannel.MapMode.READ_ONLY,0,it.length())) }
  return IndexSnapshot(m,index,file)
 }
 fun restore():IndexSnapshot? = accepted()?.let { validate(target(it),it) }
 fun update(text:String,download:(UpdateManifest)->InputStream,progress:(Long,Long)->Unit={_,_->}):IndexSnapshot =
  RandomAccessFile(File(directory,"update.lock"),"rw").use { lockFile ->
   val lock=try { lockFile.channel.tryLock() } catch(_:java.nio.channels.OverlappingFileLockException) { null }
   check(lock!=null) { "Update already running" }
   lock.use { updateLocked(text,download,progress) }
  }
 private fun updateLocked(text:String,download:(UpdateManifest)->InputStream,progress:(Long,Long)->Unit):IndexSnapshot {
  val manifest=UpdateManifest.parse(text,key)
  val previous=accepted()
  if(previous!=null) {
   require(manifest.version>=previous.version) { "Rollback rejected" }
   if(manifest.version==previous.version) {
    require(manifest.canonical()==previous.canonical()) { "Same-version metadata changed" }
    // A damaged snapshot may be repaired from the identical signed metadata, but never rewritten.
    if(target(previous).exists()) return validate(target(previous),previous)
   }
  }
  val destination=target(manifest)
  if(destination.exists()) {
   val recovered=validate(destination,manifest)
   publishManifest(manifest)
   return recovered
  }
  val temporary=File.createTempFile("download-",".part",directory)
  try {
   download(manifest).use { input -> temporary.outputStream().use { output ->
    val buffer=ByteArray(1024*1024); var total=0L
    while(true) { val n=input.read(buffer); if(n<0) break; total+=n; require(total<=manifest.size) { "Index exceeds signed length" }; output.write(buffer,0,n); progress(total,manifest.size) }
    require(total==manifest.size) { "Incomplete index download" }; output.fd.sync()
   } }
   val validated=validate(temporary,manifest)
   check(temporary.setReadOnly()) { "Cannot protect snapshot" }
   Files.move(temporary.toPath(),destination.toPath(),StandardCopyOption.ATOMIC_MOVE)
   publishManifest(manifest)
   return validated.copy(file=destination)
  } finally { temporary.delete() }
 }
 private fun publishManifest(manifest:UpdateManifest) {
  val next=File.createTempFile("manifest-",".part",directory)
  try {
   next.outputStream().use { it.write(manifest.json().toByteArray()); it.fd.sync() }
   Files.move(next.toPath(),pointer.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING)
  } finally { next.delete() }
 }
}
