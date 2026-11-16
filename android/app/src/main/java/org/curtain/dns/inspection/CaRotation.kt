package org.curtain.dns.inspection

/**
 * Pure, JVM-testable state machine for the explicit CA rotation lifecycle.
 *
 * Phases:
 * - [PHASE_IDLE]: no rotation. The persisted old/new fields may still carry the record of the
 *   last completed rotation for exact old→new display.
 * - [PHASE_PENDING]: the user has explicitly begun a rotation. The app has recorded the old
 *   subject + fingerprint and gates export/new install; the old root still exists and keeps
 *   working until the user removes it from Android Settings and confirms.
 *
 * Rotation is never automatic. The engine (LocalCertificateAuthority) deletes the stored key only
 * through an explicit call that verifies the exact old fingerprint, and a replacement root is only
 * generated afterwards, on the next construction, after the user confirmed and the platform store
 * no longer lists the old certificate (see [oldCaAbsent]; unknown store → fail closed).
 *
 * The state is plain strings/longs so it round-trips through Android SharedPreferences
 * ([toPrefs]/[fromPrefs]) without Android dependencies. Corrupt persisted state always falls back
 * to [PHASE_IDLE] with the fields cleared: a rotation that can no longer be verified must never
 * keep export gated or claim a removal that was never proven.
 */
data class CaRotationState(
 val phase:String=CaRotation.PHASE_IDLE,
 val oldSubject:String="",
 val oldFingerprint:String="",
 val newSubject:String="",
 val newFingerprint:String="",
 val startedAtMs:Long=0,
 val completedAtMs:Long=0
)

object CaRotation {
 const val PHASE_IDLE="idle"
 const val PHASE_PENDING="pending-removal"

 private const val K_PHASE="ca_rotation_phase"; private const val K_OLD_SUBJECT="ca_rotation_old_subject"
 private const val K_OLD_FP="ca_rotation_old_fingerprint"; private const val K_NEW_SUBJECT="ca_rotation_new_subject"
 private const val K_NEW_FP="ca_rotation_new_fingerprint"; private const val K_STARTED="ca_rotation_started_at"
 private const val K_COMPLETED="ca_rotation_completed_at"

 /** Uppercase hex, colon-separated pairs (64 hex digits). Accepts lowercase or colonless input. */
 fun canonicalFingerprint(raw:String):String {
  val compact=raw.trim().replace(":","").uppercase()
  require(compact.length==64 && compact.all { it in '0'..'9' || it in 'A'..'F' }) {
   "not a SHA-256 fingerprint"
  }
  return compact.chunked(2).joinToString(":")
 }

 fun isPending(s:CaRotationState):Boolean = s.phase==PHASE_PENDING

 /** While a rotation is pending the old root is on its way out: exporting it or guiding a new
  *  install would just (re)install the certificate the user is removing, so both are gated. */
 fun exportGated(s:CaRotationState):Boolean = isPending(s)

 fun hasCompletedRecord(s:CaRotationState):Boolean =
  !isPending(s) && s.completedAtMs>0 && s.oldFingerprint.isNotEmpty() && s.newFingerprint.isNotEmpty()

 /** Begins a pending rotation from idle, recording the exact old identity. Refuses to begin while
  *  another rotation is already pending (cancel or complete first). */
 fun begin(s:CaRotationState,subject:String,fingerprintSha256:String,nowMs:Long):CaRotationState {
  if(isPending(s)) throw IllegalStateException("a rotation is already pending; cancel or complete it first")
  require(s.phase==PHASE_IDLE || s.phase.isBlank()) { "unknown rotation phase: ${s.phase}" }
  val canonical=canonicalFingerprint(fingerprintSha256)
  require(subject.isNotBlank()) { "old subject is empty" }
  return CaRotationState(phase=PHASE_PENDING,oldSubject=subject,oldFingerprint=canonical,
   startedAtMs=nowMs)
 }

 /** Explicit user cancel: back to idle with the record cleared; the old CA is left untouched. */
 fun cancel(s:CaRotationState):CaRotationState {
  if(!isPending(s)) throw IllegalStateException("no rotation is pending")
  return CaRotationState(phase=PHASE_IDLE)
 }

 /** Completes a pending rotation after the old root was confirmed gone and the user explicitly
  *  confirmed generating the replacement: records the exact old and new identities for display. */
 fun completeGeneration(s:CaRotationState,newSubject:String,newFingerprintSha256:String,nowMs:Long):CaRotationState {
  if(!isPending(s)) throw IllegalStateException("no rotation is pending")
  require(newSubject.isNotBlank()) { "new subject is empty" }
  val canonical=canonicalFingerprint(newFingerprintSha256)
  require(s.oldFingerprint.isNotEmpty()) { "pending state lost the old fingerprint" }
  return s.copy(phase=PHASE_IDLE,newSubject=newSubject,newFingerprint=canonical,completedAtMs=nowMs)
 }

 /**
  * Removal proof by fingerprint absence in the platform CA store.
  * null = the store could not be read (unknown): callers must fail closed and keep the rotation
  * pending. Never trust a blank old fingerprint.
  */
 fun oldCaAbsent(s:CaRotationState,installedFingerprints:Set<String>?):Boolean? {
  if(!isPending(s) || s.oldFingerprint.isEmpty()) return null
  if(installedFingerprints==null) return null
  val expected=try { canonicalFingerprint(s.oldFingerprint) } catch(_:IllegalArgumentException) { return null }
  val installed=installedFingerprints.mapNotNull { runCatching { canonicalFingerprint(it) }.getOrNull() }
  return !installed.contains(expected)
 }

 fun displayOld(s:CaRotationState):String =
  "subject: ${s.oldSubject}\nSHA-256 fingerprint: ${s.oldFingerprint}"

 fun displayNew(s:CaRotationState):String =
  "subject: ${s.newSubject}\nSHA-256 fingerprint: ${s.newFingerprint}"

 /** Only meaningful values are persisted; missing keys read back as the idle state. */
 fun toPrefs(s:CaRotationState):Map<String,String> = buildMap {
  when {
   isPending(s) -> put(K_PHASE,PHASE_PENDING)
   s.phase==PHASE_IDLE -> {}
   else -> put(K_PHASE,s.phase)
  }
  if(s.oldSubject.isNotEmpty()) put(K_OLD_SUBJECT,s.oldSubject)
  if(s.oldFingerprint.isNotEmpty()) put(K_OLD_FP,s.oldFingerprint)
  if(s.newSubject.isNotEmpty()) put(K_NEW_SUBJECT,s.newSubject)
  if(s.newFingerprint.isNotEmpty()) put(K_NEW_FP,s.newFingerprint)
  if(s.startedAtMs>0) put(K_STARTED,s.startedAtMs.toString())
  if(s.completedAtMs>0) put(K_COMPLETED,s.completedAtMs.toString())
 }

 /** Corrupt or unknown persisted phases fall back to idle with nothing gated. An unfixed
  *  fingerprint is dropped the same way (fail closed against fake completion, fail open against
  *  a permanently stuck gate). */
 fun fromPrefs(m:Map<String,*>):CaRotationState {
  val phase=m[K_PHASE] as? String ?: PHASE_IDLE
  val pending=phase==PHASE_PENDING
  val oldFp=(m[K_OLD_FP] as? String).orEmpty()
  val validOldFp=runCatching { canonicalFingerprint(oldFp) }.getOrNull()
  return CaRotationState(
   phase=if(pending && validOldFp!=null) PHASE_PENDING else PHASE_IDLE,
   oldSubject=(m[K_OLD_SUBJECT] as? String).orEmpty(),
   oldFingerprint=validOldFp.orEmpty(),
   newSubject=(m[K_NEW_SUBJECT] as? String).orEmpty(),
   newFingerprint=(m[K_NEW_FP] as? String)?.let { runCatching { canonicalFingerprint(it) }.getOrNull() }.orEmpty(),
   startedAtMs=(m[K_STARTED] as? String)?.toLongOrNull() ?: 0,
   completedAtMs=(m[K_COMPLETED] as? String)?.toLongOrNull() ?: 0
  )
 }
}
