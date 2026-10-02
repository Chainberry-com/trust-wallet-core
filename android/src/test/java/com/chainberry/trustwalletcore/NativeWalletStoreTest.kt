package com.chainberry.trustwalletcore

import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.UUID

// Plain JVM unit tests (no Robolectric/instrumentation, same rationale as
// AmountParsingConformanceTest) for the pieces of NativeWalletStore that don't need an
// Android Context/Keystore/BiometricPrompt: wallet-id validation, the File-based
// metadata/delete helpers, the keyAlias scheme, the pure canAuthenticate()-result /
// BiometricPrompt-errorCode classification functions, and the pure KeyInfo-securityLevel
// description functions — all extracted specifically to be testable this way. The auth-gated
// paths that actually drive a Keystore key or a FragmentActivity/BiometricPrompt (mode
// resolution, both authenticateFor*Wallet flows, confirmIdentity, the StrongBox-request/fallback
// in generateKey, and the real KeyInfo introspection in logKeySecurityLevel) need a real
// device/emulator and are covered by manual end-to-end verification instead (see the remediation
// plan's verification section — API 24/28/29/30/35 x biometric-only/credential-only/both/
// neither/changed-enrollment/lockout states, plus StrongBox-present/TEE-only/software-only key
// generation).
class NativeWalletStoreTest {

  @get:Rule
  val tmp = TemporaryFolder()

  // ─── validateWalletId ────────────────────────────────────────────────────────

  @Test
  fun validateWalletId_acceptsFreshUuid() {
    val id = UUID.randomUUID().toString()
    assertEquals(id, NativeWalletStore.validateWalletId(id))
  }

  @Test
  fun validateWalletId_rejectsPathTraversal() {
    assertThrowsInvalidWalletId("../etc/passwd")
  }

  @Test
  fun validateWalletId_rejectsEmptyString() {
    assertThrowsInvalidWalletId("")
  }

  @Test
  fun validateWalletId_rejectsMalformedUuid() {
    assertThrowsInvalidWalletId("not-a-uuid")
  }

  private fun assertThrowsInvalidWalletId(walletId: String) {
    try {
      NativeWalletStore.validateWalletId(walletId)
      fail("expected InvalidWalletId for '$walletId'")
    } catch (e: NativeWalletStoreError.InvalidWalletId) {
      // expected
    }
  }

  // ─── metadata round-trip / corruption / atomicity ───────────────────────────

  @Test
  fun metadata_roundTrips() {
    val file = File(tmp.root, "metadata.json")
    val wallets = mapOf(
      "id-1" to NativeWalletStore.WalletRecord(isTestnet = false, addresses = mapOf("ethereum" to "0xabc")),
      "id-2" to NativeWalletStore.WalletRecord(isTestnet = true, addresses = mapOf("bitcoin" to "bc1abc")),
    )
    NativeWalletStore.saveMetadataToFile(file, wallets)
    assertEquals(wallets, NativeWalletStore.loadMetadataFromFile(file))
  }

  @Test
  fun metadata_legacyFlatShapeThrowsCorrupted_notSilentlyMisread() {
    // Data written by a pre-migration build (walletId -> {chain: address} with no
    // isTestnet/addresses wrapper) must never be silently reinterpreted — there is no
    // migration path, so this must surface as Corrupted, same as any other unexpected shape.
    val file = File(tmp.root, "metadata.json")
    file.writeText("""{"id-1":{"ethereum":"0xabc"}}""")
    try {
      NativeWalletStore.loadMetadataFromFile(file)
      fail("expected Corrupted for legacy flat-shape metadata")
    } catch (e: NativeWalletStoreError.Corrupted) {
      // expected
    }
  }

  @Test
  fun metadata_missingFileIsEmptyMap() {
    val file = File(tmp.root, "does-not-exist.json")
    assertTrue(NativeWalletStore.loadMetadataFromFile(file).isEmpty())
  }

  @Test
  fun metadata_corruptFileThrowsCorrupted_notSilentlyEmpty() {
    val file = File(tmp.root, "metadata.json")
    file.writeText("{ not valid json")
    try {
      NativeWalletStore.loadMetadataFromFile(file)
      fail("expected Corrupted for malformed JSON")
    } catch (e: NativeWalletStoreError.Corrupted) {
      // expected — this is the key regression check: a corrupt store must never look
      // identical to an empty one (that's what let createWallet stomp a real, unreadable
      // index in the original incident).
    }
  }

  @Test
  fun metadata_failedWrite_leavesExistingFileUntouched() {
    val target = File(tmp.root, "metadata.json")
    val original = mapOf("id-1" to NativeWalletStore.WalletRecord(isTestnet = false, addresses = mapOf("ethereum" to "0xabc")))
    NativeWalletStore.saveMetadataToFile(target, original)

    // Making the parent directory read-only blocks creating the temp file at all (the
    // earliest possible failure point of the write), which must surface as a typed
    // PermissionDenied — not a raw IOException, and the pre-existing target file must be
    // left exactly as it was (this is the atomicity guarantee: a failed write never touches
    // the previously-committed file).
    val originalBytes = target.readText()
    target.parentFile!!.setWritable(false)
    try {
      try {
        NativeWalletStore.saveMetadataToFile(
          target,
          mapOf("id-2" to NativeWalletStore.WalletRecord(isTestnet = false, addresses = mapOf("bitcoin" to "bc1xyz"))),
        )
        // Some filesystems/CI runners ignore setWritable(false) for the owner (e.g. root).
        // If the write unexpectedly succeeded, there's nothing to assert here.
      } catch (e: NativeWalletStoreError.PermissionDenied) {
        assertEquals(originalBytes, target.readText())
      }
    } finally {
      target.parentFile!!.setWritable(true)
    }
  }

  // ─── deleteFileChecked ───────────────────────────────────────────────────────

  @Test
  fun deleteFileChecked_missingFileIsNoOp() {
    val file = File(tmp.root, "missing.enc")
    // Should not throw even though the file was never created.
    NativeWalletStore.deleteFileChecked(file, "some-wallet-id")
  }

  @Test
  fun deleteFileChecked_deletesExistingFile() {
    val file = File(tmp.root, "present.enc")
    file.writeBytes(byteArrayOf(1, 2, 3))
    NativeWalletStore.deleteFileChecked(file, "some-wallet-id")
    assertFalse(file.exists())
  }

  @Test
  fun deleteFileChecked_undeletableFileThrowsDeleteFailed() {
    val dir = File(tmp.root, "readonly-dir").apply { mkdirs() }
    val file = File(dir, "present.enc")
    file.writeBytes(byteArrayOf(1, 2, 3))
    dir.setWritable(false)
    try {
      try {
        NativeWalletStore.deleteFileChecked(file, "some-wallet-id")
        // Some filesystems/CI runners (e.g. running as root) ignore setWritable(false);
        // nothing to assert if the delete unexpectedly succeeded.
      } catch (e: NativeWalletStoreError.DeleteFailed) {
        // expected
      }
    } finally {
      dir.setWritable(true)
    }
  }

  // ─── keyAlias ────────────────────────────────────────────────────────────────

  @Test
  fun keyAlias_encodesModeAndIsDistinctPerMode() {
    val id = UUID.randomUUID().toString()
    val bioAlias = NativeWalletStore.keyAlias(AuthMode.BIOMETRIC_STRONG, id)
    val credAlias = NativeWalletStore.keyAlias(AuthMode.DEVICE_CREDENTIAL, id)
    assertTrue(bioAlias.contains(id))
    assertTrue(credAlias.contains(id))
    assertFalse(bioAlias == credAlias)
  }

  @Test
  fun keyAlias_legacyCombinedHasNoInfix() {
    // Regression check for the orphaned-wallet bug: a wallet created before the
    // biometric/device-credential split used a bare "vault_wallet_<id>" alias (no bio_/cred_
    // infix). resolveExistingMode's legacy fallback depends on keyAlias(LEGACY_COMBINED, id)
    // reproducing that exact string, or a pre-split wallet becomes permanently unreachable again.
    val id = UUID.randomUUID().toString()
    val legacyAlias = NativeWalletStore.keyAlias(AuthMode.LEGACY_COMBINED, id)
    assertEquals("vault_wallet_$id", legacyAlias)
  }

  // ─── describeUnavailableReason ───────────────────────────────────────────────

  @Test
  fun describeUnavailableReason_mapsEachKnownCode() {
    val codes = listOf(
      BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
      BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
      BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
      BiometricManager.BIOMETRIC_STATUS_UNKNOWN,
    )
    // Every known code gets a distinct, non-generic reason string (i.e. none of them fall
    // through to the "unavailable (status $n)" catch-all).
    val reasons = codes.map { NativeWalletStore.describeUnavailableReason(it) }
    assertEquals(reasons.size, reasons.toSet().size)
    reasons.forEach { assertFalse(it.startsWith("unavailable (status")) }
  }

  @Test
  fun describeUnavailableReason_unknownCodeFallsThroughToGenericMessage() {
    val reason = NativeWalletStore.describeUnavailableReason(-999)
    assertTrue(reason.contains("-999"))
  }

  // ─── classifyPromptError ─────────────────────────────────────────────────────

  @Test
  fun classifyPromptError_lockoutIsTemporary() {
    val error = NativeWalletStore.classifyPromptError(BiometricPrompt.ERROR_LOCKOUT, "locked out")
    assertTrue(error is NativeWalletStoreError.AuthLockedOutTemporary)
    assertEquals("ERR_WALLET_AUTH_LOCKED_OUT", error.code)
  }

  @Test
  fun classifyPromptError_lockoutPermanentIsDistinctFromTemporary() {
    val error = NativeWalletStore.classifyPromptError(BiometricPrompt.ERROR_LOCKOUT_PERMANENT, "locked out for good")
    assertTrue(error is NativeWalletStoreError.AuthLockedOutPermanent)
    assertEquals("ERR_WALLET_AUTH_LOCKED_OUT_PERMANENT", error.code)
  }

  @Test
  fun classifyPromptError_userCancelledVariantsAllMapToCancelled() {
    val cancelCodes = listOf(
      BiometricPrompt.ERROR_USER_CANCELED,
      BiometricPrompt.ERROR_NEGATIVE_BUTTON,
      BiometricPrompt.ERROR_CANCELED,
    )
    cancelCodes.forEach { code ->
      val error = NativeWalletStore.classifyPromptError(code, "cancelled")
      assertTrue("code $code should classify as AuthCancelled", error is NativeWalletStoreError.AuthCancelled)
      assertEquals("ERR_WALLET_AUTH_CANCELLED", error.code)
    }
  }

  @Test
  fun classifyPromptError_unrecognizedCodeFallsBackToAuthenticationFailed() {
    val error = NativeWalletStore.classifyPromptError(BiometricPrompt.ERROR_NO_BIOMETRICS, "no biometrics enrolled")
    assertTrue(error is NativeWalletStoreError.AuthenticationFailed)
    assertEquals("ERR_AUTHENTICATION_FAILED", error.code)
    assertEquals(BiometricPrompt.ERROR_NO_BIOMETRICS, (error as NativeWalletStoreError.AuthenticationFailed).errorCode)
  }

  // ─── describeSecurityLevel / describeLegacySecurityLevel ────────────────────

  @Test
  fun describeSecurityLevel_mapsEachKnownLevel() {
    assertEquals("STRONGBOX", NativeWalletStore.describeSecurityLevel(KeyProperties.SECURITY_LEVEL_STRONGBOX))
    assertEquals("TEE", NativeWalletStore.describeSecurityLevel(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT))
    assertEquals("SOFTWARE", NativeWalletStore.describeSecurityLevel(KeyProperties.SECURITY_LEVEL_SOFTWARE))
  }

  @Test
  fun describeSecurityLevel_unknownLevelFallsThroughToGenericMessage() {
    val description = NativeWalletStore.describeSecurityLevel(-999)
    assertTrue(description.contains("-999"))
    // Must never silently read as hardware-backed for a level this function doesn't recognize.
    assertFalse(description == "STRONGBOX")
    assertFalse(description == "TEE")
  }

  @Test
  fun describeLegacySecurityLevel_insideSecureHardwareIsHardware() {
    assertEquals("HARDWARE", NativeWalletStore.describeLegacySecurityLevel(true))
  }

  @Test
  fun describeLegacySecurityLevel_notInsideSecureHardwareIsSoftware() {
    assertEquals("SOFTWARE", NativeWalletStore.describeLegacySecurityLevel(false))
  }

  // ─── parseKeyAlias ───────────────────────────────────────────────────────────

  @Test
  fun parseKeyAlias_isTheInverseOfKeyAlias() {
    val id = UUID.randomUUID().toString()
    for (mode in AuthMode.entries) {
      val alias = NativeWalletStore.keyAlias(mode, id)
      assertEquals(mode to id, NativeWalletStore.parseKeyAlias(alias))
    }
  }

  @Test
  fun parseKeyAlias_legacyInfixDoesNotSwallowBioOrCredAliases() {
    // Regression check: LEGACY_COMBINED's infix is "", which is a prefix of every alias under
    // KEY_ALIAS_PREFIX — parseKeyAlias must still resolve a bio_/cred_ alias to its actual mode,
    // not fall through to LEGACY_COMBINED just because the empty-infix check would also match.
    val id = UUID.randomUUID().toString()
    assertEquals(
      AuthMode.BIOMETRIC_STRONG to id,
      NativeWalletStore.parseKeyAlias(NativeWalletStore.keyAlias(AuthMode.BIOMETRIC_STRONG, id)),
    )
    assertEquals(
      AuthMode.DEVICE_CREDENTIAL to id,
      NativeWalletStore.parseKeyAlias(NativeWalletStore.keyAlias(AuthMode.DEVICE_CREDENTIAL, id)),
    )
  }

  @Test
  fun parseKeyAlias_unrelatedAliasReturnsNull() {
    assertEquals(null, NativeWalletStore.parseKeyAlias("some_other_features_key"))
  }

  // ─── findOrphanFiles / findStaleMetadataTempFiles (reconciliation, docs/adr/0001) ────────────

  @Test
  fun findOrphanFiles_fileWithNoMetadataEntryIsOrphaned() {
    File(tmp.root, "orphan-id.enc").writeBytes(byteArrayOf(1))
    val orphans = NativeWalletStore.findOrphanFiles(tmp.root, liveIds = emptySet())
    assertEquals(listOf("orphan-id.enc"), orphans.map { it.name })
  }

  @Test
  fun findOrphanFiles_fileWithMatchingMetadataEntryIsNotOrphaned() {
    File(tmp.root, "live-id.enc").writeBytes(byteArrayOf(1))
    val orphans = NativeWalletStore.findOrphanFiles(tmp.root, liveIds = setOf("live-id"))
    assertTrue(orphans.isEmpty())
  }

  @Test
  fun findOrphanFiles_ignoresNonEncFiles() {
    // metadata.json itself (and any stray temp file) must never be swept up as a wallet orphan.
    File(tmp.root, "metadata.json").writeText("{}")
    val orphans = NativeWalletStore.findOrphanFiles(tmp.root, liveIds = emptySet())
    assertTrue(orphans.isEmpty())
  }

  @Test
  fun findStaleMetadataTempFiles_findsLeftoverTempFile() {
    // Simulates a saveMetadataToFile interrupted after the temp write but before the rename.
    File(tmp.root, "metadata.json.tmp-12345").writeText("{}")
    val stale = NativeWalletStore.findStaleMetadataTempFiles(tmp.root)
    assertEquals(listOf("metadata.json.tmp-12345"), stale.map { it.name })
  }

  @Test
  fun findStaleMetadataTempFiles_ignoresCommittedMetadataFile() {
    File(tmp.root, "metadata.json").writeText("{}")
    assertTrue(NativeWalletStore.findStaleMetadataTempFiles(tmp.root).isEmpty())
  }
}
