package expo.modules.trustwalletcore

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
// Android Context/Keystore/BiometricPrompt: wallet-id validation and the File-based
// metadata/delete helpers extracted specifically to be testable this way. The
// authentication-gated paths (persistNewWallet's rollback, deleteWallet's confirmIdentity
// gate) need a real FragmentActivity/BiometricPrompt and are covered by manual end-to-end
// verification instead (see the plan's verification section).
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
      "id-1" to mapOf("ethereum" to "0xabc"),
      "id-2" to mapOf("bitcoin" to "bc1abc"),
    )
    NativeWalletStore.saveMetadataToFile(file, wallets)
    assertEquals(wallets, NativeWalletStore.loadMetadataFromFile(file))
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
    val original = mapOf("id-1" to mapOf("ethereum" to "0xabc"))
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
        NativeWalletStore.saveMetadataToFile(target, mapOf("id-2" to mapOf("bitcoin" to "bc1xyz")))
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
}
