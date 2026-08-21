package expo.modules.trustwalletcore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.exception.CodedException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * `.NotFound` and `.Corrupted` are deliberately distinct: `.NotFound` means "there is
 * legitimately nothing here yet" (no metadata has ever been written, or a wallet id has no
 * matching file) and is safe to treat as an empty/absent result. `.Corrupted` means
 * "something is here but it isn't what we expect" (malformed JSON) and must never be
 * silently treated as absent — doing so is exactly how a transient read failure can cause
 * `createWallet` to stomp a real, unreadable index with a fresh one.
 *
 * Extends `CodedException` directly (rather than a flat `Exception`) so `.code` survives the
 * Expo bridge losslessly with no extra wrapping step.
 */
sealed class NativeWalletStoreError private constructor(code: String, message: String, cause: Throwable? = null) :
  CodedException(code, message, cause) {

  class NotFound(walletId: String) :
    NativeWalletStoreError("ERR_WALLET_NOT_FOUND", "Wallet not found: $walletId")

  class Corrupted(detail: String, cause: Throwable? = null) :
    NativeWalletStoreError("ERR_WALLET_DATA_CORRUPTED", "Wallet data is corrupted: $detail", cause)

  class PermissionDenied(detail: String, cause: Throwable? = null) :
    NativeWalletStoreError("ERR_WALLET_PERMISSION_DENIED", "Permission denied: $detail", cause)

  class DeleteFailed(walletId: String, cause: Throwable? = null) :
    NativeWalletStoreError("ERR_WALLET_DELETE_FAILED", "Failed to delete wallet: $walletId", cause)

  class InvalidWalletId(walletId: String) :
    NativeWalletStoreError("ERR_INVALID_WALLET_ID", "Invalid wallet id: $walletId")

  class AuthenticationFailed(detail: String) :
    NativeWalletStoreError("ERR_AUTHENTICATION_FAILED", "Authentication failed: $detail")
}

/**
 * Persists mnemonics as files encrypted with a hardware-backed, biometry-or-device-credential
 * gated Android Keystore AES key (one key per wallet), plus a parallel ungated metadata store
 * (walletId -> per-chain addresses) for read-only UI. Deliberately not `EncryptedSharedPreferences`
 * or wallet-core's `StoredKey` keystore-JSON — confidentiality comes entirely from the Keystore
 * key never leaving the TEE/StrongBox, not from the on-disk file encoding.
 */
object NativeWalletStore {
  private const val KEY_ALIAS_PREFIX = "vault_wallet_"
  private const val ANDROID_KEYSTORE = "AndroidKeyStore"
  private const val TRANSFORMATION = "AES/GCM/NoPadding"
  private const val GCM_IV_LENGTH = 12
  private const val GCM_TAG_LENGTH_BITS = 128
  private const val WALLETS_DIR = "vault_wallets"
  private const val METADATA_FILE = "metadata.json"

  private fun walletsDir(context: Context): File =
    File(context.filesDir, WALLETS_DIR).apply { mkdirs() }

  private fun mnemonicFile(context: Context, walletId: String): File =
    File(walletsDir(context), "$walletId.enc")

  private fun metadataFile(context: Context): File =
    File(walletsDir(context), METADATA_FILE)

  /** Wallet ids are always internally generated as UUIDs (`UUID.randomUUID().toString()`).
   * Any caller-supplied id is validated against that format before it's used to build a file
   * path or Keystore alias, rejecting malformed/adversarial input (e.g. path traversal) up front. */
  fun validateWalletId(walletId: String): String {
    try {
      UUID.fromString(walletId)
    } catch (e: IllegalArgumentException) {
      throw NativeWalletStoreError.InvalidWalletId(walletId)
    }
    return walletId
  }

  // MARK: - Keystore key management

  private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

  private fun getOrCreateKey(walletId: String): SecretKey {
    val alias = KEY_ALIAS_PREFIX + walletId
    val ks = keyStore()
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }

    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setUserAuthenticationParameters(
        0,
        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
      )
    } else {
      @Suppress("DEPRECATION")
      builder.setUserAuthenticationValidityDurationSeconds(-1)
    }

    keyGenerator.init(builder.build())
    return keyGenerator.generateKey()
  }

  // MARK: - Mnemonic (biometry/device-credential gated)

  /** Encrypts and writes the mnemonic. Also requires user authentication (the key itself is
   * auth-gated for every use, encrypt included) — callers should invoke this right after a
   * successful [authenticate] prompt, same as [loadMnemonic]. */
  fun saveMnemonic(context: Context, walletId: String, mnemonic: String, authenticatedCipher: Cipher) {
    val iv = authenticatedCipher.iv
    val ciphertext = authenticatedCipher.doFinal(mnemonic.toByteArray(Charsets.UTF_8))
    mnemonicFile(context, walletId).writeBytes(iv + ciphertext)
  }

  fun loadMnemonic(context: Context, walletId: String, authenticatedCipher: Cipher): String {
    val file = mnemonicFile(context, walletId)
    if (!file.exists()) throw NativeWalletStoreError.NotFound(walletId)
    val bytes = file.readBytes()
    val ciphertext = bytes.copyOfRange(GCM_IV_LENGTH, bytes.size)
    return String(authenticatedCipher.doFinal(ciphertext), Charsets.UTF_8)
  }

  /** Idempotent: deleting a wallet id whose file is already gone is a no-op, matching normal
   * `deleteWallet` semantics. The delete result is checked and propagates on failure rather
   * than being silently discarded. Pure/`File`-based (no `Context`) so it's unit-testable on
   * the plain JVM without an Android `Context`/Keystore, unlike [deleteMnemonic] as a whole. */
  internal fun deleteFileChecked(file: File, walletId: String) {
    if (file.exists() && !file.delete()) {
      throw NativeWalletStoreError.DeleteFailed(walletId)
    }
  }

  /** Idempotent: deleting a wallet id whose file is already gone is a no-op, matching normal
   * `deleteWallet` semantics. Both the file deletion and the Keystore-entry deletion results
   * are checked and propagate on failure — neither is silently discarded. */
  fun deleteMnemonic(context: Context, walletId: String) {
    deleteFileChecked(mnemonicFile(context, walletId), walletId)
    try {
      keyStore().deleteEntry(KEY_ALIAS_PREFIX + walletId)
    } catch (e: Exception) {
      throw NativeWalletStoreError.DeleteFailed(walletId, e)
    }
  }

  /** A `Cipher` initialized for encryption, to be unlocked via [authenticate] before use. */
  fun encryptCipher(walletId: String): Cipher {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(walletId))
    return cipher
  }

  /** A `Cipher` initialized for decryption using the IV already on disk, to be unlocked via
   * [authenticate] before use. */
  fun decryptCipher(context: Context, walletId: String): Cipher {
    val file = mnemonicFile(context, walletId)
    if (!file.exists()) throw NativeWalletStoreError.NotFound(walletId)
    val iv = file.readBytes().copyOfRange(0, GCM_IV_LENGTH)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(walletId), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
    return cipher
  }

  // MARK: - Metadata (ungated: walletId -> { chain: address })

  /** Atomically replaces [target] via a temp-file write + `File.renameTo` (an atomic
   * `rename(2)` on the same filesystem/mount, since the temp file is created alongside
   * [target] in the same directory) — never a direct in-place overwrite, which could leave a
   * torn file if the process is killed mid-write. Pure/`File`-based so it's unit-testable on
   * the plain JVM without an Android `Context`. */
  internal fun saveMetadataToFile(target: File, wallets: Map<String, Map<String, String>>) {
    val root = JSONObject()
    for ((walletId, addresses) in wallets) {
      root.put(walletId, JSONObject(addresses as Map<*, *>))
    }
    val temp = File(target.parentFile, "$METADATA_FILE.tmp-${System.nanoTime()}")
    try {
      temp.writeText(root.toString())
    } catch (e: Exception) {
      temp.delete()
      throw NativeWalletStoreError.PermissionDenied("could not write metadata temp file", e)
    }
    if (!temp.renameTo(target)) {
      temp.delete()
      throw NativeWalletStoreError.Corrupted("failed to atomically replace metadata file")
    }
  }

  /** Distinguishes "no metadata has ever been written" (legitimately empty) from a genuine
   * parse/corruption failure, which now throws a typed [NativeWalletStoreError.Corrupted]
   * instead of letting a raw, uncaught `JSONException` leak through the Expo bridge.
   * Pure/`File`-based so it's unit-testable on the plain JVM without an Android `Context`. */
  internal fun loadMetadataFromFile(file: File): Map<String, Map<String, String>> {
    if (!file.exists()) return emptyMap()
    val root = try {
      JSONObject(file.readText())
    } catch (e: JSONException) {
      throw NativeWalletStoreError.Corrupted("metadata.json is not valid JSON", e)
    }
    val result = mutableMapOf<String, Map<String, String>>()
    for (walletId in root.keys()) {
      val addressesJson = root.getJSONObject(walletId)
      val addresses = mutableMapOf<String, String>()
      for (chain in addressesJson.keys()) {
        addresses[chain] = addressesJson.getString(chain)
      }
      result[walletId] = addresses
    }
    return result
  }

  fun saveMetadata(context: Context, wallets: Map<String, Map<String, String>>) {
    saveMetadataToFile(metadataFile(context), wallets)
  }

  fun loadMetadata(context: Context): Map<String, Map<String, String>> {
    return loadMetadataFromFile(metadataFile(context))
  }

  // MARK: - Biometric/device-credential prompt

  /** Authenticates the given [Cipher] via BiometricPrompt (biometry-or-device-credential),
   * returning the same cipher ready for [Cipher.doFinal]. BiometricPrompt drives a
   * FragmentManager transaction under the hood, so it — and this call — must run on the main
   * thread; callers reach this via `AsyncFunction(...) Coroutine { ... }`, which Expo dispatches
   * on a background HandlerThread, not main. */
  suspend fun authenticate(activity: FragmentActivity, cipher: Cipher, title: String): Cipher =
    withContext(Dispatchers.Main) {
      suspendCoroutine { continuation ->
        val prompt = biometricPrompt(
          activity,
          onSucceeded = { result ->
            val authenticatedCipher = result.cryptoObject?.cipher
            if (authenticatedCipher == null) {
              continuation.resumeWithException(
                NativeWalletStoreError.AuthenticationFailed("no authenticated cipher returned")
              )
            } else {
              continuation.resume(authenticatedCipher)
            }
          },
          onError = { errString ->
            continuation.resumeWithException(NativeWalletStoreError.AuthenticationFailed(errString))
          }
        )
        prompt.authenticate(promptInfo(title), BiometricPrompt.CryptoObject(cipher))
      }
    }

  /** Crypto-object-less confirmation prompt — for gating operations like `deleteWallet` that
   * don't perform a Keystore encrypt/decrypt themselves, so there's no `Cipher` to bind the
   * prompt to (and binding to one would wrongly fail when e.g. cleaning up a wallet whose key
   * is already broken/missing). Same main-thread requirement as [authenticate]. */
  suspend fun confirmIdentity(activity: FragmentActivity, title: String) {
    withContext(Dispatchers.Main) {
      suspendCoroutine<Unit> { continuation ->
        val prompt = biometricPrompt(
          activity,
          onSucceeded = { continuation.resume(Unit) },
          onError = { errString ->
            continuation.resumeWithException(NativeWalletStoreError.AuthenticationFailed(errString))
          }
        )
        prompt.authenticate(promptInfo(title))
      }
    }
  }

  private fun promptInfo(title: String): BiometricPrompt.PromptInfo {
    val allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
      BiometricManager.Authenticators.DEVICE_CREDENTIAL
    return BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setAllowedAuthenticators(allowedAuthenticators)
      .build()
  }

  private fun biometricPrompt(
    activity: FragmentActivity,
    onSucceeded: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: (String) -> Unit,
  ): BiometricPrompt {
    val executor = ContextCompat.getMainExecutor(activity)
    return BiometricPrompt(
      activity,
      executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          onSucceeded(result)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          onError(errString.toString())
        }

        override fun onAuthenticationFailed() {
          // Not terminal — BiometricPrompt keeps the sheet open for retry; only
          // onAuthenticationError/onAuthenticationSucceeded resolve the continuation.
        }
      }
    )
  }
}
