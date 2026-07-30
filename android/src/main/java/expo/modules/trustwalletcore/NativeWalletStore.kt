package expo.modules.trustwalletcore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * Persists mnemonics as files encrypted with a hardware-backed, biometry-or-device-credential
 * gated Android Keystore AES key (one key per wallet), plus a parallel ungated metadata store
 * (walletId -> per-chain addresses) for read-only UI. Deliberately not `EncryptedSharedPreferences`
 * or wallet-core's `StoredKey` keystore-JSON — confidentiality comes entirely from the Keystore
 * key never leaving the TEE/StrongBox, not from the on-disk file encoding.
 */
class NativeWalletStoreError(message: String) : Exception(message)

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
    if (!file.exists()) throw NativeWalletStoreError("Wallet not found: $walletId")
    val bytes = file.readBytes()
    val ciphertext = bytes.copyOfRange(GCM_IV_LENGTH, bytes.size)
    return String(authenticatedCipher.doFinal(ciphertext), Charsets.UTF_8)
  }

  fun deleteMnemonic(context: Context, walletId: String) {
    mnemonicFile(context, walletId).delete()
    runCatching { keyStore().deleteEntry(KEY_ALIAS_PREFIX + walletId) }
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
    if (!file.exists()) throw NativeWalletStoreError("Wallet not found: $walletId")
    val iv = file.readBytes().copyOfRange(0, GCM_IV_LENGTH)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(walletId), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
    return cipher
  }

  // MARK: - Metadata (ungated: walletId -> { chain: address })

  fun saveMetadata(context: Context, wallets: Map<String, Map<String, String>>) {
    val root = JSONObject()
    for ((walletId, addresses) in wallets) {
      root.put(walletId, JSONObject(addresses as Map<*, *>))
    }
    metadataFile(context).writeText(root.toString())
  }

  fun loadMetadata(context: Context): Map<String, Map<String, String>> {
    val file = metadataFile(context)
    if (!file.exists()) return emptyMap()
    val root = JSONObject(file.readText())
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

  // MARK: - Biometric/device-credential prompt

  /** Authenticates the given [Cipher] via BiometricPrompt (biometry-or-device-credential),
   * returning the same cipher ready for [Cipher.doFinal]. BiometricPrompt drives a
   * FragmentManager transaction under the hood, so it — and this call — must run on the main
   * thread; callers reach this via `AsyncFunction(...) Coroutine { ... }`, which Expo dispatches
   * on a background HandlerThread, not main. */
  suspend fun authenticate(activity: FragmentActivity, cipher: Cipher, title: String): Cipher =
    withContext(Dispatchers.Main) {
      suspendCoroutine { continuation ->
        val allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
          BiometricManager.Authenticators.DEVICE_CREDENTIAL

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
          .setTitle(title)
          .setAllowedAuthenticators(allowedAuthenticators)
          .build()

        val executor = androidx.core.content.ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
          activity,
          executor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
              val authenticatedCipher = result.cryptoObject?.cipher
                ?: return continuation.resumeWithException(NativeWalletStoreError("No authenticated cipher returned"))
              continuation.resume(authenticatedCipher)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
              continuation.resumeWithException(NativeWalletStoreError("Authentication error: $errString"))
            }

            override fun onAuthenticationFailed() {
              // Not terminal — BiometricPrompt keeps the sheet open for retry; only
              // onAuthenticationError/onAuthenticationSucceeded resolve the continuation.
            }
          }
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
      }
    }
}
