package com.chainberry.trustwalletcore

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
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
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * Which authenticator a wallet's Keystore key is gated by, chosen once at creation time (see
 * [NativeWalletStore.resolveAvailableMode]) and thereafter recoverable from which Keystore alias
 * exists for that wallet id (see [NativeWalletStore.resolveExistingMode]) — no separate metadata
 * needed. The two *creatable* modes are deliberately separate flows rather than one prompt/key
 * straddling both: combining `BIOMETRIC_STRONG` and `DEVICE_CREDENTIAL` in a single
 * `BiometricPrompt` (or in a single per-use Keystore key) is not reliably supported on API 29 and
 * below, per https://developer.android.com/identity/sign-in/biometric-auth — see
 * [NativeWalletStore] for the full rationale.
 */
enum class AuthMode(val aliasInfix: String) {
  /** Authentication-per-use: every single encrypt/decrypt requires a fresh `BIOMETRIC_STRONG`
   * prompt. Supported identically on every API level 24+ — this is the only combination that
   * needs no API-level branching in [NativeWalletStore.getOrCreateKey] at all. */
  BIOMETRIC_STRONG("bio_"),

  /** Fallback used only when no strong biometric is enrolled/available. Backed by a short
   * bounded-validity key rather than a per-use one, and never binds a `CryptoObject` to its
   * prompt on any API level (see [NativeWalletStore.confirmDeviceCredential]) — both are
   * consequences of `CryptoObject` support for device-credential auth only existing from API 30
   * (androidx.biometric 1.1.0-alpha02) onward. */
  DEVICE_CREDENTIAL("cred_"),

  /** Pre-migration scheme (alias `vault_wallet_<id>`, no infix — matches [aliasInfix] `""`) from
   * before the biometric/device-credential split above existed: a single per-use key accepting
   * *either* `BIOMETRIC_STRONG` or `DEVICE_CREDENTIAL` in one combined `BiometricPrompt`. Never
   * chosen for a new wallet ([NativeWalletStore.resolveAvailableMode] never returns it) — it
   * exists purely so [NativeWalletStore.resolveExistingMode] can still find and
   * [NativeWalletStore.authenticateForExistingWallet] can still unlock a wallet that was created
   * before the split shipped. The split's original commit assumed no such wallet could exist
   * pre-launch and shipped with no migration path; that assumption turned out to be wrong (a
   * real wallet created under this scheme was found to be permanently unreachable — `resolveExistingMode`
   * only checked the two post-split aliases), so this case restores discoverability rather than
   * silently stranding it. */
  LEGACY_COMBINED(""),
}

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

  /** Residual bucket for anything not classified more specifically below. Carries the raw
   * AndroidX `errorCode` (when known) for native-side logging only — the JS-facing `.code`/
   * `.message` are unaffected by it. */
  class AuthenticationFailed(detail: String, val errorCode: Int? = null) :
    NativeWalletStoreError("ERR_AUTHENTICATION_FAILED", "Authentication failed: $detail")

  /** Thrown at wallet-creation time when neither `BIOMETRIC_STRONG` nor `DEVICE_CREDENTIAL` is
   * available — never create a Keystore key that couldn't possibly be unlocked. */
  class NoSecureAuthAvailable :
    NativeWalletStoreError(
      "ERR_WALLET_NO_SECURE_AUTH",
      "No secure authentication method (biometric or device credential) is available on this device"
    )

  /** Thrown by the use-time `canAuthenticate()` precheck (before any prompt UI opens) when an
   * existing wallet's already-committed [mode] is no longer satisfiable — e.g. the user removed
   * their only fingerprint, or disabled the screen lock. Distinct from [KeyInvalidated]: this
   * fires on the precheck, before ever touching the Keystore key. */
  class AuthUnavailable(mode: AuthMode, reason: String) :
    NativeWalletStoreError("ERR_WALLET_AUTH_UNAVAILABLE", "Authentication unavailable for $mode: $reason")

  /** `BiometricPrompt.ERROR_LOCKOUT` — too many failed attempts, temporary; clears itself after
   * a short OS-enforced cooldown. */
  class AuthLockedOutTemporary :
    NativeWalletStoreError("ERR_WALLET_AUTH_LOCKED_OUT", "Too many failed authentication attempts — try again later")

  /** `BiometricPrompt.ERROR_LOCKOUT_PERMANENT` — biometric auth is disabled until the user
   * unlocks the device with their device credential. */
  class AuthLockedOutPermanent :
    NativeWalletStoreError(
      "ERR_WALLET_AUTH_LOCKED_OUT_PERMANENT",
      "Too many failed authentication attempts — unlock your device to reset"
    )

  /** User dismissed the prompt (back/negative-button/system-cancel) rather than authentication
   * actually failing. Kept distinct from [AuthenticationFailed] so callers can treat it as a
   * quiet no-op instead of an error to surface. */
  class AuthCancelled :
    NativeWalletStoreError("ERR_WALLET_AUTH_CANCELLED", "Authentication was cancelled")

  /** `KeyPermanentlyInvalidatedException` from the Keystore — the wallet's key was invalidated
   * by an enrollment or lock-screen change since it was created and can never be unlocked again.
   * There is no recovery for this wallet's on-disk mnemonic file; the user must restore from
   * their recovery phrase. */
  class KeyInvalidated(walletId: String, cause: Throwable? = null) :
    NativeWalletStoreError(
      "ERR_WALLET_KEY_INVALIDATED",
      "Wallet key invalidated by a device security change: $walletId",
      cause
    )
}

/**
 * Persists mnemonics as files encrypted with an Android Keystore AES key (one key per wallet),
 * plus a parallel ungated metadata store (walletId -> per-chain addresses) for read-only UI.
 * Deliberately not `EncryptedSharedPreferences` or wallet-core's `StoredKey` keystore-JSON —
 * confidentiality comes from the Keystore key never leaving secure hardware when the device has
 * any, not from the on-disk file encoding.
 *
 * ### Hardware backing is requested and verified, not assumed
 *
 * [getOrCreateKey] requests the strongest hardware backing available: StrongBox first (API 28+,
 * `setIsStrongBoxBacked(true)`), falling back to a plain (TEE-or-better) Keystore key on
 * `StrongBoxUnavailableException` or below API 28. Android Keystore keys can still end up
 * software-only on devices/emulators without secure hardware, so after generating a fresh key
 * this module inspects its actual [KeyInfo] and logs the real level achieved
 * ([logKeySecurityLevel]) rather than asserting it blindly. Per this module's security model, a
 * software-only key is tolerated (best-effort, never blocks wallet creation) — see the README's
 * Security model section for the full policy.
 *
 * ### Biometric vs. device-credential: two separate flows, not one combined prompt
 *
 * Every wallet's key is gated by exactly one [AuthMode], chosen once at creation
 * ([resolveAvailableMode]) and thereafter recovered from which Keystore alias exists
 * ([resolveExistingMode]). The two modes are handled as genuinely separate flows rather than one
 * `BiometricPrompt` requesting `BIOMETRIC_STRONG | DEVICE_CREDENTIAL` together, because per
 * https://developer.android.com/identity/sign-in/biometric-auth that combination (and
 * `DEVICE_CREDENTIAL` alone via `setAllowedAuthenticators`) is not supported on API 29 and below,
 * and per https://developer.android.com/privacy-and-security/keystore a per-use
 * (`setUserAuthenticationValidityDurationSeconds(-1)`) key is restricted to biometric-only
 * authentication pre-API-30 regardless of what the prompt requests. `BIOMETRIC_STRONG`-mode keeps
 * today's strict "fresh prompt for every single operation" semantics; `DEVICE_CREDENTIAL`-mode
 * uses a short bounded validity window instead (see [getOrCreateKey]) and never binds a
 * `CryptoObject` to its prompt on any API level, since androidx.biometric only added
 * `CryptoObject` support for device-credential auth from API 30 onward. Every prompt path also
 * runs a `BiometricManager.canAuthenticate()` precheck before opening any UI, so availability
 * problems (not enrolled, no hardware, locked out, security patch required) surface as a specific
 * typed error instead of a generic mid-prompt failure.
 *
 * A wallet created before this split shipped still carries a third possible mode,
 * [AuthMode.LEGACY_COMBINED] — [resolveExistingMode] and [authenticateForExistingWallet] both
 * handle it so such a wallet stays reachable, but [resolveAvailableMode] (the only path that
 * chooses a *new* wallet's mode) never produces it. See that case's doc for why it exists.
 */
object NativeWalletStore {
  private const val TAG = "NativeWalletStore"
  private const val KEY_ALIAS_PREFIX = "vault_wallet_"
  private const val ANDROID_KEYSTORE = "AndroidKeyStore"
  private const val TRANSFORMATION = "AES/GCM/NoPadding"
  private const val GCM_IV_LENGTH = 12
  private const val GCM_TAG_LENGTH_BITS = 128
  private const val WALLETS_DIR = "vault_wallets"
  private const val METADATA_FILE = "metadata.json"

  /** How long a `DEVICE_CREDENTIAL`-mode key stays usable after a confirmed device-credential
   * unlock. Chosen to comfortably absorb normal prompt-dismiss-to-cipher-init latency without
   * leaving a needlessly wide window open. */
  private const val WINDOW_SECONDS = 30

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

  /** Self-describing alias: which [AuthMode] gates a wallet's key is recoverable purely from
   * which of these two aliases exists for it (see [resolveExistingMode]), with no separate
   * metadata field needed. */
  internal fun keyAlias(mode: AuthMode, walletId: String): String = KEY_ALIAS_PREFIX + mode.aliasInfix + walletId

  private fun getOrCreateKey(walletId: String, mode: AuthMode): SecretKey {
    val alias = keyAlias(mode, walletId)
    val ks = keyStore()
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }

    val key = generateKey(alias, mode)
    logKeySecurityLevel(alias, key)
    return key
  }

  /** Builds the [KeyGenParameterSpec] shared by both the StrongBox-requested attempt and its
   * fallback — everything except whether StrongBox is requested is identical, so this is
   * parameterized on [strongBox] rather than duplicated. */
  private fun buildKeySpec(alias: String, mode: AuthMode, strongBox: Boolean): KeyGenParameterSpec {
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)

    when (mode) {
      AuthMode.BIOMETRIC_STRONG ->
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          // Single authenticator type only (no DEVICE_CREDENTIAL bit) — combining types is
          // unsupported pre-API-30, which is exactly why DEVICE_CREDENTIAL is a wholly separate
          // mode/key rather than an OR'd-in fallback on this same key.
          builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
          // Pre-R, a validity duration of -1 is documented to restrict the key to biometric
          // authentication only (https://developer.android.com/privacy-and-security/keystore)
          // — exactly the semantics this mode wants, with no explicit type parameter available
          // at this API level.
          @Suppress("DEPRECATION")
          builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

      AuthMode.DEVICE_CREDENTIAL ->
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          builder.setUserAuthenticationParameters(WINDOW_SECONDS, KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else {
          // Pre-R has no type-restriction parameter for a windowed key — it accepts a recent
          // keyguard unlock by any registered method. If the user later enrolls a fingerprint, a
          // biometric unlock within the window would also satisfy this key; that's an
          // unavoidable platform limitation of setUserAuthenticationValidityDurationSeconds, not
          // a bug here (see the class doc and the manual test matrix in the remediation plan).
          @Suppress("DEPRECATION")
          builder.setUserAuthenticationValidityDurationSeconds(WINDOW_SECONDS)
        }

      AuthMode.LEGACY_COMBINED ->
        // Unreachable in practice: getOrCreateKey only calls this when no existing alias was
        // found, and LEGACY_COMBINED is only ever returned by resolveExistingMode for an alias
        // that, by definition, already exists — resolveAvailableMode (the only source of a
        // *new* wallet's mode) never returns it. Fails loudly rather than silently minting a
        // new key under a scheme this codebase deliberately stopped creating.
        error("LEGACY_COMBINED keys are never freshly generated — resolveExistingMode found alias '$alias' but getOrCreateKey couldn't retrieve it")
    }

    if (strongBox) {
      builder.setIsStrongBoxBacked(true)
    }

    return builder.build()
  }

  /** Requests the strongest hardware backing available for a brand-new key: StrongBox first
   * (API 28+), falling back to a plain Keystore key — which Keymaster may still back with a TEE
   * or, on devices without secure hardware, software only — on [StrongBoxUnavailableException]
   * or below API 28 (`setIsStrongBoxBacked` doesn't exist pre-P). The actual level achieved is
   * verified separately by [logKeySecurityLevel]; this function never inspects it. */
  private fun generateKey(alias: String, mode: AuthMode): SecretKey {
    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        keyGenerator.init(buildKeySpec(alias, mode, strongBox = true))
        return keyGenerator.generateKey()
      } catch (e: StrongBoxUnavailableException) {
        Log.i(TAG, "StrongBox unavailable for $alias, falling back to a non-StrongBox key", e)
      }
    }
    keyGenerator.init(buildKeySpec(alias, mode, strongBox = false))
    return keyGenerator.generateKey()
  }

  /** Pure `KeyInfo.securityLevel` -> human-readable-level mapping (API 31+), extracted so it's
   * JVM-testable without a real Keystore key. */
  internal fun describeSecurityLevel(securityLevel: Int): String = when (securityLevel) {
    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
    else -> "UNKNOWN($securityLevel)"
  }

  /** Pure legacy `KeyInfo.isInsideSecureHardware` -> human-readable-level mapping (below API 31,
   * where `getSecurityLevel()` doesn't exist and TEE vs. StrongBox can't be distinguished),
   * extracted so it's JVM-testable without a real Keystore key. */
  internal fun describeLegacySecurityLevel(insideSecureHardware: Boolean): String =
    if (insideSecureHardware) "HARDWARE" else "SOFTWARE"

  /** Verifies and logs the actual security level of a freshly generated key — best-effort only:
   * this module's security model tolerates a software-only key (e.g. an emulator, or a device
   * with no secure hardware at all) rather than blocking wallet creation, so this never throws
   * on either a software-only result or an introspection failure, it only logs. Only called for
   * freshly generated keys, not ones retrieved from an existing alias — the level can't change
   * after creation, so re-checking on every retrieval would just be log noise. */
  private fun logKeySecurityLevel(alias: String, key: SecretKey) {
    try {
      // SecretKeyFactory, not KeyFactory — KeyFactory is for asymmetric KeyPair material
      // (PrivateKey/PublicKey); AndroidKeyStore only registers a symmetric-key ("AES") service
      // under SecretKeyFactory, so KeyFactory.getInstance("AES", "AndroidKeyStore") throws
      // NoSuchAlgorithmException for a SecretKey like this one.
      // The Android stub's getKeySpec(SecretKey, Class<?>) is non-generic (unlike the desktop
      // JDK's), returning a raw KeySpec — an explicit cast to KeyInfo is required here.
      val keyInfo = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        .getKeySpec(key, KeyInfo::class.java) as KeyInfo
      val description = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        describeSecurityLevel(keyInfo.securityLevel)
      } else {
        @Suppress("DEPRECATION")
        describeLegacySecurityLevel(keyInfo.isInsideSecureHardware)
      }
      if (description == "SOFTWARE") {
        Log.w(TAG, "Keystore key $alias is NOT hardware-backed (level=$description) — this device has no usable secure hardware, falling back to software-only protection")
      } else {
        Log.i(TAG, "Keystore key $alias security level: $description")
      }
    } catch (e: Exception) {
      Log.w(TAG, "Could not determine security level for Keystore key $alias", e)
    }
  }

  /** Resolves which [AuthMode] to gate a *new* wallet's key with, preferring `BIOMETRIC_STRONG`
   * and falling back to `DEVICE_CREDENTIAL`. Throws [NativeWalletStoreError.NoSecureAuthAvailable]
   * rather than ever creating a key that couldn't possibly be unlocked. */
  private fun resolveAvailableMode(context: Context): AuthMode {
    val biometricManager = BiometricManager.from(context)
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
      BiometricManager.BIOMETRIC_SUCCESS
    ) {
      return AuthMode.BIOMETRIC_STRONG
    }
    if (deviceCredentialAvailable(context, biometricManager)) {
      return AuthMode.DEVICE_CREDENTIAL
    }
    throw NativeWalletStoreError.NoSecureAuthAvailable()
  }

  /** `BiometricManager.canAuthenticate(DEVICE_CREDENTIAL)` is itself unsupported pre-API-30
   * (same restriction as the combined-authenticator case), so pre-30 this asks the keyguard
   * directly whether a screen lock is set instead. */
  private fun deviceCredentialAvailable(context: Context, biometricManager: BiometricManager): Boolean =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL) ==
        BiometricManager.BIOMETRIC_SUCCESS
    } else {
      ContextCompat.getSystemService(context, KeyguardManager::class.java)?.isDeviceSecure == true
    }

  /** Recovers which [AuthMode] an *existing* wallet's key was created with, purely from which
   * Keystore alias exists — see [keyAlias]. Checks [AuthMode.LEGACY_COMBINED] last: a wallet
   * created before the biometric/device-credential split (see that case's doc) would otherwise
   * be permanently unreachable despite its key and metadata both still being intact — this was
   * found to actually happen, not just a theoretical gap. */
  private fun resolveExistingMode(walletId: String): AuthMode {
    val ks = keyStore()
    if (ks.containsAlias(keyAlias(AuthMode.BIOMETRIC_STRONG, walletId))) return AuthMode.BIOMETRIC_STRONG
    if (ks.containsAlias(keyAlias(AuthMode.DEVICE_CREDENTIAL, walletId))) return AuthMode.DEVICE_CREDENTIAL
    if (ks.containsAlias(keyAlias(AuthMode.LEGACY_COMBINED, walletId))) return AuthMode.LEGACY_COMBINED
    throw NativeWalletStoreError.NotFound(walletId)
  }

  /** The `canAuthenticate()` precheck required before every use-time prompt (not just at
   * creation): confirms the wallet's already-committed [mode] is still satisfiable *before* any
   * prompt UI opens, so an enrollment/lock-screen change surfaces as a specific
   * [NativeWalletStoreError.AuthUnavailable] instead of a generic mid-prompt failure. */
  private fun precheckExistingMode(context: Context, mode: AuthMode) {
    val biometricManager = BiometricManager.from(context)
    val available = when (mode) {
      AuthMode.BIOMETRIC_STRONG ->
        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
          BiometricManager.BIOMETRIC_SUCCESS
      AuthMode.DEVICE_CREDENTIAL -> deviceCredentialAvailable(context, biometricManager)
      // Accepts either, same as the key itself does — mirrors resolveAvailableMode's
      // BIOMETRIC_STRONG-or-DEVICE_CREDENTIAL precedence rather than requiring both.
      AuthMode.LEGACY_COMBINED ->
        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
          BiometricManager.BIOMETRIC_SUCCESS || deviceCredentialAvailable(context, biometricManager)
    }
    if (!available) {
      val result = if (mode == AuthMode.BIOMETRIC_STRONG) {
        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      } else {
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
      }
      throw NativeWalletStoreError.AuthUnavailable(mode, describeUnavailableReason(result))
    }
  }

  /** Pure `canAuthenticate()`-result -> human-readable-reason mapping, extracted so it's
   * JVM-testable without a real `BiometricManager`. */
  internal fun describeUnavailableReason(canAuthenticateResult: Int): String = when (canAuthenticateResult) {
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "no biometric or device credential is enrolled"
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "no biometric hardware present"
    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "biometric hardware currently unavailable"
    BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "a security update is required"
    BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "authentication is unsupported on this device"
    BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "authentication status could not be determined"
    else -> "unavailable (status $canAuthenticateResult)"
  }

  private fun buildEncryptCipher(walletId: String, mode: AuthMode): Cipher {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    initCipherOrThrow(walletId) { cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(walletId, mode)) }
    return cipher
  }

  private fun buildDecryptCipher(context: Context, walletId: String, mode: AuthMode): Cipher {
    val file = mnemonicFile(context, walletId)
    if (!file.exists()) throw NativeWalletStoreError.NotFound(walletId)
    val iv = file.readBytes().copyOfRange(0, GCM_IV_LENGTH)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    initCipherOrThrow(walletId) {
      cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(walletId, mode), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
    }
    return cipher
  }

  /** Centralizes the two ways a Keystore-backed `Cipher.init()` can fail for an auth-gated key:
   * permanently (enrollment/lock-screen changed since the key was created — unrecoverable) or
   * transiently (a `DEVICE_CREDENTIAL`-mode window that closed before the cipher was opened —
   * the caller should just prompt again). */
  private inline fun initCipherOrThrow(walletId: String, init: () -> Unit) {
    try {
      init()
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw NativeWalletStoreError.KeyInvalidated(walletId, e)
    } catch (e: UserNotAuthenticatedException) {
      throw NativeWalletStoreError.AuthenticationFailed("authentication window expired before the cipher could be opened")
    }
  }

  // MARK: - Mnemonic (biometry/device-credential gated)

  /** Encrypts and writes the mnemonic. Also requires user authentication (the key itself is
   * auth-gated for every use, encrypt included) — callers should invoke this right after a
   * successful [authenticateForNewWallet] call, same as [loadMnemonic] after
   * [authenticateForExistingWallet]. */
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
   * are checked and propagate on failure — neither is silently discarded. Tries all three
   * possible aliases, including [AuthMode.LEGACY_COMBINED] (only one will ever exist for a given
   * wallet), so cleanup doesn't need to know which mode a wallet used — `KeyStore.deleteEntry` on
   * the AndroidKeyStore provider is a documented no-op (not a throw) for an alias that doesn't
   * exist. */
  fun deleteMnemonic(context: Context, walletId: String) {
    deleteFileChecked(mnemonicFile(context, walletId), walletId)
    try {
      val ks = keyStore()
      ks.deleteEntry(keyAlias(AuthMode.BIOMETRIC_STRONG, walletId))
      ks.deleteEntry(keyAlias(AuthMode.DEVICE_CREDENTIAL, walletId))
      ks.deleteEntry(keyAlias(AuthMode.LEGACY_COMBINED, walletId))
    } catch (e: Exception) {
      throw NativeWalletStoreError.DeleteFailed(walletId, e)
    }
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

  /** Authenticates and returns a `Cipher` ready for [saveMnemonic], for a brand-new wallet id.
   * Resolves which [AuthMode] to gate the new key with via [resolveAvailableMode] (a
   * `canAuthenticate()`-based precheck) before creating anything. */
  suspend fun authenticateForNewWallet(
    activity: FragmentActivity,
    context: Context,
    walletId: String,
    title: String,
  ): Cipher =
    when (val mode = resolveAvailableMode(context)) {
      AuthMode.BIOMETRIC_STRONG -> authenticateBiometric(activity, buildEncryptCipher(walletId, mode), title)
      AuthMode.DEVICE_CREDENTIAL -> {
        confirmDeviceCredential(activity, title)
        buildEncryptCipher(walletId, mode)
      }
      // Unreachable: resolveAvailableMode never returns LEGACY_COMBINED — see that case's doc.
      AuthMode.LEGACY_COMBINED -> error("resolveAvailableMode returned LEGACY_COMBINED, which it must never do")
    }

  /** Authenticates and returns a `Cipher` ready for [loadMnemonic], for an existing wallet id.
   * Recovers the wallet's already-committed [AuthMode] via [resolveExistingMode] and runs the
   * [precheckExistingMode] availability check before opening any prompt UI. */
  suspend fun authenticateForExistingWallet(
    activity: FragmentActivity,
    context: Context,
    walletId: String,
    title: String,
  ): Cipher {
    val mode = resolveExistingMode(walletId)
    precheckExistingMode(context, mode)
    return when (mode) {
      AuthMode.BIOMETRIC_STRONG -> authenticateBiometric(activity, buildDecryptCipher(context, walletId, mode), title)
      AuthMode.DEVICE_CREDENTIAL -> {
        confirmDeviceCredential(activity, title)
        buildDecryptCipher(context, walletId, mode)
      }
      AuthMode.LEGACY_COMBINED ->
        authenticateCombinedLegacy(activity, buildDecryptCipher(context, walletId, mode), title)
    }
  }

  /** `BIOMETRIC_STRONG`-only, `CryptoObject`-bound prompt — the cipher is built+`init()`'d
   * *before* this is called; the prompt authorizes that specific already-initialized operation
   * handle, per the standard Keystore per-op-key pattern (unchanged from before this
   * remediation). Same main-thread requirement as [confirmDeviceCredential]: `BiometricPrompt`
   * drives a `FragmentManager` transaction, so this — and this call — must run on the main
   * thread; callers reach this via `AsyncFunction(...) Coroutine { ... }`, which Expo dispatches
   * on a background HandlerThread, not main. */
  private suspend fun authenticateBiometric(activity: FragmentActivity, cipher: Cipher, title: String): Cipher =
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
          onError = { code, errString -> continuation.resumeWithException(classifyPromptError(code, errString)) }
        )
        prompt.authenticate(
          singleAuthenticatorPromptInfo(title, BiometricManager.Authenticators.BIOMETRIC_STRONG),
          BiometricPrompt.CryptoObject(cipher)
        )
      }
    }

  /** Pre-migration combined `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`, `CryptoObject`-bound prompt —
   * this is exactly what [authenticateBiometric] replaced, preserved solely so an
   * [AuthMode.LEGACY_COMBINED] wallet (created before the split) stays unlockable. Never used for
   * a new key. Carries the same reliability caveat the split was written to fix: this combination
   * isn't reliably supported by `BiometricPrompt` on API 29 and below — an existing, unavoidable
   * (short of forcing every such wallet through a re-encrypt) limitation for old wallets on old
   * API levels, not a new regression. */
  private suspend fun authenticateCombinedLegacy(activity: FragmentActivity, cipher: Cipher, title: String): Cipher =
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
          onError = { code, errString -> continuation.resumeWithException(classifyPromptError(code, errString)) }
        )
        prompt.authenticate(
          singleAuthenticatorPromptInfo(
            title,
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
          ),
          BiometricPrompt.CryptoObject(cipher)
        )
      }
    }

  /** Crypto-object-less confirmation prompt — for gating operations like `deleteWallet` that
   * don't perform a Keystore encrypt/decrypt themselves, so there's no `Cipher` to bind the
   * prompt to (and binding to one would wrongly fail when e.g. cleaning up a wallet whose key
   * is already broken/missing). Resolves availability the same way wallet creation does, since
   * deleting isn't tied to any specific wallet's committed key mode — this always chooses between
   * the two *creatable* modes, never [AuthMode.LEGACY_COMBINED] (see [resolveAvailableMode]). */
  suspend fun confirmIdentity(activity: FragmentActivity, context: Context, title: String) {
    when (resolveAvailableMode(context)) {
      AuthMode.BIOMETRIC_STRONG -> confirmSingleAuthenticator(activity, title, BiometricManager.Authenticators.BIOMETRIC_STRONG)
      AuthMode.DEVICE_CREDENTIAL -> confirmDeviceCredential(activity, title)
      // Unreachable: resolveAvailableMode never returns LEGACY_COMBINED — see that case's doc.
      AuthMode.LEGACY_COMBINED -> error("resolveAvailableMode returned LEGACY_COMBINED, which it must never do")
    }
  }

  private suspend fun confirmSingleAuthenticator(activity: FragmentActivity, title: String, authenticator: Int) {
    withContext(Dispatchers.Main) {
      suspendCoroutine<Unit> { continuation ->
        val prompt = biometricPrompt(
          activity,
          onSucceeded = { continuation.resume(Unit) },
          onError = { code, errString -> continuation.resumeWithException(classifyPromptError(code, errString)) }
        )
        prompt.authenticate(singleAuthenticatorPromptInfo(title, authenticator))
      }
    }
  }

  /** Device-credential-only confirmation, deliberately never `CryptoObject`-bound on any API
   * level (see the class doc for why). Used both directly by [confirmIdentity] and as the first
   * step of [authenticateForNewWallet]/[authenticateForExistingWallet]'s `DEVICE_CREDENTIAL`
   * branch, where the cipher is built immediately *after* this succeeds instead of being bound
   * to the prompt. */
  private suspend fun confirmDeviceCredential(activity: FragmentActivity, title: String) {
    withContext(Dispatchers.Main) {
      suspendCoroutine<Unit> { continuation ->
        val prompt = biometricPrompt(
          activity,
          onSucceeded = { continuation.resume(Unit) },
          onError = { code, errString -> continuation.resumeWithException(classifyPromptError(code, errString)) }
        )
        prompt.authenticate(deviceCredentialPromptInfo(title))
      }
    }
  }

  private fun singleAuthenticatorPromptInfo(title: String, authenticator: Int): BiometricPrompt.PromptInfo =
    BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setAllowedAuthenticators(authenticator)
      .build()

  private fun deviceCredentialPromptInfo(title: String): BiometricPrompt.PromptInfo =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      singleAuthenticatorPromptInfo(title, BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    } else {
      // setAllowedAuthenticators(DEVICE_CREDENTIAL) alone is unsupported pre-API-30; the
      // deprecated setDeviceCredentialAllowed(true) is the only way to request a
      // device-credential-only confirmation on API 24-29, and never supports a CryptoObject —
      // exactly why DEVICE_CREDENTIAL mode never binds one, on any API level.
      @Suppress("DEPRECATION")
      BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setDeviceCredentialAllowed(true)
        .build()
    }

  /** Pure `errorCode` -> typed-error mapping, extracted so it's JVM-testable without a real
   * `BiometricPrompt`. */
  internal fun classifyPromptError(errorCode: Int, errString: String): NativeWalletStoreError = when (errorCode) {
    BiometricPrompt.ERROR_LOCKOUT -> NativeWalletStoreError.AuthLockedOutTemporary()
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> NativeWalletStoreError.AuthLockedOutPermanent()
    BiometricPrompt.ERROR_USER_CANCELED,
    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
    BiometricPrompt.ERROR_CANCELED,
    -> NativeWalletStoreError.AuthCancelled()
    else -> NativeWalletStoreError.AuthenticationFailed(errString, errorCode)
  }

  private fun biometricPrompt(
    activity: FragmentActivity,
    onSucceeded: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: (Int, String) -> Unit,
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
          onError(errorCode, errString.toString())
        }

        override fun onAuthenticationFailed() {
          // Not terminal — BiometricPrompt keeps the sheet open for retry; only
          // onAuthenticationError/onAuthenticationSucceeded resolve the continuation.
        }
      }
    )
  }
}
