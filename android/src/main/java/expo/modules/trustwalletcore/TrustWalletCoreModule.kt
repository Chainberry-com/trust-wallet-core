package expo.modules.trustwalletcore

import android.app.AlertDialog
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.suspendCancellableCoroutine
import wallet.core.jni.HDWallet
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

// Mnemonic/private-key material never crosses back to JS except `exportMnemonic` — an
// explicit, biometric/device-credential-gated backup flow. Every other method returns only
// walletIds, addresses, or signed transaction bytes/hex.
class TrustWalletCoreModule : Module() {
  companion object {
    init {
      // Must be loaded once before any JNI calls
      System.loadLibrary("TrustWalletCore")
    }
  }

  private val context get() = appContext.reactContext
    ?: throw CodedException("NoContext", "React context unavailable", null)

  private val activity: FragmentActivity
    get() = appContext.currentActivity as? FragmentActivity
      ?: throw CodedException("NoActivity", "No foreground FragmentActivity to host the biometric prompt", null)

  override fun definition() = ModuleDefinition {
    Name("TrustWalletCore")

    // strength 128 = 12 words, 256 = 24 words. Returns { walletId, addresses }.
    // No BIP-39 passphrase support: signTransaction always reconstructs the wallet with an
    // empty passphrase, so accepting one here would derive addresses from a seed different
    // from the one actually used to sign — always pass "" to stay consistent with that.
    // isTestnet selects the address format for BTC/LTC/BCH (see ChainSigner.addressForChain) —
    // every other chain's address is the same on mainnet and testnet.
    AsyncFunction("createWallet") Coroutine { strength: Int, isTestnet: Boolean ->
      val wallet = HDWallet(strength, "")
      persistNewWallet(wallet, isTestnet)
    }

    // One-time mnemonic exposure from JS, at import only — never retained after this call.
    // Returns { walletId, addresses }. No BIP-39 passphrase support (see `createWallet`).
    AsyncFunction("importWallet") Coroutine { mnemonic: String, isTestnet: Boolean ->
      val wallet = HDWallet(mnemonic, "") // throws on invalid mnemonic
      persistNewWallet(wallet, isTestnet)
    }

    // Reads only the ungated metadata store — no biometric prompt.
    AsyncFunction("listWallets") {
      NativeWalletStore.loadMetadata(context).map { (walletId, addresses) ->
        mapOf("walletId" to walletId, "addresses" to addresses)
      }
    }

    // Irreversible — requires a fresh biometric/device-credential confirmation before
    // anything is deleted, same gate as `signTransaction`/`exportMnemonic`. A
    // compromised/malicious JS caller can still invoke this directly (there's no UI call
    // site today), so the gate must live here rather than in JS.
    AsyncFunction("deleteWallet") Coroutine { walletId: String ->
      val id = NativeWalletStore.validateWalletId(walletId)
      NativeWalletStore.confirmIdentity(activity, context, "Delete wallet")
      NativeWalletStore.deleteMnemonic(context, id)
      val metadata = NativeWalletStore.loadMetadata(context).toMutableMap()
      metadata.remove(id)
      NativeWalletStore.saveMetadata(context, metadata)
    }

    // Triggers the native biometry/device-credential prompt, then signs entirely in-process.
    // Returns { signedTx, meta? }. isTestnet must match whatever `createWallet`/`importWallet`
    // used — see ChainSigner.keyForChain (a mismatch signs with the wrong key for BTC/LTC).
    AsyncFunction("signTransaction") Coroutine { walletId: String, chain: String, unsignedTx: Map<String, Any>, isTestnet: Boolean ->
      val id = NativeWalletStore.validateWalletId(walletId)
      val chainKey = ChainKey.fromJs(chain)
      confirmTransaction(chainKey, unsignedTx)
      val cipher = NativeWalletStore.authenticateForExistingWallet(activity, context, id, "Sign transaction")
      val mnemonic = NativeWalletStore.loadMnemonic(context, id, cipher)
      val wallet = HDWallet(mnemonic, "")
      val result = ChainSigner.sign(chainKey, wallet, unsignedTx, isTestnet)
      val response = mutableMapOf<String, Any>("signedTx" to result.signedTx)
      result.meta?.let { response["meta"] = it }
      response
    }

    // The one sanctioned mnemonic exposure — explicit backup flow only.
    AsyncFunction("exportMnemonic") Coroutine { walletId: String ->
      val id = NativeWalletStore.validateWalletId(walletId)
      val cipher = NativeWalletStore.authenticateForExistingWallet(activity, context, id, "Reveal recovery phrase")
      NativeWalletStore.loadMnemonic(context, id, cipher)
    }
  }

  /// Shows a native AlertDialog with decoded tx details before biometric auth fires.
  /// The user must tap "Confirm & Sign" — cancelling throws UserCancelled.
  private suspend fun confirmTransaction(chain: ChainKey, unsignedTx: Map<String, Any>) {
    val message = ChainSigner.buildSummary(chain, unsignedTx)
    suspendCancellableCoroutine<Unit> { continuation ->
      activity.runOnUiThread {
        AlertDialog.Builder(activity)
          .setTitle("Confirm Transaction")
          .setMessage(message)
          .setPositiveButton("Confirm & Sign") { _, _ -> continuation.resume(Unit) }
          .setNegativeButton("Cancel") { _, _ ->
            continuation.resumeWithException(
              CodedException("UserCancelled", "Transaction cancelled by user", null)
            )
          }
          .setOnCancelListener {
            continuation.resumeWithException(
              CodedException("UserCancelled", "Transaction cancelled by user", null)
            )
          }
          .show()
      }
    }
  }

  private suspend fun persistNewWallet(wallet: HDWallet, isTestnet: Boolean): Map<String, Any> {
    val walletId = UUID.randomUUID().toString()
    val addresses = ChainKey.entries.associate { chain ->
      chain.name.lowercase() to ChainSigner.addressForChain(wallet, chain, isTestnet)
    }

    val cipher = NativeWalletStore.authenticateForNewWallet(activity, context, walletId, "Secure your new wallet")
    NativeWalletStore.saveMnemonic(context, walletId, wallet.mnemonic(), cipher)

    try {
      val metadata = NativeWalletStore.loadMetadata(context).toMutableMap()
      metadata[walletId] = addresses
      NativeWalletStore.saveMetadata(context, metadata)
    } catch (e: Exception) {
      // The mnemonic/key is already persisted but has no metadata pointer — compensate by
      // best-effort deleting it rather than leaving a permanent, invisible orphan. If this
      // rollback delete also fails, there's nothing more useful to do than propagate the
      // original error; the wallet is at least no worse off than before this call.
      runCatching { NativeWalletStore.deleteMnemonic(context, walletId) }
      throw e
    }

    return mapOf("walletId" to walletId, "addresses" to addresses)
  }
}
