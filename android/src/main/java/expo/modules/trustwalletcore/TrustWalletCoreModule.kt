package expo.modules.trustwalletcore

import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import wallet.core.jni.HDWallet
import java.util.UUID

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
    AsyncFunction("createWallet") Coroutine { strength: Int, passphrase: String ->
      val wallet = HDWallet(strength, passphrase)
      persistNewWallet(wallet)
    }

    // One-time mnemonic exposure from JS, at import only — never retained after this call.
    // Returns { walletId, addresses }.
    AsyncFunction("importWallet") Coroutine { mnemonic: String, passphrase: String ->
      val wallet = HDWallet(mnemonic, passphrase) // throws on invalid mnemonic
      persistNewWallet(wallet)
    }

    // Reads only the ungated metadata store — no biometric prompt.
    AsyncFunction("listWallets") {
      NativeWalletStore.loadMetadata(context).map { (walletId, addresses) ->
        mapOf("walletId" to walletId, "addresses" to addresses)
      }
    }

    AsyncFunction("deleteWallet") { walletId: String ->
      NativeWalletStore.deleteMnemonic(context, walletId)
      val metadata = NativeWalletStore.loadMetadata(context).toMutableMap()
      metadata.remove(walletId)
      NativeWalletStore.saveMetadata(context, metadata)
    }

    // Triggers the native biometry/device-credential prompt, then signs entirely in-process.
    // Returns { signedTx, meta? }.
    AsyncFunction("signTransaction") Coroutine { walletId: String, chain: String, unsignedTx: Map<String, Any> ->
      val chainKey = ChainKey.fromJs(chain)
      val cipher = NativeWalletStore.authenticate(activity, NativeWalletStore.decryptCipher(context, walletId), "Sign transaction")
      val mnemonic = NativeWalletStore.loadMnemonic(context, walletId, cipher)
      val wallet = HDWallet(mnemonic, "")
      val result = ChainSigner.sign(chainKey, wallet, unsignedTx)
      val response = mutableMapOf<String, Any>("signedTx" to result.signedTx)
      result.meta?.let { response["meta"] = it }
      response
    }

    // The one sanctioned mnemonic exposure — explicit backup flow only.
    AsyncFunction("exportMnemonic") Coroutine { walletId: String ->
      val cipher = NativeWalletStore.authenticate(activity, NativeWalletStore.decryptCipher(context, walletId), "Reveal recovery phrase")
      NativeWalletStore.loadMnemonic(context, walletId, cipher)
    }
  }

  private suspend fun persistNewWallet(wallet: HDWallet): Map<String, Any> {
    val walletId = UUID.randomUUID().toString()
    val addresses = ChainKey.entries.associate { chain -> chain.name.lowercase() to wallet.getAddressForCoin(chain.coinType) }

    val cipher = NativeWalletStore.authenticate(activity, NativeWalletStore.encryptCipher(walletId), "Secure your new wallet")
    NativeWalletStore.saveMnemonic(context, walletId, wallet.mnemonic(), cipher)

    val metadata = NativeWalletStore.loadMetadata(context).toMutableMap()
    metadata[walletId] = addresses
    NativeWalletStore.saveMetadata(context, metadata)

    return mapOf("walletId" to walletId, "addresses" to addresses)
  }
}
