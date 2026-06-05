package expo.modules.trustwalletcore

import com.google.protobuf.ByteString
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import wallet.core.java.AnySigner
import wallet.core.jni.CoinType
import wallet.core.jni.HDWallet
import wallet.core.jni.PrivateKey
import wallet.core.jni.proto.Common
import wallet.core.jni.proto.Ethereum
import wallet.core.jni.proto.Solana
import java.math.BigInteger

class TrustWalletCoreModule : Module() {
  companion object {
    init {
      // Must be loaded once before any JNI calls
      System.loadLibrary("TrustWalletCore")
    }
  }

  override fun definition() = ModuleDefinition {
    Name("TrustWalletCore")

    // Returns { mnemonic } — strength 128 = 12 words, 256 = 24 words
    AsyncFunction("generateWallet") { strength: Int, passphrase: String ->
      mapOf("mnemonic" to HDWallet(strength, passphrase).mnemonic())
    }

    // Validates mnemonic and returns { mnemonic }
    AsyncFunction("restoreWallet") { mnemonic: String, passphrase: String ->
      HDWallet(mnemonic, passphrase) // throws on invalid mnemonic
      mapOf("mnemonic" to mnemonic)
    }

    // Derives address and private key for a named coin
    // coin: "ethereum" | "solana"
    AsyncFunction("getAddressForCoin") { mnemonic: String, coin: String, passphrase: String ->
      val wallet = HDWallet(mnemonic, passphrase)
      val coinType = resolveCoinType(coin)
      mapOf(
        "address"    to wallet.getAddressForCoin(coinType),
        "privateKey" to wallet.getKeyForCoin(coinType).data().toHex(),
      )
    }

    // Signs an Ethereum transaction; returns 0x-prefixed RLP-encoded signed tx hex
    // txParams: { to, valueHex, nonce, gasLimitHex, chainId, dataHex?,
    //             gasPriceHex? (legacy) | maxFeePerGasHex + maxPriorityFeePerGasHex (EIP-1559) }
    AsyncFunction("signEthereumTransaction") { privateKeyHex: String, txParams: Map<String, Any> ->
      val privateKey = PrivateKey(privateKeyHex.hexToBytes())
      val to        = txParams["to"] as String
      val valueHex  = (txParams["valueHex"] as? String)?.ifEmpty { "0" } ?: "0"
      val nonce     = (txParams["nonce"] as Number).toInt()
      val gasLimHex = txParams["gasLimitHex"] as String
      val chainId   = (txParams["chainId"] as Number).toInt()
      val dataHex   = (txParams["dataHex"] as? String) ?: ""

      val input = Ethereum.SigningInput.newBuilder().apply {
        this.chainId    = BigInteger.valueOf(chainId.toLong()).toMinimalByteString()
        this.nonce      = BigInteger.valueOf(nonce.toLong()).toMinimalByteString()
        this.gasLimit   = BigInteger(gasLimHex, 16).toMinimalByteString()
        this.toAddress  = to
        this.privateKey = ByteString.copyFrom(privateKey.data())

        this.transaction = Ethereum.Transaction.newBuilder().apply {
          this.transfer = Ethereum.Transaction.Transfer.newBuilder().apply {
            this.amount = BigInteger(valueHex, 16).toMinimalByteString()
            if (dataHex.isNotEmpty()) this.data = ByteString.copyFrom(dataHex.hexToBytes())
          }.build()
        }.build()

        val gasPriceHex = txParams["gasPriceHex"] as? String
        if (gasPriceHex != null) {
          this.gasPrice = BigInteger(gasPriceHex, 16).toMinimalByteString()
        } else {
          val mfHex = txParams["maxFeePerGasHex"] as? String
          val pfHex = txParams["maxPriorityFeePerGasHex"] as? String
          if (mfHex != null && pfHex != null) {
            this.maxFeePerGas          = BigInteger(mfHex, 16).toMinimalByteString()
            this.maxInclusionFeePerGas = BigInteger(pfHex, 16).toMinimalByteString()
          }
        }
      }.build()

      val output = AnySigner.sign(input, CoinType.ETHEREUM, Ethereum.SigningOutput.parser())
      if (output.error != Common.SigningError.OK) {
        throw Exception("Signing failed: ${output.errorMessage}")
      }
      "0x" + output.encoded.toByteArray().toHex()
    }

    // Signs a Solana transfer; returns base64-encoded signed transaction
    // txParams: { to, lamports (string, lamports amount), recentBlockhash }
    AsyncFunction("signSolanaTransaction") { privateKeyHex: String, txParams: Map<String, Any> ->
      val privateKey      = PrivateKey(privateKeyHex.hexToBytes())
      val to              = txParams["to"] as String
      val lamports        = (txParams["lamports"] as String).toLong()
      val recentBlockhash = txParams["recentBlockhash"] as String

      val input = Solana.SigningInput.newBuilder().apply {
        this.recentBlockhash = recentBlockhash
        this.privateKey      = ByteString.copyFrom(privateKey.data())
        this.transferTransaction = Solana.Transfer.newBuilder().apply {
          this.recipient = to
          this.value     = lamports
        }.build()
      }.build()

      val output = AnySigner.sign(input, CoinType.SOLANA, Solana.SigningOutput.parser())
      if (output.error != Common.SigningError.OK) {
        throw Exception("Signing failed: ${output.errorMessage}")
      }
      output.encoded
    }
  }
}

// Helpers
private fun resolveCoinType(coin: String): CoinType = when (coin.lowercase()) {
  "ethereum" -> CoinType.ETHEREUM
  "solana"   -> CoinType.SOLANA
  else       -> throw IllegalArgumentException("Unsupported coin: $coin")
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexToBytes(): ByteArray {
  val s = removePrefix("0x").let { if (it.length % 2 == 0) it else "0$it" }
  return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

// BigInteger → minimal big-endian ByteString (strips Java's leading sign byte)
private fun BigInteger.toMinimalByteString(): ByteString {
  val raw = toByteArray()
  return if (raw.size > 1 && raw[0] == 0.toByte()) {
    ByteString.copyFrom(raw, 1, raw.size - 1)
  } else {
    ByteString.copyFrom(raw)
  }
}
