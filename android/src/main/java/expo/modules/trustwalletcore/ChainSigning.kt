package expo.modules.trustwalletcore

import com.google.protobuf.ByteString
import org.json.JSONObject
import wallet.core.java.AnySigner
import wallet.core.jni.CoinType
import wallet.core.jni.DataVector
import wallet.core.jni.HDWallet
import wallet.core.jni.SolanaTransaction
import wallet.core.jni.TransactionDecoder
import wallet.core.jni.proto.Bitcoin
import wallet.core.jni.proto.Common
import wallet.core.jni.proto.Ethereum
import wallet.core.jni.proto.Ripple
import wallet.core.jni.proto.Solana
import wallet.core.jni.proto.TheOpenNetwork
import wallet.core.jni.proto.Tron
import java.math.BigInteger

class ChainSigningException(message: String) : Exception(message)

// All chains this module derives addresses for / signs transactions for.
enum class ChainKey(val coinType: CoinType) {
  ETHEREUM(CoinType.ETHEREUM),
  BNB(CoinType.SMARTCHAIN),
  // Polygon shares Ethereum's secp256k1 key/address (same BIP44 path) — no distinct CoinType.
  POLYGON(CoinType.ETHEREUM),
  SOLANA(CoinType.SOLANA),
  TRON(CoinType.TRON),
  TON(CoinType.TON),
  BITCOIN(CoinType.BITCOIN),
  BITCOINCASH(CoinType.BITCOINCASH),
  LITECOIN(CoinType.LITECOIN),
  XRP(CoinType.XRP);

  companion object {
    fun fromJs(raw: String): ChainKey =
      entries.find { it.name.equals(raw, ignoreCase = true) }
        ?: throw ChainSigningException("Unsupported chain: $raw")
  }
}

data class ChainSignResult(val signedTx: String, val meta: Map<String, Any>?)

object ChainSigner {
  fun sign(chain: ChainKey, wallet: HDWallet, unsignedTx: Map<String, Any>): ChainSignResult = when (chain) {
    ChainKey.ETHEREUM, ChainKey.BNB, ChainKey.POLYGON ->
      ChainSignResult(signEvm(wallet, chain.coinType, unsignedTx), null)
    ChainKey.SOLANA -> ChainSignResult(signSolana(wallet, unsignedTx), null)
    ChainKey.BITCOIN, ChainKey.LITECOIN -> ChainSignResult(signUtxo(wallet, chain.coinType, unsignedTx), null)
    ChainKey.TRON -> ChainSignResult(signTron(wallet, unsignedTx), null)
    ChainKey.XRP -> ChainSignResult(signXrp(wallet, unsignedTx), null)
    ChainKey.TON -> signTon(wallet, unsignedTx)
    // Sending is intentionally unsupported: chainberry-wallet's prepareSelfCustodyUnsignedTx has
    // no BCH case — this app only ever needs BCH address derivation, never a signed BCH tx.
    ChainKey.BITCOINCASH -> throw ChainSigningException("BCH sending is not supported")
  }

  // MARK: - EVM (ethereum / bnb / polygon)
  // unsignedTx: { to, chainId, nonce, gasLimitHex, valueHex?, dataHex?,
  //               gasPriceHex? (legacy) | maxFeePerGasHex + maxPriorityFeePerGasHex (EIP-1559) }

  private fun signEvm(wallet: HDWallet, coin: CoinType, unsignedTx: Map<String, Any>): String {
    val privateKey = wallet.getKeyForCoin(coin)
    val to = unsignedTx["to"] as? String ?: throw ChainSigningException("Missing to")
    val nonce = (unsignedTx["nonce"] as? Number)?.toLong() ?: throw ChainSigningException("Missing nonce")
    val gasLimHex = unsignedTx["gasLimitHex"] as? String ?: throw ChainSigningException("Missing gasLimitHex")
    val chainId = (unsignedTx["chainId"] as? Number)?.toLong() ?: throw ChainSigningException("Missing chainId")
    val valueHex = (unsignedTx["valueHex"] as? String)?.ifEmpty { "0" } ?: "0"
    val dataHex = unsignedTx["dataHex"] as? String ?: ""

    val input = Ethereum.SigningInput.newBuilder().apply {
      this.chainId = BigInteger.valueOf(chainId).toMinimalByteString()
      this.nonce = BigInteger.valueOf(nonce).toMinimalByteString()
      this.gasLimit = BigInteger(gasLimHex, 16).toMinimalByteString()
      this.toAddress = to
      this.privateKey = ByteString.copyFrom(privateKey.data())

      this.transaction = Ethereum.Transaction.newBuilder().apply {
        this.transfer = Ethereum.Transaction.Transfer.newBuilder().apply {
          this.amount = BigInteger(valueHex, 16).toMinimalByteString()
          if (dataHex.isNotEmpty()) this.data = ByteString.copyFrom(dataHex.hexToBytes())
        }.build()
      }.build()

      val gasPriceHex = unsignedTx["gasPriceHex"] as? String
      if (gasPriceHex != null) {
        this.gasPrice = BigInteger(gasPriceHex, 16).toMinimalByteString()
      } else {
        val mfHex = unsignedTx["maxFeePerGasHex"] as? String
        val pfHex = unsignedTx["maxPriorityFeePerGasHex"] as? String
        if (mfHex != null && pfHex != null) {
          this.maxFeePerGas = BigInteger(mfHex, 16).toMinimalByteString()
          this.maxInclusionFeePerGas = BigInteger(pfHex, 16).toMinimalByteString()
        }
      }
    }.build()

    val output = AnySigner.sign(input, coin, Ethereum.SigningOutput.parser())
    if (output.error != Common.SigningError.OK) throw ChainSigningException("Signing failed: ${output.errorMessage}")
    return "0x" + output.encoded.toByteArray().toHex()
  }

  // MARK: - Solana
  // unsignedTx: { unsignedTxBase64: string } — a fully-built, base64-serialized unsigned
  // @solana/web3.js Transaction (native transfer or SPL-token transfer) from
  // prepareSelfCustodyUnsignedTx's SOL branch, already carrying a recentBlockhash/feePayer.
  // wallet-core has no "sign these raw bytes as-is" entry point for Solana — RawMessage is a
  // structured legacy/v0 message, not an opaque blob. `updateBlockhashAndSign` is TW's own
  // helper for signing an already-built web3.js transaction: it takes the base64 tx, a
  // recent blockhash, and a set of private keys, and re-serializes+signs. We don't have a
  // fresher blockhash than the one already embedded, so decode the tx to read it back out
  // (via TransactionDecoder) and hand it straight back in — a no-op "update" that still goes
  // through the sanctioned signing path.
  private fun signSolana(wallet: HDWallet, unsignedTx: Map<String, Any>): String {
    val privateKey = wallet.getKeyForCoin(CoinType.SOLANA)
    val unsignedTxBase64 = unsignedTx["unsignedTxBase64"] as? String
      ?: throw ChainSigningException("Missing unsignedTxBase64")
    val txBytes = android.util.Base64.decode(unsignedTxBase64, android.util.Base64.NO_WRAP)

    val decoded = Solana.DecodingTransactionOutput.parseFrom(TransactionDecoder.decode(CoinType.SOLANA, txBytes))
    if (decoded.error != Common.SigningError.OK) {
      throw ChainSigningException("Failed to decode Solana tx: ${decoded.errorMessage}")
    }
    val recentBlockhash = decoded.transaction.legacy.recentBlockhash

    val privateKeys = DataVector()
    privateKeys.add(privateKey.data())

    val output = Solana.SigningOutput.parseFrom(
      SolanaTransaction.updateBlockhashAndSign(unsignedTxBase64, recentBlockhash, privateKeys)
    )
    if (output.error != Common.SigningError.OK) throw ChainSigningException("Signing failed: ${output.errorMessage}")
    return output.encoded
  }

  // MARK: - BTC / LTC (UTXO-based)
  // unsignedTx (from wallet-broadcast's additive prepareBtcUtxoSet/prepareLtcUtxoSet):
  // { toAddress, changeAddress, sendAmountSats, changeAmountSats, satsPerByte,
  //   inputs: [{ txIdHex, vout, amountSats, scriptPubKeyHex }] }
  @Suppress("UNCHECKED_CAST")
  private fun signUtxo(wallet: HDWallet, coin: CoinType, unsignedTx: Map<String, Any>): String {
    val privateKey = wallet.getKeyForCoin(coin)
    val toAddress = unsignedTx["toAddress"] as? String ?: throw ChainSigningException("Missing toAddress")
    val changeAddress = unsignedTx["changeAddress"] as? String ?: throw ChainSigningException("Missing changeAddress")
    val sendAmountSats = (unsignedTx["sendAmountSats"] as? String)?.toLong() ?: throw ChainSigningException("Missing sendAmountSats")
    val satsPerByte = (unsignedTx["satsPerByte"] as? Number)?.toLong() ?: throw ChainSigningException("Missing satsPerByte")
    val inputs = unsignedTx["inputs"] as? List<Map<String, Any>> ?: throw ChainSigningException("Missing inputs")

    val utxos = inputs.map { entry ->
      val txIdHex = entry["txIdHex"] as? String ?: throw ChainSigningException("Invalid UTXO entry")
      val vout = (entry["vout"] as? Number)?.toInt() ?: throw ChainSigningException("Invalid UTXO entry")
      val amount = (entry["amountSats"] as? String)?.toLong() ?: throw ChainSigningException("Invalid UTXO entry")
      val scriptHex = entry["scriptPubKeyHex"] as? String ?: throw ChainSigningException("Invalid UTXO entry")

      // On-chain/explorer txid hex is displayed big-endian; wallet-core's OutPoint.hash wants
      // the reversed (little-endian, internal wire-format) byte order.
      val txIdBytes = txIdHex.hexToBytes().reversedArray()

      Bitcoin.UnspentTransaction.newBuilder().apply {
        this.outPoint = Bitcoin.OutPoint.newBuilder().apply {
          this.hash = ByteString.copyFrom(txIdBytes)
          this.index = vout
        }.build()
        this.amount = amount
        this.script = ByteString.copyFrom(scriptHex.hexToBytes())
      }.build()
    }

    val input = Bitcoin.SigningInput.newBuilder().apply {
      this.hashType = 1 // SIGHASH_ALL — stable Bitcoin protocol constant, not a wallet-core-specific value
      this.amount = sendAmountSats
      this.byteFee = satsPerByte
      this.toAddress = toAddress
      this.changeAddress = changeAddress
      this.useMaxAmount = false
      this.coinType = coin.value()
      this.addPrivateKey(ByteString.copyFrom(privateKey.data()))
      this.addAllUtxo(utxos)
    }.build()

    val output = AnySigner.sign(input, coin, Bitcoin.SigningOutput.parser())
    if (output.error != Common.SigningError.OK) throw ChainSigningException("Signing failed: ${output.errorMessage}")
    return output.encoded.toByteArray().toHex()
  }

  // MARK: - TRX
  // unsignedTx: the raw TronGrid-shaped unsigned tx object from prepareSelfCustodyUnsignedTx's
  // TRX branch (TronWeb's transactionBuilder output — raw_data, raw_data_hex, txID). Building a
  // Tron.Transaction proto from scratch would need the *full* source BlockHeader (parent hash,
  // tx trie root, witness address, version): wallet-core hashes that header itself to derive
  // ref_block_bytes/ref_block_hash, and TronGrid only ever hands us those two derived fields
  // pre-computed, not the header they came from — so there's no way to reconstruct one that
  // rehashes to the same values. Tron.SigningInput's `txId` field exists for exactly this case
  // (see its proto doc: "direct sign in Tron, we just have to sign the txId returned by the
  // DApp json payload") — it signs the given digest as-is and skips transaction rebuilding
  // entirely, which also means TRC20 `triggerSmartContract` payloads are covered for free, not
  // just plain transfers. wallet-core's direct-sign path only returns the raw signature (no
  // `json`), so the signed tx is assembled here the same way TronWeb does: original tx + a
  // `signature` array — the shape broadcastTrxTransaction's tronWeb.trx.sendRawTransaction expects.
  private fun signTron(wallet: HDWallet, unsignedTx: Map<String, Any>): String {
    val privateKey = wallet.getKeyForCoin(CoinType.TRON)
    val txId = unsignedTx["txID"] as? String ?: throw ChainSigningException("Missing txID")

    val input = Tron.SigningInput.newBuilder().apply {
      this.txId = txId
      this.privateKey = ByteString.copyFrom(privateKey.data())
    }.build()

    val output = AnySigner.sign(input, CoinType.TRON, Tron.SigningOutput.parser())
    if (output.error != Common.SigningError.OK) throw ChainSigningException("Signing failed: ${output.errorMessage}")

    val signatureHex = output.signature.toByteArray().toHex()
    val signedTx = JSONObject(unsignedTx).put("signature", org.json.JSONArray().put(signatureHex))
    return signedTx.toString()
  }

  // MARK: - XRP
  // unsignedTx: xrpl.js `Payment` object (Account, Destination, Amount (drops, string),
  // Fee (drops, string), Sequence, LastLedgerSequence, DestinationTag?).
  private fun signXrp(wallet: HDWallet, unsignedTx: Map<String, Any>): String {
    val privateKey = wallet.getKeyForCoin(CoinType.XRP)
    val account = unsignedTx["Account"] as? String ?: throw ChainSigningException("Missing Account")
    val destination = unsignedTx["Destination"] as? String ?: throw ChainSigningException("Missing Destination")
    val amountDrops = unsignedTx["Amount"] as? String ?: throw ChainSigningException("Missing Amount")
    val feeDrops = unsignedTx["Fee"] as? String ?: throw ChainSigningException("Missing Fee")
    val sequence = (unsignedTx["Sequence"] as? Number)?.toInt() ?: throw ChainSigningException("Missing Sequence")
    val lastLedgerSequence = (unsignedTx["LastLedgerSequence"] as? Number)?.toInt()
    val destinationTag = (unsignedTx["DestinationTag"] as? Number)?.toLong()

    val input = Ripple.SigningInput.newBuilder().apply {
      this.privateKey = ByteString.copyFrom(privateKey.data())
      this.account = account
      this.fee = feeDrops.toLong()
      this.sequence = sequence
      lastLedgerSequence?.let { this.lastLedgerSequence = it }
      this.opPayment = Ripple.OperationPayment.newBuilder().apply {
        this.amount = amountDrops.toLong()
        this.destination = destination
        destinationTag?.let { this.destinationTag = it }
      }.build()
    }.build()

    val output = AnySigner.sign(input, CoinType.XRP, Ripple.SigningOutput.parser())
    if (output.error != Common.SigningError.OK) throw ChainSigningException("Signing failed: ${output.errorMessage}")
    return output.encoded.toByteArray().toHex()
  }

  // MARK: - TON
  // unsignedTx: { toAddress, amount, seqno, memoId? }.
  // NOTE(verify-on-device): confirm `amount` units (nanoton vs TON) and that wallet_version
  // V4R2 matches the address format the current @ton/* implementation derives.
  // expireAt isn't supplied by prepareSelfCustodyUnsignedTx's TON branch (just
  // {toAddress,amount,seqno,memoId}); default to a 10-minute signing window, matching the
  // extendExpiration(tx, 600) buffer TRX's prepare step already uses.
  private fun signTon(wallet: HDWallet, unsignedTx: Map<String, Any>): ChainSignResult {
    val privateKey = wallet.getKeyForCoin(CoinType.TON)
    val toAddress = unsignedTx["toAddress"] as? String ?: throw ChainSigningException("Missing toAddress")
    val amount = (unsignedTx["amount"] as? String)?.toULongOrNull() ?: throw ChainSigningException("Missing amount")
    val seqno = (unsignedTx["seqno"] as? Number)?.toInt() ?: throw ChainSigningException("Missing seqno")
    val memoId = unsignedTx["memoId"] as? String
    val expireAt = (System.currentTimeMillis() / 1000L + 600L).toInt()

    val transfer = TheOpenNetwork.Transfer.newBuilder().apply {
      this.dest = toAddress
      this.amount = amount.toLong()
      this.mode = TheOpenNetwork.SendMode.PAY_FEES_SEPARATELY_VALUE or TheOpenNetwork.SendMode.IGNORE_ACTION_PHASE_ERRORS_VALUE
      this.bounceable = true
      memoId?.let { this.comment = it }
    }.build()

    val input = TheOpenNetwork.SigningInput.newBuilder().apply {
      this.privateKey = ByteString.copyFrom(privateKey.data())
      this.walletVersion = TheOpenNetwork.WalletVersion.WALLET_V4_R2
      this.sequenceNumber = seqno
      this.expireAt = expireAt
      this.addMessages(transfer)
    }.build()

    val output = AnySigner.sign(input, CoinType.TON, TheOpenNetwork.SigningOutput.parser())
    if (output.error != Common.SigningError.OK) throw ChainSigningException("Signing failed: ${output.errorMessage}")
    return ChainSignResult(output.encoded, mapOf("txHash" to output.hash.toByteArray().toHex()))
  }
}

// Helpers

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexToBytes(): ByteArray {
  val s = removePrefix("0x").let { if (it.length % 2 == 0) it else "0$it" }
  return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

// BigInteger -> minimal big-endian ByteString (strips Java's leading sign byte)
private fun BigInteger.toMinimalByteString(): ByteString {
  val raw = toByteArray()
  return if (raw.size > 1 && raw[0] == 0.toByte()) {
    ByteString.copyFrom(raw, 1, raw.size - 1)
  } else {
    ByteString.copyFrom(raw)
  }
}
