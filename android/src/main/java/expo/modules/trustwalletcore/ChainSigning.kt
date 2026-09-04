package expo.modules.trustwalletcore

import android.util.Log
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

  val symbol: String get() = when (this) {
    ETHEREUM -> "ETH"; BNB -> "BNB"; POLYGON -> "POL"; SOLANA -> "SOL"
    TRON -> "TRX"; TON -> "TON"; BITCOIN -> "BTC"; BITCOINCASH -> "BCH"
    LITECOIN -> "LTC"; XRP -> "XRP"
  }

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
          this.txMode = Ethereum.TransactionMode.Enveloped
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

    Log.d("ChainSigning", "signUtxo: parsing ${inputs.size} UTXOs")
    val utxos = inputs.map { entry ->
      val txIdHex = entry["txIdHex"] as? String ?: throw ChainSigningException("Invalid UTXO entry: missing txIdHex, keys=${entry.keys}")
      val vout = (entry["vout"] as? Number)?.toInt() ?: throw ChainSigningException("Invalid UTXO entry: missing vout")
      val amount = (entry["amountSats"] as? String)?.toLong() ?: throw ChainSigningException("Invalid UTXO entry: missing amountSats, type=${entry["amountSats"]?.javaClass?.name}")
      val scriptHex = entry["scriptPubKeyHex"] as? String ?: throw ChainSigningException("Invalid UTXO entry: missing scriptPubKeyHex")
      Log.d("ChainSigning", "signUtxo: UTXO txid=$txIdHex vout=$vout amount=$amount")

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

    Log.d("ChainSigning", "signUtxo: building SigningInput toAddress=$toAddress sats=$sendAmountSats fee=$satsPerByte")
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

    Log.d("ChainSigning", "signUtxo: calling AnySigner.sign coin=${coin.name}")
    val output = AnySigner.sign(input, coin, Bitcoin.SigningOutput.parser())
    Log.d("ChainSigning", "signUtxo: AnySigner.sign done error=${output.error} msg=${output.errorMessage}")
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
    val destinationTag = parseXrpDestinationTag((unsignedTx["DestinationTag"] as? Number)?.toLong())

    val input = Ripple.SigningInput.newBuilder().apply {
      this.privateKey = ByteString.copyFrom(privateKey.data())
      this.account = account
      this.fee = parseXrpFeeDrops(feeDrops)
      this.sequence = sequence
      lastLedgerSequence?.let { this.lastLedgerSequence = it }
      this.opPayment = Ripple.OperationPayment.newBuilder().apply {
        this.amount = parseXrpAmountDrops(amountDrops)
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
    val amountStr = unsignedTx["amount"] as? String ?: throw ChainSigningException("Missing amount")
    val amount = parseTonNanotons(amountStr)
    val seqno = (unsignedTx["seqno"] as? Number)?.toInt() ?: throw ChainSigningException("Missing seqno")
    val memoId = unsignedTx["memoId"] as? String
    val expireAt = (System.currentTimeMillis() / 1000L + 600L).toInt()

    val transfer = TheOpenNetwork.Transfer.newBuilder().apply {
      this.dest = toAddress
      this.amount = amount
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

// Transaction summary helpers (used by TrustWalletCoreModule for native confirmation UI)

internal fun ChainSigner.buildSummary(chain: ChainKey, unsignedTx: Map<String, Any>): String {
  val lines = mutableListOf("Network: ${chain.name}")
  when (chain) {
    ChainKey.ETHEREUM, ChainKey.BNB, ChainKey.POLYGON -> {
      (unsignedTx["to"] as? String)?.let { lines += "To: ${fmtAddr(it)}" }
      val valueWei = txHexToDouble((unsignedTx["valueHex"] as? String) ?: "0")
      lines += "Amount: ${fmtAmt(valueWei / 1e18)} ${chain.symbol}"
      val gasLimit = txHexToDouble((unsignedTx["gasLimitHex"] as? String) ?: "0")
      val gasPrice = txHexToDouble(
        (unsignedTx["gasPriceHex"] as? String) ?: (unsignedTx["maxFeePerGasHex"] as? String) ?: "0"
      )
      val feeWei = gasLimit * gasPrice
      if (feeWei > 0) lines += "Max fee: ${fmtAmt(feeWei / 1e18)} ${chain.symbol}"
      (unsignedTx["chainId"] as? Number)?.let { lines += "Chain ID: ${it.toInt()}" }
      (unsignedTx["nonce"] as? Number)?.let { lines += "Nonce: ${it.toInt()}" }
      val dataHex = (unsignedTx["dataHex"] as? String) ?: ""
      val stripped = dataHex.removePrefix("0x")
      if (stripped.isNotEmpty() && stripped != "0") {
        lines += "Contract data: ${stripped.length / 2} bytes — review carefully"
      }
    }
    ChainKey.BITCOIN, ChainKey.LITECOIN -> {
      (unsignedTx["toAddress"] as? String)?.let { lines += "To: ${fmtAddr(it)}" }
      (unsignedTx["sendAmountSats"] as? String)?.toLongOrNull()?.let {
        lines += "Amount: ${fmtAmt(it.toDouble() / 1e8)} ${chain.symbol}"
      }
      (unsignedTx["changeAddress"] as? String)?.let { lines += "Change to: ${fmtAddr(it)}" }
      (unsignedTx["satsPerByte"] as? Number)?.let { lines += "Fee rate: ${it.toInt()} sat/vB" }
    }
    ChainKey.XRP -> {
      (unsignedTx["Destination"] as? String)?.let { lines += "To: ${fmtAddr(it)}" }
      (unsignedTx["Amount"] as? String)?.toLongOrNull()?.let {
        lines += "Amount: ${fmtAmt(it.toDouble() / 1_000_000.0)} XRP"
      }
      (unsignedTx["Fee"] as? String)?.toLongOrNull()?.let {
        lines += "Fee: ${fmtAmt(it.toDouble() / 1_000_000.0)} XRP"
      }
      unsignedTx["DestinationTag"]?.let { lines += "Tag: $it" }
    }
    ChainKey.TON -> {
      (unsignedTx["toAddress"] as? String)?.let { lines += "To: ${fmtAddr(it)}" }
      (unsignedTx["amount"] as? String)?.toULongOrNull()?.let {
        lines += "Amount: ${fmtAmt(it.toDouble() / 1e9)} TON"
      }
      (unsignedTx["memoId"] as? String)?.takeIf { it.isNotEmpty() }?.let { lines += "Memo: $it" }
      lines += "Fee: set by network"
    }
    ChainKey.TRON -> {
      @Suppress("UNCHECKED_CAST")
      val firstContract = (unsignedTx["raw_data"] as? Map<String, Any>)
        ?.let { (it["contract"] as? List<Map<String, Any>>)?.firstOrNull() }
      firstContract?.let { contract ->
        (contract["parameter"] as? Map<String, Any>)
          ?.let { it["value"] as? Map<String, Any> }
          ?.let { v ->
            (v["to_address"] as? String)?.let { lines += "To: ${fmtAddr(it)}" }
            (v["amount"] as? Number)?.let { lines += "Amount: ${fmtAmt(it.toDouble() / 1e6)} TRX" }
          }
        (contract["type"] as? String)?.takeIf { it != "TransferContract" }?.let {
          lines += "Contract type: $it — review carefully"
        }
      }
      (unsignedTx["txID"] as? String)?.let { lines += "TxID: ${it.take(16)}…" }
    }
    ChainKey.SOLANA -> {
      val info = (unsignedTx["unsignedTxBase64"] as? String)?.let { decodeSolanaForSummary(it) }
      if (info != null) {
        info.to?.let { lines += "To: ${fmtAddr(it)}" }
        info.lamports?.let { lines += "Amount: ${fmtAmt(it.toDouble() / 1e9)} SOL" }
        if (!info.isTransfer) lines += "Non-transfer instruction — review carefully"
      } else {
        lines += "Unable to decode transaction — proceed only if you trust the source"
      }
    }
    ChainKey.BITCOINCASH -> {}
  }
  return lines.joinToString("\n")
}

private data class SolanaSummary(val to: String?, val lamports: ULong?, val isTransfer: Boolean)

private fun decodeSolanaForSummary(b64: String): SolanaSummary? = try {
  val txBytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
  val decoded = Solana.DecodingTransactionOutput.parseFrom(TransactionDecoder.decode(CoinType.SOLANA, txBytes))
  if (decoded.error != Common.SigningError.OK) return null
  val accounts = decoded.transaction.legacy.message.accountKeysList
  val ix = decoded.transaction.legacy.message.instructionsList.firstOrNull()
    ?: return SolanaSummary(null, null, false)
  val to = if (ix.accountsCount >= 2) accounts.getOrNull(ix.accountsList[1]) else null
  val dataBytes = ix.data.toByteArray()
  val isTransfer = dataBytes.size >= 12 &&
    dataBytes[0] == 2.toByte() && dataBytes[1] == 0.toByte() &&
    dataBytes[2] == 0.toByte() && dataBytes[3] == 0.toByte()
  val lamports = if (isTransfer) {
    var v = 0UL
    for (i in 0..7) v = v or (dataBytes[4 + i].toUByte().toULong() shl (i * 8))
    v
  } else null
  SolanaSummary(to, lamports, isTransfer)
} catch (_: Exception) { null }

private fun txHexToDouble(hex: String): Double = try {
  BigInteger(hex.removePrefix("0x").ifEmpty { "0" }, 16).toDouble()
} catch (_: NumberFormatException) { 0.0 }

private fun fmtAmt(value: Double): String =
  "%.8f".format(value).trimEnd('0').trimEnd('.')

private fun fmtAddr(addr: String): String = addr

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
