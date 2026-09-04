import Foundation
import ExpoModulesCore
import WalletCore

// All chains this module derives addresses for / signs transactions for.

enum ChainKey: String, CaseIterable {
  case ethereum, bnb, polygon
  case solana
  case tron, ton
  case bitcoin, bitcoincash, litecoin
  case xrp

  init(fromJs raw: String) throws {
    guard let key = ChainKey(rawValue: raw) else {
      throw Exception(name: "UnsupportedChain", description: "Unsupported chain: \(raw)")
    }
    self = key
  }

  var symbol: String {
    switch self {
    case .ethereum: return "ETH"
    case .bnb:      return "BNB"
    case .polygon:  return "POL"
    case .solana:   return "SOL"
    case .tron:     return "TRX"
    case .ton:      return "TON"
    case .bitcoin:  return "BTC"
    case .bitcoincash: return "BCH"
    case .litecoin: return "LTC"
    case .xrp:      return "XRP"
    }
  }

  // Polygon shares Ethereum's secp256k1 key/address (same BIP44 path) — no distinct CoinType.
  var coinType: CoinType {
    switch self {
    case .ethereum, .polygon: return .ethereum
    case .bnb: return .smartChain
    case .solana: return .solana
    case .tron: return .tron
    case .ton: return .ton
    case .bitcoin: return .bitcoin
    case .bitcoincash: return .bitcoinCash
    case .litecoin: return .litecoin
    case .xrp: return .xrp
    }
  }
}

enum ChainSigner {
  struct Result {
    let signedTx: String
    let meta: [String: Any]?
  }

  static func sign(chain: ChainKey, wallet: HDWallet, unsignedTx: [String: Any]) throws -> Result {
    switch chain {
    case .ethereum, .bnb, .polygon:
      return Result(signedTx: try signEvm(wallet: wallet, coin: chain.coinType, txParams: unsignedTx), meta: nil)
    case .solana:
      return Result(signedTx: try signSolana(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .bitcoin, .litecoin:
      return Result(signedTx: try signUtxo(wallet: wallet, coin: chain.coinType, txParams: unsignedTx), meta: nil)
    case .tron:
      return Result(signedTx: try signTron(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .xrp:
      return Result(signedTx: try signXrp(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .ton:
      return try signTon(wallet: wallet, txParams: unsignedTx)
    case .bitcoincash:
      // Sending is intentionally unsupported: chainberry-wallet's prepareSelfCustodyUnsignedTx
      // has no BCH case (its own comment notes apps/selfCustodySigner's signer doesn't either) —
      // this app only ever needs BCH address derivation, never a signed BCH transaction.
      throw Exception(name: "UnsupportedChain", description: "BCH sending is not supported")
    }
  }

  // MARK: - EVM (ethereum / bnb / polygon)
  // txParams: { to, chainId, nonce, gasLimitHex, valueHex?, dataHex?,
  //             gasPriceHex? (legacy) | maxFeePerGasHex + maxPriorityFeePerGasHex (EIP-1559) }
  // Hex fields are bare hex (no 0x prefix required) — mirrors what wallet.ts's buildTxParams sends.

  private static func signEvm(wallet: HDWallet, coin: CoinType, txParams: [String: Any]) throws -> String {
    guard let to = txParams["to"] as? String,
          let nonceNum = txParams["nonce"] as? NSNumber,
          let gasLimHex = txParams["gasLimitHex"] as? String,
          let chainIdNum = txParams["chainId"] as? NSNumber else {
      throw Exception(name: "InvalidParams", description: "Missing required EVM tx params")
    }
    let nonce = nonceNum.intValue
    let chainId = chainIdNum.intValue
    let valueHex = (txParams["valueHex"] as? String) ?? "0"
    let dataHex = (txParams["dataHex"] as? String) ?? ""

    let privateKey = wallet.getKeyForCoin(coin: coin)

    guard let gasLimitData = hexData(gasLimHex) else {
      throw Exception(name: "InvalidParams", description: "Invalid gasLimitHex: \(gasLimHex)")
    }
    guard let valueData = hexData(valueHex) else {
      throw Exception(name: "InvalidParams", description: "Invalid valueHex: \(valueHex)")
    }

    var input = EthereumSigningInput()
    input.chainID = intToData(chainId)
    input.nonce = intToData(nonce)
    input.gasLimit = gasLimitData
    input.toAddress = to
    input.privateKey = privateKey.data
    var transfer = EthereumTransaction.Transfer()
    transfer.amount = valueData
    if !dataHex.isEmpty {
      guard let dataBytes = hexData(dataHex) else {
        throw Exception(name: "InvalidParams", description: "Invalid dataHex: \(dataHex)")
      }
      transfer.data = dataBytes
    }
    var tx = EthereumTransaction()
    tx.transfer = transfer
    input.transaction = tx

    if let gasPriceHex = txParams["gasPriceHex"] as? String {
      guard let gasPriceData = hexData(gasPriceHex) else {
        throw Exception(name: "InvalidParams", description: "Invalid gasPriceHex: \(gasPriceHex)")
      }
      input.gasPrice = gasPriceData
    } else if let mfHex = txParams["maxFeePerGasHex"] as? String,
              let pfHex = txParams["maxPriorityFeePerGasHex"] as? String {
      guard let maxFeeData = hexData(mfHex) else {
        throw Exception(name: "InvalidParams", description: "Invalid maxFeePerGasHex: \(mfHex)")
      }
      guard let maxPriorityData = hexData(pfHex) else {
        throw Exception(name: "InvalidParams", description: "Invalid maxPriorityFeePerGasHex: \(pfHex)")
      }
      input.txMode = .enveloped
      input.maxFeePerGas = maxFeeData
      input.maxInclusionFeePerGas = maxPriorityData
    }

    let output: EthereumSigningOutput = AnySigner.sign(input: input, coin: coin)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return "0x" + output.encoded.hexString
  }

  // MARK: - Solana
  // NOTE(verify-on-device): prepareSelfCustodyUnsignedTx's SOL branch (chainberry-wallet)
  // returns a fully-built, base64-serialized unsigned @solana/web3.js Transaction (supports
  // both native transfer and SPL-token transfer instructions) — not a simple {to,lamports,
  // recentBlockhash} triple. wallet-core's SolanaSigningInput has a raw-message signing mode
  // (`rawMessage` / legacy transaction bytes) intended for exactly this "sign an externally
  // built transaction" case — confirm the exact field name against the installed wallet-core
  // version and adjust the input construction below accordingly before relying on this path.
  // txParams: { unsignedTxBase64: string }
  private static func signSolana(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    guard let unsignedTxBase64 = txParams["unsignedTxBase64"] as? String,
          let txData = Data(base64Encoded: unsignedTxBase64) else {
      throw Exception(name: "InvalidParams", description: "Missing/invalid unsignedTxBase64")
    }
    let privateKey = wallet.getKeyForCoin(coin: .solana)

    // Decode the unsigned tx to extract the embedded recentBlockhash, then re-sign via
    // TW's sanctioned path. We pass the same blockhash back (no-op refresh) so the
    // tx content is unchanged — only the signature is added.
    let decodedData = TransactionDecoder.decode(coinType: .solana, encodedTx: txData)
    let decoded = try SolanaDecodingTransactionOutput(serializedBytes: decodedData)
    guard decoded.error == .ok else {
      throw Exception(name: "DecodingFailed", description: "Failed to decode SOL tx: \(decoded.errorMessage)")
    }
    let recentBlockhash = decoded.transaction.legacy.recentBlockhash

    let privateKeys = DataVector()
    privateKeys.add(data: privateKey.data)
    let outputData = SolanaTransaction.updateBlockhashAndSign(
      encodedTx: unsignedTxBase64, recentBlockhash: recentBlockhash, privateKeys: privateKeys
    )
    let output = try SolanaSigningOutput(serializedBytes: outputData)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.encoded
  }

  // MARK: - BTC / LTC (UTXO-based)
  // txParams (from wallet-broadcast's additive prepareBtcUtxoSet/prepareLtcUtxoSet):
  // { toAddress, changeAddress, sendAmountSats, changeAmountSats, satsPerByte,
  //   inputs: [{ txIdHex, vout, amountSats, scriptPubKeyHex }] }
  // NOTE(verify-on-device): field names (hashType/toAddress/changeAddress/byteFee/utxo/
  // outPoint/privateKey) match wallet-core's long-documented Bitcoin signing example, but
  // confirm against the installed 4.1.19 generated Swift types before trusting with real funds.
  private static func signUtxo(wallet: HDWallet, coin: CoinType, txParams: [String: Any]) throws -> String {
    guard let toAddress = txParams["toAddress"] as? String,
          let changeAddress = txParams["changeAddress"] as? String,
          let sendAmountSats = (txParams["sendAmountSats"] as? String).flatMap(Int64.init),
          let satsPerByteNum = txParams["satsPerByte"] as? NSNumber,
          let inputs = txParams["inputs"] as? [[String: Any]] else {
      throw Exception(name: "InvalidParams", description: "Missing required UTXO tx params")
    }

    let privateKey = wallet.getKeyForCoin(coin: coin)

    var input = BitcoinSigningInput()
    input.hashType = 1 // SIGHASH_ALL — stable Bitcoin protocol constant, not a wallet-core-specific value
    input.amount = sendAmountSats
    input.byteFee = Int64(satsPerByteNum.doubleValue.rounded(.up))
    input.toAddress = toAddress
    input.changeAddress = changeAddress
    input.useMaxAmount = false
    input.coinType = coin.rawValue
    input.privateKey = [privateKey.data]

    input.utxo = try inputs.map { entry in
      guard let txIdHex = entry["txIdHex"] as? String,
            let voutNum = entry["vout"] as? NSNumber,
            let amount = (entry["amountSats"] as? String).flatMap(Int64.init),
            let scriptHex = entry["scriptPubKeyHex"] as? String,
            let scriptData = hexData(scriptHex),
            var txIdData = hexData(txIdHex) else {
        throw Exception(name: "InvalidParams", description: "Invalid UTXO input entry")
      }
      // On-chain/explorer txid hex is displayed big-endian; wallet-core's OutPoint.hash wants
      // the reversed (little-endian, internal wire-format) byte order.
      txIdData.reverse()

      var outPoint = BitcoinOutPoint()
      outPoint.hash = txIdData
      outPoint.index = UInt32(voutNum.intValue)

      var utxo = BitcoinUnspentTransaction()
      utxo.outPoint = outPoint
      utxo.amount = amount
      utxo.script = scriptData
      return utxo
    }

    let output: BitcoinSigningOutput = AnySigner.sign(input: input, coin: coin)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.encoded.hexString
  }

  // MARK: - TRX
  // txParams: the raw TronGrid-shaped unsigned tx object from prepareSelfCustodyUnsignedTx's
  // TRX branch (raw_data.contract[], ref_block_bytes/hash, expiration, timestamp).
  // NOTE(verify-on-device): field mapping into TronSigningInput/TronTransaction must be checked
  // against the installed wallet-core version's Tron.proto — this covers the plain TRX-transfer
  // contract type only (matches prepareTrxTransaction's non-token branch); the TRC20
  // (triggerSmartContract) branch is not mapped here and needs its own contract-call SigningInput.
  private static func signTron(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    let privateKey = wallet.getKeyForCoin(coin: .tron)

    // Sign via txID — wallet-core reads the txID digest and signs it directly.
    // This covers both plain TRX transfers and TRC20 triggerSmartContract payloads.
    guard let txID = txParams["txID"] as? String else {
      throw Exception(name: "InvalidParams", description: "Missing txID in TRX tx params")
    }

    var input = TronSigningInput()
    input.privateKey = privateKey.data
    input.txID = txID

    let output: TronSigningOutput = AnySigner.sign(input: input, coin: .tron)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }

    // Reconstruct the full TronGrid broadcast payload with the signature appended.
    var broadcastTx = txParams
    broadcastTx["signature"] = [output.signature.hexString]
    let broadcastData = try JSONSerialization.data(withJSONObject: broadcastTx)
    guard let broadcastJson = String(data: broadcastData, encoding: .utf8) else {
      throw Exception(name: "EncodingFailed", description: "TRX broadcast tx JSON encoding failed")
    }
    return broadcastJson
  }

  // MARK: - XRP
  // txParams: xrpl.js `Payment` object from prepareSelfCustodyUnsignedTx's XRP branch
  // (Account, Destination, Amount (drops, string), Fee (drops, string), Sequence,
  // LastLedgerSequence, DestinationTag?).
  private static func signXrp(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    guard let account = txParams["Account"] as? String,
          let destination = txParams["Destination"] as? String,
          let amountDrops = txParams["Amount"] as? String,
          let feeDrops = txParams["Fee"] as? String,
          let sequenceNum = txParams["Sequence"] as? NSNumber else {
      throw Exception(name: "InvalidParams", description: "Missing required XRP Payment fields")
    }
    let sequence = sequenceNum.intValue
    let lastLedgerSequence = (txParams["LastLedgerSequence"] as? NSNumber)?.intValue
    let destinationTag = (txParams["DestinationTag"] as? NSNumber)?.intValue

    let privateKey = wallet.getKeyForCoin(coin: .xrp)

    var payment = RippleOperationPayment()
    payment.amount = try parseXrpAmountDrops(amountDrops)
    payment.destination = destination
    if let resolvedTag = try parseXrpDestinationTag(destinationTag) {
      payment.destinationTag = Int64(resolvedTag)
    }

    var input = RippleSigningInput()
    input.privateKey = privateKey.data
    input.account = account
    input.fee = try parseXrpFeeDrops(feeDrops)
    input.sequence = Int32(sequence)
    if let lls = lastLedgerSequence { input.lastLedgerSequence = Int32(lls) }
    input.opPayment = payment

    let output: RippleSigningOutput = AnySigner.sign(input: input, coin: .xrp)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.encoded.hexString
  }

  // MARK: - TON
  // txParams: { toAddress, amount, seqno, memoId? } from prepareSelfCustodyUnsignedTx's TON
  // branch. `amount` there is a human-readable TON string (see chainberry-wallet's TON case,
  // which passes the raw `amount` param through unconverted) — NOTE(verify-on-device): confirm
  // whether that's already nanoton or needs *1e9 conversion, and confirm wallet_version V4R2
  // matches the address format the current @ton/* implementation derives (address-format parity
  // is the main risk for this chain per the migration plan).
  private static func signTon(wallet: HDWallet, txParams: [String: Any]) throws -> ChainSigner.Result {
    guard let toAddress = txParams["toAddress"] as? String,
          let amountStr = txParams["amount"] as? String,
          let seqnoNum = txParams["seqno"] as? NSNumber else {
      throw Exception(name: "InvalidParams", description: "Missing required TON tx params")
    }
    let seqno = seqnoNum.intValue
    let memoId = txParams["memoId"] as? String

    let privateKey = wallet.getKeyForCoin(coin: .ton)

    let nanotons = try parseTonNanotons(amountStr)

    var transfer = TheOpenNetworkTransfer()
    transfer.dest = toAddress
    transfer.amount = nanotons
    transfer.mode = UInt32(TheOpenNetworkSendMode.payFeesSeparately.rawValue | TheOpenNetworkSendMode.ignoreActionPhaseErrors.rawValue)
    transfer.bounceable = true
    if let memoId { transfer.comment = memoId }

    var input = TheOpenNetworkSigningInput()
    input.privateKey = privateKey.data
    input.walletVersion = .walletV4R2
    input.sequenceNumber = UInt32(seqno)
    input.expireAt = UInt32(Date().timeIntervalSince1970) + 600
    input.messages = [transfer]

    let output: TheOpenNetworkSigningOutput = AnySigner.sign(input: input, coin: .ton)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return ChainSigner.Result(signedTx: output.encoded, meta: ["txHash": output.hash.hexString])
  }

  // MARK: - Transaction summary for native confirmation UI

  static func buildSummary(chain: ChainKey, unsignedTx: [String: Any]) -> String {
    var lines = ["Network: \(chain.rawValue.uppercased())"]
    switch chain {
    case .ethereum, .bnb, .polygon:
      if let to = unsignedTx["to"] as? String { lines.append("To: \(fmtAddr(to))") }
      let val_ = txHexToDouble((unsignedTx["valueHex"] as? String) ?? "0")
      lines.append("Amount: \(fmtAmt(val_ / 1e18)) \(chain.symbol)")
      let gasLimit = txHexToDouble((unsignedTx["gasLimitHex"] as? String) ?? "0")
      let gasPrice = txHexToDouble(
        (unsignedTx["gasPriceHex"] as? String) ?? (unsignedTx["maxFeePerGasHex"] as? String) ?? "0"
      )
      let fee = gasLimit * gasPrice
      if fee > 0 { lines.append("Max fee: \(fmtAmt(fee / 1e18)) \(chain.symbol)") }
      if let chainId = unsignedTx["chainId"] as? NSNumber { lines.append("Chain ID: \(chainId.intValue)") }
      if let nonce = unsignedTx["nonce"] as? NSNumber { lines.append("Nonce: \(nonce.intValue)") }
      let dataHex = (unsignedTx["dataHex"] as? String) ?? ""
      let stripped = dataHex.hasPrefix("0x") ? String(dataHex.dropFirst(2)) : dataHex
      if !stripped.isEmpty && stripped != "0" {
        lines.append("Contract data: \(stripped.count / 2) bytes — review carefully")
      }

    case .bitcoin, .litecoin:
      if let to = unsignedTx["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      if let sats = (unsignedTx["sendAmountSats"] as? String).flatMap(Int64.init) {
        lines.append("Amount: \(fmtAmt(Double(sats) / 1e8)) \(chain.symbol)")
      }
      if let change = unsignedTx["changeAddress"] as? String { lines.append("Change to: \(fmtAddr(change))") }
      if let spb = unsignedTx["satsPerByte"] as? NSNumber { lines.append("Fee rate: \(spb.intValue) sat/vB") }

    case .xrp:
      if let dest = unsignedTx["Destination"] as? String { lines.append("To: \(fmtAddr(dest))") }
      if let drops = (unsignedTx["Amount"] as? String).flatMap(Int64.init) {
        lines.append("Amount: \(fmtAmt(Double(drops) / 1_000_000)) XRP")
      }
      if let feeDrops = (unsignedTx["Fee"] as? String).flatMap(Int64.init) {
        lines.append("Fee: \(fmtAmt(Double(feeDrops) / 1_000_000)) XRP")
      }
      if let tag = unsignedTx["DestinationTag"] { lines.append("Tag: \(tag)") }

    case .ton:
      if let to = unsignedTx["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      if let nano = (unsignedTx["amount"] as? String).flatMap(UInt64.init) {
        lines.append("Amount: \(fmtAmt(Double(nano) / 1e9)) TON")
      }
      if let memo = unsignedTx["memoId"] as? String, !memo.isEmpty { lines.append("Memo: \(memo)") }
      lines.append("Fee: set by network")

    case .tron:
      if let rawData = unsignedTx["raw_data"] as? [String: Any],
         let contracts = rawData["contract"] as? [[String: Any]],
         let first = contracts.first {
        if let param = first["parameter"] as? [String: Any],
           let value = param["value"] as? [String: Any] {
          if let to = value["to_address"] as? String { lines.append("To: \(fmtAddr(to))") }
          if let amount = value["amount"] as? Int { lines.append("Amount: \(fmtAmt(Double(amount) / 1e6)) TRX") }
        }
        if let type_ = first["type"] as? String, type_ != "TransferContract" {
          lines.append("Contract type: \(type_) — review carefully")
        }
      }
      // Show the exact digest being signed so the user can cross-check with the broadcast payload.
      if let txID = unsignedTx["txID"] as? String {
        lines.append("TxID: \(txID.prefix(16))…")
      }

    case .solana:
      // Decode the pre-built tx to extract recipient and lamports from the first instruction.
      // Falls back to an explicit warning instead of the misleading "verified by network" message.
      if let info = decodeSolanaForSummary(unsignedTx) {
        if let to = info.to { lines.append("To: \(fmtAddr(to))") }
        if let lamports = info.lamports { lines.append("Amount: \(fmtAmt(Double(lamports) / 1e9)) SOL") }
        if !info.isTransfer { lines.append("Non-transfer instruction — review carefully") }
      } else {
        lines.append("Unable to decode transaction — proceed only if you trust the source")
      }

    case .bitcoincash:
      break
    }
    return lines.joined(separator: "\n")
  }

  private static func decodeSolanaForSummary(_ txParams: [String: Any])
    -> (to: String?, lamports: UInt64?, isTransfer: Bool)? {
    guard let b64 = txParams["unsignedTxBase64"] as? String,
          let txData = Data(base64Encoded: b64) else { return nil }
    let rawBytes = TransactionDecoder.decode(coinType: .solana, encodedTx: txData)
    guard let decoded = try? SolanaDecodingTransactionOutput(serializedBytes: rawBytes),
          decoded.error == .ok else { return nil }
    let accounts = decoded.transaction.legacy.accountKeys
    let instrs = decoded.transaction.legacy.instructions
    guard let ix = instrs.first else { return (nil, nil, false) }
    let to: String? = ix.accounts.count >= 2
      ? safeGet(accounts, Int(ix.accounts[1]))
      : nil
    let isTransfer = ix.programData.count >= 12 && ix.programData.prefix(4) == Data([2, 0, 0, 0])
    var lamports: UInt64?
    if isTransfer {
      var v: UInt64 = 0
      for (i, b) in ix.programData.dropFirst(4).prefix(8).enumerated() { v |= UInt64(b) << (i * 8) }
      lamports = v
    }
    return (to, lamports, isTransfer)
  }

  private static func txHexToDouble(_ hex: String) -> Double {
    let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    if let v = UInt64(s, radix: 16) { return Double(v) }
    return hexData(s)?.reduce(0.0) { $0 * 256 + Double($1) } ?? 0
  }

  private static func fmtAmt(_ value: Double) -> String {
    var s = String(format: "%.8f", value)
    while s.hasSuffix("0") { s.removeLast() }
    if s.hasSuffix(".") { s.removeLast() }
    return s
  }

  private static func fmtAddr(_ addr: String) -> String { addr }

  // MARK: - Helpers

  private static func safeGet<T>(_ array: [T], _ index: Int) -> T? {
    array.indices.contains(index) ? array[index] : nil
  }

  // Parses a hex string (with or without 0x, odd or even length) into Data. An empty string
  // deliberately maps to a single zero byte (fields like valueHex already default to "0"
  // when absent — that's a legitimate zero-value transfer, not malformed input). Any
  // non-empty string containing a non-hex character returns nil so callers can fail closed
  // instead of silently coercing garbage into a zero/empty value.
  static func hexData(_ hex: String) -> Data? {
    let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    let padded = s.count % 2 == 0 ? s : "0" + s
    guard !padded.isEmpty else { return Data([0]) }
    guard padded.allSatisfy({ $0.isHexDigit }) else { return nil }
    return Data(hexString: padded)
  }

  // Encodes a non-negative integer as minimal big-endian Data.
  static func intToData(_ value: Int) -> Data {
    guard value > 0 else { return Data([0]) }
    var v = value
    var bytes: [UInt8] = []
    while v > 0 {
      bytes.insert(UInt8(v & 0xFF), at: 0)
      v >>= 8
    }
    return Data(bytes)
  }
}
