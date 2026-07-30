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
          let nonce = txParams["nonce"] as? Int,
          let gasLimHex = txParams["gasLimitHex"] as? String,
          let chainId = txParams["chainId"] as? Int else {
      throw Exception(name: "InvalidParams", description: "Missing required EVM tx params")
    }
    let valueHex = (txParams["valueHex"] as? String) ?? "0"
    let dataHex = (txParams["dataHex"] as? String) ?? ""

    let privateKey = wallet.getKeyForCoin(coin: coin)

    var input = EthereumSigningInput()
    input.chainID = intToData(chainId)
    input.nonce = intToData(nonce)
    input.gasLimit = hexData(gasLimHex) ?? Data()
    input.toAddress = to
    input.privateKey = privateKey.data
    if !dataHex.isEmpty { input.txData = hexData(dataHex) ?? Data() }

    var transfer = EthereumTransaction.Transfer()
    transfer.amount = hexData(valueHex) ?? Data([0])
    var tx = EthereumTransaction()
    tx.transfer = transfer
    input.transaction = tx

    if let gasPriceHex = txParams["gasPriceHex"] as? String {
      input.gasPrice = hexData(gasPriceHex) ?? Data()
    } else if let mfHex = txParams["maxFeePerGasHex"] as? String,
              let pfHex = txParams["maxPriorityFeePerGasHex"] as? String {
      input.maxFeePerGas = hexData(mfHex) ?? Data()
      input.maxInclusionFeePerGas = hexData(pfHex) ?? Data()
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

    var raw = SolanaRawMessage()
    raw.type = .legacy
    raw.encoded = txData

    var input = SolanaSigningInput()
    input.privateKey = privateKey.data
    input.rawMessage = raw

    let output: SolanaSigningOutput = AnySigner.sign(input: input, coin: .solana)
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
          let satsPerByte = txParams["satsPerByte"] as? Double,
          let inputs = txParams["inputs"] as? [[String: Any]] else {
      throw Exception(name: "InvalidParams", description: "Missing required UTXO tx params")
    }

    let privateKey = wallet.getKeyForCoin(coin: coin)

    var input = BitcoinSigningInput()
    input.hashType = 1 // SIGHASH_ALL — stable Bitcoin protocol constant, not a wallet-core-specific value
    input.amount = sendAmountSats
    input.byteFee = Int64(satsPerByte.rounded(.up))
    input.toAddress = toAddress
    input.changeAddress = changeAddress
    input.useMaxAmount = false
    input.coinType = coin.rawValue
    input.privateKey = [privateKey.data]

    input.utxo = try inputs.map { entry in
      guard let txIdHex = entry["txIdHex"] as? String,
            let vout = entry["vout"] as? Int,
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
      outPoint.index = UInt32(vout)

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
    guard let rawData = txParams["raw_data"] as? [String: Any],
          let contracts = rawData["contract"] as? [[String: Any]],
          let firstContract = contracts.first,
          let parameter = firstContract["parameter"] as? [String: Any],
          let value = parameter["value"] as? [String: Any],
          let toAddressHex = value["to_address"] as? String,
          let amount = value["amount"] as? Int,
          let refBlockBytes = rawData["ref_block_bytes"] as? String,
          let refBlockHash = rawData["ref_block_hash"] as? String,
          let expiration = rawData["expiration"] as? Int,
          let timestamp = rawData["timestamp"] as? Int else {
      throw Exception(name: "InvalidParams", description: "Missing/unrecognized TRX unsigned tx shape")
    }
    let privateKey = wallet.getKeyForCoin(coin: .tron)

    // TronGrid's raw_data.contract[].parameter.value.to_address is raw hex (0x41-prefixed
    // 21-byte address), not the base58check "T..." string wallet-core's TronTransfer.toAddress
    // expects — convert via the coin-agnostic AnyAddress helper.
    guard let toAddressData = ChainSigner.hexData(toAddressHex),
          let toAddress = AnyAddress(data: toAddressData, coin: .tron)?.description else {
      throw Exception(name: "InvalidParams", description: "Invalid TRX to_address")
    }

    var transfer = TronTransfer()
    transfer.toAddress = toAddress
    transfer.amount = Int64(amount)

    var contract = TronTransaction()
    contract.transfer = transfer

    var input = TronSigningInput()
    input.privateKey = privateKey.data
    input.transaction = contract
    input.txID = "" // computed by the signer
    input.refBlockBytes = hexData(refBlockBytes) ?? Data()
    input.refBlockHash = hexData(refBlockHash) ?? Data()
    input.expiration = Int64(expiration)
    input.timestamp = Int64(timestamp)

    let output: TronSigningOutput = AnySigner.sign(input: input, coin: .tron)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.json
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
          let sequence = txParams["Sequence"] as? Int else {
      throw Exception(name: "InvalidParams", description: "Missing required XRP Payment fields")
    }
    let lastLedgerSequence = txParams["LastLedgerSequence"] as? Int
    let destinationTag = txParams["DestinationTag"] as? Int

    let privateKey = wallet.getKeyForCoin(coin: .xrp)

    var payment = RippleOperationPayment()
    payment.amount = Int64(amountDrops) ?? 0
    payment.destination = destination
    if let tag = destinationTag { payment.destinationTag = UInt32(tag) }

    var input = RippleSigningInput()
    input.privateKey = privateKey.data
    input.account = account
    input.fee = Int64(feeDrops) ?? 0
    input.sequence = UInt32(sequence)
    if let lls = lastLedgerSequence { input.lastLedgerSequence = UInt32(lls) }
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
          let seqno = txParams["seqno"] as? Int else {
      throw Exception(name: "InvalidParams", description: "Missing required TON tx params")
    }
    let memoId = txParams["memoId"] as? String

    let privateKey = wallet.getKeyForCoin(coin: .ton)

    var transfer = TheOpenNetworkTransfer()
    transfer.dest = toAddress
    transfer.amount = UInt64(amountStr) ?? 0
    transfer.mode = UInt32(TheOpenNetworkSendMode.payGasSeparately.rawValue | TheOpenNetworkSendMode.ignoreActionPhaseErrors.rawValue)
    transfer.bounceable = true
    if let memoId { transfer.comment = memoId }

    var input = TheOpenNetworkSigningInput()
    input.privateKey = privateKey.data
    input.walletVersion = .walletV4R2
    input.sequenceNumber = UInt32(seqno)
    input.transfer = transfer

    let output: TheOpenNetworkSigningOutput = AnySigner.sign(input: input, coin: .ton)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return ChainSigner.Result(signedTx: output.encoded, meta: ["txHash": output.hash.hexString])
  }

  // MARK: - Helpers

  // Parses a hex string (with or without 0x, odd or even length) into Data.
  static func hexData(_ hex: String) -> Data? {
    let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    let padded = s.count % 2 == 0 ? s : "0" + s
    return padded.isEmpty ? Data([0]) : Data(hexString: padded)
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
