import Foundation
import ExpoModulesCore
import WalletCore

// All chains this module derives addresses for / signs transactions for.

enum ChainKey: String, CaseIterable {
  case ethereum, bnb, polygon
  case avax, base, arbitrum, optimism, sonic
  case solana
  case tron, ton
  case bitcoin, bitcoincash, dogecoin, litecoin
  case xrp
  case cosmos
  case aptos
  case tezos

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
    case .avax:     return "AVAX"
    case .base:     return "ETH"
    case .arbitrum: return "ETH"
    case .optimism: return "ETH"
    case .sonic:    return "S"
    case .solana:   return "SOL"
    case .tron:     return "TRX"
    case .ton:      return "TON"
    case .bitcoin:  return "BTC"
    case .bitcoincash: return "BCH"
    case .dogecoin: return "DOGE"
    case .litecoin: return "LTC"
    case .xrp:      return "XRP"
    case .cosmos:   return "ATOM"
    case .aptos:    return "APT"
    case .tezos:    return "XTZ"
    }
  }

  // All EVM chains share Ethereum's secp256k1 key/address (BIP44 slip44 = 60) — no distinct CoinType.
  var coinType: CoinType {
    switch self {
    case .ethereum, .polygon, .avax, .base, .arbitrum, .optimism, .sonic: return .ethereum
    case .bnb: return .smartChain
    case .solana: return .solana
    case .tron: return .tron
    case .ton: return .ton
    case .bitcoin: return .bitcoin
    case .bitcoincash: return .bitcoinCash
    case .dogecoin: return .dogecoin
    case .litecoin: return .litecoin
    case .xrp: return .xrp
    case .cosmos: return .cosmos
    case .aptos: return .aptos
    case .tezos: return .tezos
    }
  }
}

enum ChainSigner {
  struct Result {
    let signedTx: String
    let meta: [String: Any]?
  }

  // SLIP-44 dedicates coin_type 1' to "testnet" for every coin — so a shared literal path
  // would make Litecoin and Bitcoin Cash derive the *same* key (BIP32 derivation only depends
  // on (seed, path, curve), and CoinType alone doesn't perturb it when the path and curve —
  // secp256k1 for both — are identical). Disambiguate by using each coin's own SLIP-44 index
  // as the account (3rd) path component. `purpose` follows the usual BIP44/49/84 convention
  // (44' legacy, 84' native segwit) matching the address style each coin actually gets below.
  private static func utxoTestnetPath(_ chain: ChainKey, purpose: Int) -> String {
    // .rawValue is this coin's SLIP-44 id (same value `signUtxo` already sends as
    // `input.coinType = coin.rawValue` below) — reusing it here instead of an unverified
    // `.slip44Id` accessor keeps this to APIs already proven to exist in this binding.
    "m/\(purpose)'/1'/\(chain.coinType.rawValue)'/0/0"
  }

  private static let litecoinTestnetHRP = "tltc"

  // Bitcoin Cash testnet legacy P2PKH version byte (0x6F) — same value Bitcoin/Litecoin
  // testnets use for their base58 legacy prefix. BCH has no bech32/cashaddr testnet support in
  // wallet-core (cashaddr is a different, more involved encoding than bech32 — unlike
  // Litecoin below, not reimplemented here), so it stays on this legacy fallback.
  private static let bchTestnetP2PKHPrefix: UInt8 = 0x6F

  /// Address for `chain`, honoring `isTestnet`.
  ///
  /// wallet-core's coin registry only carries a real testnet derivation for Bitcoin
  /// (`.bitcoinTestnet`, native segwit — same "bc1"→"tb1" style shift as mainnet). Litecoin and
  /// Bitcoin Cash have no testnet entry at all (no CoinType, no Derivation):
  ///  - Litecoin gets a hand-rolled native-segwit bech32 address (see Bech32.swift) — the same
  ///    style as its own mainnet "ltc1..." address, just hrp "tltc" instead of "ltc". wallet-
  ///    core's `SegwitAddress` can't do this itself (its HRP is a closed native enum with no
  ///    "tltc" entry), so this reimplements the encode half of BIP-173 by hand.
  ///  - Bitcoin Cash gets a legacy P2PKH address instead — a different *style* from its own
  ///    mainnet cashaddr address (cashaddr testnet isn't implemented), but still a real,
  ///    correctly-testnet-flagged one.
  static func address(for chain: ChainKey, wallet: HDWallet, isTestnet: Bool) -> String {
    guard isTestnet else { return wallet.getAddressForCoin(coin: chain.coinType) }
    switch chain {
    case .bitcoin:
      return wallet.getAddressDerivation(coin: .bitcoin, derivation: .bitcoinTestnet)
    case .litecoin:
      let pubKey = key(for: chain, wallet: wallet, isTestnet: true).getPublicKeySecp256k1(compressed: true)
      return Bech32.encodeSegwitV0(hrp: litecoinTestnetHRP, program: pubKey.bitcoinKeyHash)
    case .bitcoincash:
      let pubKey = key(for: chain, wallet: wallet, isTestnet: true).getPublicKeySecp256k1(compressed: true)
      return BitcoinAddress(publicKey: pubKey, prefix: bchTestnetP2PKHPrefix)!.description
    // Everything else (EVM/Solana/Tron/Ton/Xrp) shares one address format across
    // mainnet/testnet — only the RPC endpoint differs, which lives entirely in JS.
    default:
      return wallet.getAddressForCoin(coin: chain.coinType)
    }
  }

  /// The signing key for `chain`, honoring `isTestnet` — must always derive the same key
  /// `address(for:)` used, or a UTXO signer builds a transaction that can't spend the
  /// wallet's own funds (wrong key ⇒ different scriptPubKey than what's actually sitting at
  /// the receive address it was given).
  private static func key(for chain: ChainKey, wallet: HDWallet, isTestnet: Bool) -> PrivateKey {
    guard isTestnet else { return wallet.getKeyForCoin(coin: chain.coinType) }
    switch chain {
    case .bitcoin:
      return wallet.getKeyDerivation(coin: .bitcoin, derivation: .bitcoinTestnet)
    case .litecoin:
      return wallet.getKey(coin: chain.coinType, derivationPath: utxoTestnetPath(chain, purpose: 84))
    case .bitcoincash:
      return wallet.getKey(coin: chain.coinType, derivationPath: utxoTestnetPath(chain, purpose: 44))
    default:
      return wallet.getKeyForCoin(coin: chain.coinType)
    }
  }

  static func sign(chain: ChainKey, wallet: HDWallet, unsignedTx: [String: Any], isTestnet: Bool) throws -> Result {
    switch chain {
    case .ethereum, .bnb, .polygon, .avax, .base, .arbitrum, .optimism, .sonic:
      return Result(signedTx: try signEvm(wallet: wallet, coin: chain.coinType, txParams: unsignedTx), meta: nil)
    case .solana:
      return Result(signedTx: try signSolana(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .bitcoin, .dogecoin, .litecoin:
      return Result(signedTx: try signUtxo(wallet: wallet, chain: chain, txParams: unsignedTx, isTestnet: isTestnet), meta: nil)
    case .tron:
      return Result(signedTx: try signTron(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .xrp:
      return Result(signedTx: try signXrp(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .ton:
      return try signTon(wallet: wallet, txParams: unsignedTx)
    case .bitcoincash:
      return Result(signedTx: try signBch(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .cosmos:
      return Result(signedTx: try signCosmos(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .aptos:
      return Result(signedTx: try signAptos(wallet: wallet, txParams: unsignedTx), meta: nil)
    case .tezos:
      return Result(signedTx: try signTezos(wallet: wallet, txParams: unsignedTx), meta: nil)
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

  // MARK: - BCH (UTXO-based, replay-protected)
  // txParams: { unsignedDescriptorJson: string }
  // descriptor (from wallet-broadcast's prepareBchTransaction):
  //   { inputs: [{ txid, vout, satoshis, scriptPubKeyHex }], toAddress, sendAmountSats,
  //     changeAddress?, changeSats? }
  // BCH uses SIGHASH_ALL | SIGHASH_FORK_ID (0x41) for replay protection — distinct from
  // BTC/LTC's plain SIGHASH_ALL (0x01).
  private static func signBch(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    guard let descriptorJson = txParams["unsignedDescriptorJson"] as? String,
          let descriptorData = descriptorJson.data(using: .utf8),
          let descriptor = try? JSONSerialization.jsonObject(with: descriptorData) as? [String: Any],
          let toAddress = descriptor["toAddress"] as? String,
          let sendAmountSats = (descriptor["sendAmountSats"] as? NSNumber)?.int64Value,
          let inputs = descriptor["inputs"] as? [[String: Any]] else {
      throw Exception(name: "InvalidParams", description: "Invalid BCH descriptor JSON")
    }

    let privateKey = wallet.getKeyForCoin(coin: .bitcoinCash)

    var input = BitcoinSigningInput()
    input.hashType = 0x41 // SIGHASH_ALL | SIGHASH_FORK_ID (BCH replay protection)
    input.amount = sendAmountSats
    input.byteFee = 1 // BCH fees are minimal; 1 sat/byte is the ecosystem standard
    input.toAddress = toAddress
    if let changeAddress = descriptor["changeAddress"] as? String {
      input.changeAddress = changeAddress
    }
    input.useMaxAmount = false
    input.coinType = CoinType.bitcoinCash.rawValue
    input.privateKey = [privateKey.data]

    input.utxo = try inputs.map { entry in
      guard let txid = entry["txid"] as? String,
            let voutNum = entry["vout"] as? NSNumber,
            let satoshisNum = entry["satoshis"] as? NSNumber,
            let scriptHex = entry["scriptPubKeyHex"] as? String,
            let scriptData = hexData(scriptHex),
            var txIdData = hexData(txid) else {
        throw Exception(name: "InvalidParams", description: "Invalid BCH UTXO entry")
      }
      txIdData.reverse()

      var outPoint = BitcoinOutPoint()
      outPoint.hash = txIdData
      outPoint.index = UInt32(voutNum.intValue)

      var utxo = BitcoinUnspentTransaction()
      utxo.outPoint = outPoint
      utxo.amount = satoshisNum.int64Value
      utxo.script = scriptData
      return utxo
    }

    let output: BitcoinSigningOutput = AnySigner.sign(input: input, coin: .bitcoinCash)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.encoded.hexString
  }

  // MARK: - BTC / LTC (UTXO-based)
  // txParams (from wallet-broadcast's additive prepareBtcUtxoSet/prepareLtcUtxoSet):
  // { toAddress, changeAddress, sendAmountSats, changeAmountSats, satsPerByte,
  //   inputs: [{ txIdHex, vout, amountSats, scriptPubKeyHex }] }
  // NOTE(verify-on-device): field names (hashType/toAddress/changeAddress/byteFee/utxo/
  // outPoint/privateKey) match wallet-core's long-documented Bitcoin signing example, but
  // confirm against the installed 4.1.19 generated Swift types before trusting with real funds.
  private static func signUtxo(wallet: HDWallet, chain: ChainKey, txParams: [String: Any], isTestnet: Bool) throws -> String {
    guard let toAddress = txParams["toAddress"] as? String,
          let changeAddress = txParams["changeAddress"] as? String,
          let sendAmountSats = (txParams["sendAmountSats"] as? String).flatMap(Int64.init),
          let satsPerByteNum = txParams["satsPerByte"] as? NSNumber,
          let inputs = txParams["inputs"] as? [[String: Any]] else {
      throw Exception(name: "InvalidParams", description: "Missing required UTXO tx params")
    }

    let coin = chain.coinType
    let privateKey = key(for: chain, wallet: wallet, isTestnet: isTestnet)

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

  // MARK: - Cosmos (ATOM)
  // txParams: { accountNumber, sequence, chainId, feeAmount, gas, memo, fromAddress, toAddress,
  //             amount (uatom, decimal string), denom }
  // Returns output.serialized — the ready-to-broadcast JSON
  // {"mode":"BROADCAST_MODE_SYNC","tx_bytes":"<base64>"} posted directly to the Cosmos LCD.
  private static func signCosmos(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    guard let fromAddress = txParams["fromAddress"] as? String,
          let toAddress = txParams["toAddress"] as? String,
          let amountStr = txParams["amount"] as? String,
          let feeAmountStr = txParams["feeAmount"] as? String,
          let denom = txParams["denom"] as? String,
          let chainId = txParams["chainId"] as? String,
          let accountNumberNum = txParams["accountNumber"] as? NSNumber,
          let sequenceNum = txParams["sequence"] as? NSNumber,
          let gasNum = txParams["gas"] as? NSNumber else {
      throw Exception(name: "InvalidParams", description: "Missing required Cosmos tx params")
    }
    let memo = (txParams["memo"] as? String) ?? ""

    let privateKey = wallet.getKeyForCoin(coin: .cosmos)

    var sendAmount = CosmosAmount()
    sendAmount.denom = denom
    sendAmount.amount = amountStr

    var send = CosmosMessage.Send()
    send.fromAddress = fromAddress
    send.toAddress = toAddress
    send.amounts = [sendAmount]

    var message = CosmosMessage()
    message.sendCoinsMessage = send

    var feeAmt = CosmosAmount()
    feeAmt.denom = denom
    feeAmt.amount = feeAmountStr

    var fee = CosmosFee()
    fee.amounts = [feeAmt]
    fee.gas = UInt64(gasNum.intValue)

    var input = CosmosSigningInput()
    input.signingMode = .protobuf
    input.accountNumber = UInt64(accountNumberNum.intValue)
    input.chainID = chainId
    input.sequence = UInt64(sequenceNum.intValue)
    input.memo = memo
    input.fee = fee
    input.messages = [message]
    input.privateKey = privateKey.data
    input.mode = .sync

    let output: CosmosSigningOutput = AnySigner.sign(input: input, coin: .cosmos)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.serialized
  }

  // MARK: - Aptos (APT)
  // txParams: { sender, sequenceNumber, maxGasAmount, gasUnitPrice, expirationTimestampSecs,
  //             chainId, toAddress, amount (octas, decimal string) }
  // Returns output.json — the signed JSON body posted directly to the Aptos REST API.
  private static func signAptos(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    guard let sender = txParams["sender"] as? String,
          let toAddress = txParams["toAddress"] as? String,
          let amountStr = txParams["amount"] as? String,
          let seqNum = txParams["sequenceNumber"] as? NSNumber,
          let maxGas = txParams["maxGasAmount"] as? NSNumber,
          let gasPrice = txParams["gasUnitPrice"] as? NSNumber,
          let expiry = txParams["expirationTimestampSecs"] as? NSNumber,
          let chainId = txParams["chainId"] as? NSNumber else {
      throw Exception(name: "InvalidParams", description: "Missing required Aptos tx params")
    }
    guard let amountOctas = UInt64(amountStr) else {
      throw Exception(name: "InvalidParams", description: "Invalid Aptos amount: \(amountStr)")
    }

    let privateKey = wallet.getKeyForCoin(coin: .aptos)

    var transfer = AptosTransferMessage()
    transfer.to = toAddress
    transfer.amount = amountOctas

    var input = AptosSigningInput()
    input.sender = sender
    input.sequenceNumber = Int64(seqNum.intValue)
    input.maxGasAmount = UInt64(maxGas.intValue)
    input.gasUnitPrice = UInt64(gasPrice.intValue)
    input.expirationTimestampSecs = UInt64(expiry.intValue)
    input.chainID = UInt32(chainId.intValue)
    input.privateKey = privateKey.data
    input.transfer = transfer

    let output: AptosSigningOutput = AnySigner.sign(input: input, coin: .aptos)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.json
  }

  // MARK: - Tezos (XTZ)
  // txParams: { branch, fromAddress, toAddress, counter, amount (mutez), fee (mutez),
  //             gasLimit, storageLimit, needsReveal }
  // Returns output.encoded hex — posted to /injection/operation as a JSON-encoded string.
  private static func signTezos(wallet: HDWallet, txParams: [String: Any]) throws -> String {
    guard let branch = txParams["branch"] as? String,
          let fromAddress = txParams["fromAddress"] as? String,
          let toAddress = txParams["toAddress"] as? String,
          let counterNum = txParams["counter"] as? NSNumber,
          let amountNum = txParams["amount"] as? NSNumber,
          let feeNum = txParams["fee"] as? NSNumber,
          let gasLimitNum = txParams["gasLimit"] as? NSNumber,
          let storageLimitNum = txParams["storageLimit"] as? NSNumber else {
      throw Exception(name: "InvalidParams", description: "Missing required Tezos tx params")
    }
    let needsReveal = (txParams["needsReveal"] as? Bool) ?? false
    let counter = counterNum.int64Value

    let privateKey = wallet.getKeyForCoin(coin: .tezos)
    var operations: [TezosOperation] = []

    if needsReveal {
      let pubKey = privateKey.getPublicKeyEd25519()
      var revealData = TezosRevealOperationData()
      revealData.publicKey = pubKey.data

      var reveal = TezosOperation()
      reveal.source = fromAddress
      reveal.counter = counter - 1
      reveal.fee = 1420
      reveal.gasLimit = 10600
      reveal.storageLimit = 0
      reveal.kind = .reveal
      reveal.revealOperationData = revealData
      operations.append(reveal)
    }

    var txData = TezosTransactionOperationData()
    txData.destination = toAddress
    txData.amount = amountNum.int64Value

    var txOp = TezosOperation()
    txOp.source = fromAddress
    txOp.counter = counter
    txOp.fee = feeNum.int64Value
    txOp.gasLimit = gasLimitNum.int64Value
    txOp.storageLimit = storageLimitNum.int64Value
    txOp.kind = .transaction
    txOp.transactionOperationData = txData
    operations.append(txOp)

    var opList = TezosOperationList()
    opList.branch = branch
    opList.operations = operations

    var input = TezosSigningInput()
    input.operationList = opList
    input.privateKey = privateKey.data

    let output: TezosSigningOutput = AnySigner.sign(input: input, coin: .tezos)
    guard output.error == .ok else {
      throw Exception(name: "SigningFailed", description: output.errorMessage)
    }
    return output.encoded.hexString
  }

  // MARK: - Transaction summary for native confirmation UI

  static func buildSummary(chain: ChainKey, unsignedTx: [String: Any]) throws -> String {
    var lines = ["Network: \(chain.rawValue.uppercased())"]
    switch chain {
    case .ethereum, .bnb, .polygon, .avax, .base, .arbitrum, .optimism, .sonic:
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
        let sel = stripped.prefix(8).lowercased()
        if sel == "a9059cbb", stripped.count >= 136 {
          // transfer(address recipient, uint256 amount)
          let recipient = "0x" + String(stripped.dropFirst(32).prefix(40))
          let amountHex = String(stripped.dropFirst(72).prefix(64)).drop(while: { $0 == "0" })
          lines.append("Token transfer to: \(fmtAddr(recipient))")
          lines.append("Token amount (raw units): 0x\(amountHex.isEmpty ? "0" : String(amountHex))")
        } else if sel == "23b872dd", stripped.count >= 200 {
          // transferFrom(address from, address to, uint256 amount)
          let to = "0x" + String(stripped.dropFirst(96).prefix(40))
          let amountHex = String(stripped.dropFirst(136).prefix(64)).drop(while: { $0 == "0" })
          lines.append("Token transfer to: \(fmtAddr(to))")
          lines.append("Token amount (raw units): 0x\(amountHex.isEmpty ? "0" : String(amountHex))")
        } else {
          lines.append("Contract data: \(stripped.count / 2) bytes — review carefully")
        }
      }

    case .bitcoin, .dogecoin, .litecoin:
      if let to = unsignedTx["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      let sendSats = (unsignedTx["sendAmountSats"] as? String).flatMap(Int64.init) ?? 0
      if sendSats > 0 { lines.append("Amount: \(fmtAmt(Double(sendSats) / 1e8)) \(chain.symbol)") }
      if let change = unsignedTx["changeAddress"] as? String { lines.append("Change to: \(fmtAddr(change))") }
      if let spb = unsignedTx["satsPerByte"] as? NSNumber { lines.append("Fee rate: \(spb.intValue) sat/vB") }
      let inputTotal = (unsignedTx["inputs"] as? [[String: Any]])?
        .compactMap { ($0["amountSats"] as? String).flatMap(Int64.init) }
        .reduce(Int64(0), +) ?? 0
      let changeSats = (unsignedTx["changeAmountSats"] as? String).flatMap(Int64.init) ?? 0
      let totalFee = inputTotal - sendSats - changeSats
      if totalFee > 0 { lines.append("Total fee: \(fmtAmt(Double(totalFee) / 1e8)) \(chain.symbol)") }

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
      let memoTon = unsignedTx["memoId"] as? String
      if let memo = memoTon, !memo.isEmpty { lines.append("Memo: \(memo)") }
      let feeEst = (memoTon?.isEmpty == false) ? "~0.006" : "~0.005"
      lines.append("Fee: \(feeEst) TON (estimate)")

    case .tron:
      if let rawData = unsignedTx["raw_data"] as? [String: Any],
         let contracts = rawData["contract"] as? [[String: Any]],
         let first = contracts.first {
        let type_ = first["type"] as? String ?? ""
        if let param = first["parameter"] as? [String: Any],
           let value = param["value"] as? [String: Any] {
          switch type_ {
          case "TransferContract":
            if let to = value["to_address"] as? String { lines.append("To: \(fmtAddr(to))") }
            if let amount = value["amount"] as? Int { lines.append("Amount: \(fmtAmt(Double(amount) / 1e6)) TRX") }
          case "TriggerSmartContract":
            if let contractAddr = value["contract_address"] as? String {
              lines.append("Token contract: \(fmtAddr(contractAddr))")
            }
            let dataHex = (value["data"] as? String) ?? ""
            let stripped = dataHex.hasPrefix("0x") ? String(dataHex.dropFirst(2)) : dataHex
            let sel = stripped.prefix(8).lowercased()
            if sel == "a9059cbb" && stripped.count >= 136 {
              // TRC-20 transfer(address, uint256) — ABI encoding identical to EVM
              let recipientHex = "0x" + String(stripped.dropFirst(32).prefix(40))
              let amountHex = String(stripped.dropFirst(72).prefix(64)).drop(while: { $0 == "0" })
              lines.append("TRC-20 to: \(fmtAddr(recipientHex))")
              lines.append("Token amount (raw units): 0x\(amountHex.isEmpty ? "0" : String(amountHex))")
            } else {
              lines.append("Contract call: \(stripped.count / 2) bytes — review carefully")
            }
          default:
            if !type_.isEmpty { lines.append("Contract type: \(type_) — review carefully") }
          }
        }
      }
      // Verify txID == SHA256(raw_data_hex). raw_data_hex must be present — fail closed if absent
      // so a JS caller cannot suppress the integrity check by omitting the field.
      guard let txID = unsignedTx["txID"] as? String else {
        throw Exception(name: "TxIntegrityFailed", description: "TRX txID missing — signing refused")
      }
      guard let rawHex = unsignedTx["raw_data_hex"] as? String,
            let rawBytes = hexData(rawHex) else {
        throw Exception(name: "TxIntegrityFailed",
          description: "TRX raw_data_hex missing — cannot verify txID, signing refused")
      }
      let computed = Hash.sha256(data: rawBytes)
      let computedHex = computed.map { String(format: "%02x", $0) }.joined()
      guard computedHex.lowercased() == txID.lowercased() else {
        throw Exception(name: "TxIntegrityFailed",
          description: "TRX txID does not match SHA256(raw_data_hex) — signing refused")
      }
      lines.append("TxID verified ✓")

    case .solana:
      // Decode the pre-built tx to extract recipient and lamports (SOL) or destination and
      // amount (SPL token). Falls closed — throws if the tx cannot be decoded at all.
      guard let info = decodeSolanaForSummary(unsignedTx) else {
        throw Exception(name: "UndecodableTx",
          description: "Cannot decode Solana transaction — signing refused to prevent blind signing")
      }
      if info.isSplTransfer {
        if let dest = info.splDest { lines.append("SPL Token to: \(fmtAddr(dest))") }
        if let amt = info.splAmount { lines.append("SPL Token amount (raw): \(amt)") }
      } else {
        if let to = info.to { lines.append("To: \(fmtAddr(to))") }
        if let lamports = info.lamports { lines.append("Amount: \(fmtAmt(Double(lamports) / 1e9)) SOL") }
        if !info.isTransfer { lines.append("Non-transfer instruction — review carefully") }
      }

    case .bitcoincash:
      // Fail closed — if descriptor is absent or unparseable we cannot show what will be signed.
      guard let descriptorJson = unsignedTx["unsignedDescriptorJson"] as? String,
            let data = descriptorJson.data(using: .utf8),
            let descriptor = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw Exception(name: "UndecodableTx",
          description: "Cannot decode BCH descriptor — signing refused to prevent blind signing")
      }
      if let to = descriptor["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      if let sats = (descriptor["sendAmountSats"] as? NSNumber)?.int64Value {
        lines.append("Amount: \(fmtAmt(Double(sats) / 1e8)) BCH")
      }
      if let change = descriptor["changeAddress"] as? String { lines.append("Change to: \(fmtAddr(change))") }
      if let spb = (descriptor["satsPerByte"] as? NSNumber)?.intValue { lines.append("Fee rate: \(spb) sat/vB") }
      let bchInputs = (descriptor["inputs"] as? [[String: Any]])?
        .compactMap { ($0["amountSats"] as? NSNumber)?.int64Value }
        .reduce(Int64(0), +) ?? 0
      let bchSend = (descriptor["sendAmountSats"] as? NSNumber)?.int64Value ?? 0
      let bchChange = (descriptor["changeAmountSats"] as? NSNumber)?.int64Value ?? 0
      let bchFee = bchInputs - bchSend - bchChange
      if bchFee > 0 { lines.append("Total fee: \(fmtAmt(Double(bchFee) / 1e8)) BCH") }

    case .cosmos:
      if let to = unsignedTx["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      if let uatom = (unsignedTx["amount"] as? String).flatMap(Int64.init) {
        lines.append("Amount: \(fmtAmt(Double(uatom) / 1_000_000)) ATOM")
      }
      if let feeUatom = (unsignedTx["feeAmount"] as? String).flatMap(Int64.init) {
        lines.append("Fee: \(fmtAmt(Double(feeUatom) / 1_000_000)) ATOM")
      }

    case .aptos:
      if let to = unsignedTx["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      if let octas = (unsignedTx["amount"] as? String).flatMap(UInt64.init) {
        lines.append("Amount: \(fmtAmt(Double(octas) / 1e8)) APT")
      }
      if let maxGas = (unsignedTx["maxGasAmount"] as? NSNumber)?.uint64Value,
         let gasPrice = (unsignedTx["gasUnitPrice"] as? NSNumber)?.uint64Value {
        let feeOctas = maxGas * gasPrice
        lines.append("Max fee: \(fmtAmt(Double(feeOctas) / 1e8)) APT")
      }

    case .tezos:
      if let to = unsignedTx["toAddress"] as? String { lines.append("To: \(fmtAddr(to))") }
      if let mutez = (unsignedTx["amount"] as? NSNumber)?.int64Value {
        lines.append("Amount: \(fmtAmt(Double(mutez) / 1_000_000)) XTZ")
      }
      if let feeMutez = (unsignedTx["fee"] as? NSNumber)?.int64Value {
        lines.append("Fee: \(fmtAmt(Double(feeMutez) / 1_000_000)) XTZ")
      }
      if let reveal = unsignedTx["needsReveal"] as? Bool, reveal {
        lines.append("(includes reveal operation)")
      }
    }
    return lines.joined(separator: "\n")
  }

  private struct SolanaSummaryInfo {
    let to: String?
    let lamports: UInt64?
    let isTransfer: Bool
    let splDest: String?
    let splAmount: UInt64?
    let isSplTransfer: Bool
  }

  private static func decodeSolanaForSummary(_ txParams: [String: Any]) -> SolanaSummaryInfo? {
    guard let b64 = txParams["unsignedTxBase64"] as? String,
          let txData = Data(base64Encoded: b64) else { return nil }
    let rawBytes = TransactionDecoder.decode(coinType: .solana, encodedTx: txData)
    guard let decoded = try? SolanaDecodingTransactionOutput(serializedBytes: rawBytes),
          decoded.error == .ok else { return nil }
    let accounts = decoded.transaction.legacy.accountKeys
    let instrs = decoded.transaction.legacy.instructions

    let systemProgram = "11111111111111111111111111111111"
    // SPL Token Program and Token-2022
    let splPrograms: Set<String> = [
      "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
    ]

    // Find first SystemProgram instruction (skip ComputeBudget etc.)
    // and first SPL Token instruction in a single pass.
    var systemIx: TW_Solana_Proto_RawMessage.Instruction? = nil
    var splIx: TW_Solana_Proto_RawMessage.Instruction? = nil
    for instr in instrs {
      let prog = safeGet(accounts, Int(instr.programID)) ?? ""
      if systemIx == nil && prog == systemProgram { systemIx = instr }
      if splIx == nil && splPrograms.contains(prog) { splIx = instr }
    }

    if let ix = systemIx {
      let to: String? = ix.accounts.count >= 2 ? safeGet(accounts, Int(ix.accounts[1])) : nil
      // SystemProgram Transfer discriminator: [2, 0, 0, 0] as u32-LE
      let isTransfer = ix.programData.count >= 12 && ix.programData.prefix(4) == Data([2, 0, 0, 0])
      var lamports: UInt64?
      if isTransfer {
        var v: UInt64 = 0
        for (i, b) in ix.programData.dropFirst(4).prefix(8).enumerated() { v |= UInt64(b) << (i * 8) }
        lamports = v
      }
      return SolanaSummaryInfo(to: to, lamports: lamports, isTransfer: isTransfer,
                               splDest: nil, splAmount: nil, isSplTransfer: false)
    }

    if let ix = splIx {
      let data = ix.programData
      // SPL instruction byte 0: 3 = Transfer, 12 = TransferChecked
      // Transfer: accounts[0]=src, accounts[1]=dest, accounts[2]=owner; data[1..8]=amount LE u64
      // TransferChecked: accounts[0]=src, accounts[1]=mint, accounts[2]=dest, accounts[3]=owner
      if !data.isEmpty && data[0] == 3 && data.count >= 9 {
        let dest = ix.accounts.count >= 2 ? safeGet(accounts, Int(ix.accounts[1])) : nil
        var amount: UInt64 = 0
        for (i, b) in data.dropFirst(1).prefix(8).enumerated() { amount |= UInt64(b) << (i * 8) }
        return SolanaSummaryInfo(to: nil, lamports: nil, isTransfer: false,
                                 splDest: dest, splAmount: amount, isSplTransfer: true)
      } else if !data.isEmpty && data[0] == 12 && data.count >= 10 {
        let dest = ix.accounts.count >= 3 ? safeGet(accounts, Int(ix.accounts[2])) : nil
        var amount: UInt64 = 0
        for (i, b) in data.dropFirst(1).prefix(8).enumerated() { amount |= UInt64(b) << (i * 8) }
        return SolanaSummaryInfo(to: nil, lamports: nil, isTransfer: false,
                                 splDest: dest, splAmount: amount, isSplTransfer: true)
      }
      return SolanaSummaryInfo(to: nil, lamports: nil, isTransfer: false,
                               splDest: nil, splAmount: nil, isSplTransfer: false)
    }

    return nil
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
