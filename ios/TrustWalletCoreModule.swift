import ExpoModulesCore
import WalletCore

// All numeric transaction fields are bare hex strings (no 0x prefix) to avoid JS number precision loss.
public class TrustWalletCoreModule: Module {
  public func definition() -> ModuleDefinition {
    Name("TrustWalletCore")

    // Returns { mnemonic } — strength 128 = 12 words, 256 = 24 words
    AsyncFunction("generateWallet") { (strength: Int, passphrase: String) throws -> [String: String] in
      guard let wallet = HDWallet(strength: UInt32(strength), passphrase: passphrase) else {
        throw Exception(name: "WalletError", description: "Failed to generate wallet")
      }
      return ["mnemonic": wallet.mnemonic]
    }

    // Validates mnemonic and returns { mnemonic }
    AsyncFunction("restoreWallet") { (mnemonic: String, passphrase: String) throws -> [String: String] in
      guard HDWallet(mnemonic: mnemonic, passphrase: passphrase) != nil else {
        throw Exception(name: "InvalidMnemonic", description: "Invalid mnemonic phrase")
      }
      return ["mnemonic": mnemonic]
    }

    // Derives address and private key for a named coin
    // coin: "ethereum" | "solana"
    AsyncFunction("getAddressForCoin") { (mnemonic: String, coin: String, passphrase: String) throws -> [String: String] in
      guard let wallet = HDWallet(mnemonic: mnemonic, passphrase: passphrase) else {
        throw Exception(name: "InvalidMnemonic", description: "Invalid mnemonic phrase")
      }
      let coinType = try Self.resolveCoinType(coin)
      return [
        "address":    wallet.getAddressForCoin(coin: coinType),
        "privateKey": wallet.getKeyForCoin(coin: coinType).data.hexString,
      ]
    }

    // Signs an Ethereum transaction; returns 0x-prefixed RLP-encoded signed tx hex
    // txParams: { to, valueHex, nonce, gasLimitHex, chainId, dataHex?,
    //             gasPriceHex? (legacy) | maxFeePerGasHex + maxPriorityFeePerGasHex (EIP-1559) }
    AsyncFunction("signEthereumTransaction") { (privateKeyHex: String, txParams: [String: Any]) throws -> String in
      guard let pkData = Data(hexString: privateKeyHex),
            let privateKey = PrivateKey(data: pkData) else {
        throw Exception(name: "InvalidKey", description: "Invalid private key hex")
      }
      guard let to       = txParams["to"] as? String,
            let nonce    = txParams["nonce"] as? Int,
            let gasLimHex = txParams["gasLimitHex"] as? String,
            let chainId  = txParams["chainId"] as? Int else {
        throw Exception(name: "InvalidParams", description: "Missing required tx params")
      }
      let valueHex = (txParams["valueHex"] as? String) ?? "0"
      let dataHex  = (txParams["dataHex"]  as? String) ?? ""

      var input = EthereumSigningInput()
      input.chainID    = Self.intToData(chainId)
      input.nonce      = Self.intToData(nonce)
      input.gasLimit   = Self.hexData(gasLimHex) ?? Data()
      input.toAddress  = to
      input.privateKey = privateKey.data
      if !dataHex.isEmpty { input.txData = Self.hexData(dataHex) ?? Data() }

      var transfer = EthereumTransaction.Transfer()
      transfer.amount = Self.hexData(valueHex) ?? Data([0])
      var tx = EthereumTransaction()
      tx.transfer = transfer
      input.transaction = tx

      if let gasPriceHex = txParams["gasPriceHex"] as? String {
        input.gasPrice = Self.hexData(gasPriceHex) ?? Data()
      } else if let mfHex = txParams["maxFeePerGasHex"] as? String,
                let pfHex = txParams["maxPriorityFeePerGasHex"] as? String {
        input.maxFeePerGas          = Self.hexData(mfHex) ?? Data()
        input.maxInclusionFeePerGas = Self.hexData(pfHex) ?? Data()
      }

      let output: EthereumSigningOutput = AnySigner.sign(input: input, coin: .ethereum)
      guard output.error == .ok else {
        throw Exception(name: "SigningFailed", description: output.errorMessage)
      }
      return "0x" + output.encoded.hexString
    }

    // Signs a Solana transfer; returns base64-encoded signed transaction
    // txParams: { to, lamports (string), recentBlockhash }
    AsyncFunction("signSolanaTransaction") { (privateKeyHex: String, txParams: [String: Any]) throws -> String in
      guard let pkData = Data(hexString: privateKeyHex),
            let privateKey = PrivateKey(data: pkData) else {
        throw Exception(name: "InvalidKey", description: "Invalid private key hex")
      }
      guard let to             = txParams["to"] as? String,
            let lamportsStr    = txParams["lamports"] as? String,
            let lamports       = UInt64(lamportsStr),
            let recentBlockhash = txParams["recentBlockhash"] as? String else {
        throw Exception(name: "InvalidParams", description: "Missing required Solana tx params (to, lamports, recentBlockhash)")
      }

      var transfer = SolanaTransfer()
      transfer.recipient = to
      transfer.value = lamports

      var input = SolanaSigningInput()
      input.recentBlockhash      = recentBlockhash
      input.privateKey           = privateKey.data
      input.transferTransaction  = transfer

      let output: SolanaSigningOutput = AnySigner.sign(input: input, coin: .solana)
      guard output.error == .ok else {
        throw Exception(name: "SigningFailed", description: output.errorMessage)
      }
      return output.encoded
    }
  }

  // MARK: - Helpers

  private static func resolveCoinType(_ coin: String) throws -> CoinType {
    switch coin.lowercased() {
    case "ethereum": return .ethereum
    case "solana":   return .solana
    case "bnb":      return .smartChain
    default:
      throw Exception(name: "UnsupportedCoin", description: "Unsupported coin: \(coin)")
    }
  }

  // Parses a hex string (with or without 0x, odd or even length) into Data
  private static func hexData(_ hex: String) -> Data? {
    let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    let padded = s.count % 2 == 0 ? s : "0" + s
    return padded.isEmpty ? Data([0]) : Data(hexString: padded)
  }

  // Encodes a non-negative integer as minimal big-endian Data
  private static func intToData(_ value: Int) -> Data {
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
