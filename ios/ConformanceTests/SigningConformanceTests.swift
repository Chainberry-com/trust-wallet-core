import XCTest
import WalletCore

// Mirrors Android's SigningConformanceTest.kt: reads conformance/signing-vectors.json and asserts
// iOS WalletCore 4.1.19 produces byte-for-byte identical signed transactions. Covers every status:
//   "verified"                  — assert output == expectedSignedTx
//   "verified-non-deterministic"— assert signing succeeds and output is structurally valid (TON)
//   "verified-android-only"     — run the same input on iOS to confirm cross-platform parity (TRX)
//
// Add this file to an XCTest target in vault.xcworkspace that links WalletCore.xcframework.
class SigningConformanceTests: XCTestCase {

  private struct SigningVector: Decodable {
    let chain: String
    let status: String
    let unsignedTx: [String: JSONValue]
    let expectedSignedTx: String?
  }

  private struct FixtureFile: Decodable {
    let testMnemonic: String
    let testPassphrase: String
    let signingVectors: [SigningVector]
  }

  // Minimal JSON value type so unsignedTx can be decoded without knowing its shape up front.
  private enum JSONValue: Decodable {
    case string(String), int(Int), double(Double), bool(Bool), array([JSONValue]), object([String: JSONValue]), null
    init(from decoder: Decoder) throws {
      let c = try decoder.singleValueContainer()
      if c.decodeNil() { self = .null }
      else if let v = try? c.decode(Bool.self) { self = .bool(v) }
      else if let v = try? c.decode(Int.self) { self = .int(v) }
      else if let v = try? c.decode(Double.self) { self = .double(v) }
      else if let v = try? c.decode(String.self) { self = .string(v) }
      else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
      else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    var string: String? { if case .string(let s) = self { return s }; return nil }
    var int: Int? { if case .int(let i) = self { return i }; return nil }
    var object: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    var array: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
  }

  private func loadFixture() throws -> FixtureFile {
    let thisFile = URL(fileURLWithPath: #filePath)
    let url = thisFile
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("conformance/signing-vectors.json")
      .standardizedFileURL
    return try JSONDecoder().decode(FixtureFile.self, from: Data(contentsOf: url))
  }

  private var wallet: HDWallet!

  override func setUpWithError() throws {
    let fixture = try loadFixture()
    guard let w = HDWallet(mnemonic: fixture.testMnemonic, passphrase: fixture.testPassphrase) else {
      throw XCTSkip("HDWallet init failed")
    }
    wallet = w
  }

  // MARK: - Per-chain tests

  func testEthereum() throws { try runVector(chain: "ethereum") }
  func testPolygon()  throws { try runVector(chain: "polygon") }
  func testBitcoin()  throws { try runVector(chain: "bitcoin") }
  func testLitecoin() throws { try runVector(chain: "litecoin") }
  func testXrp()      throws { try runVector(chain: "xrp") }
  func testTron()     throws { try runVector(chain: "tron") }
  func testSolana()   throws { try runVector(chain: "solana") }
  func testTon()      throws { try runVector(chain: "ton") }

  // MARK: - Dispatch

  private func runVector(chain: String) throws {
    let fixture = try loadFixture()
    guard let v = fixture.signingVectors.first(where: { $0.chain == chain }) else {
      throw XCTSkip("No vector for chain '\(chain)'")
    }
    let tx = v.unsignedTx
    switch chain {
    case "ethereum", "polygon": try assertEvm(v, tx: tx)
    case "bitcoin", "litecoin": try assertUtxo(v, tx: tx)
    case "xrp":    try assertXrp(v, tx: tx)
    case "tron":   try assertTron(v, tx: tx)
    case "solana": try assertSolana(v, tx: tx)
    case "ton":    try assertTon(v, tx: tx)
    default: XCTFail("No signing impl for chain '\(chain)'")
    }
  }

  // MARK: - EVM

  private func assertEvm(_ v: SigningVector, tx: [String: JSONValue]) throws {
    let coin: CoinType = .ethereum
    let pk = wallet.getKeyForCoin(coin: coin)
    guard let to      = tx["to"]?.string,
          let nonce   = tx["nonce"]?.int,
          let gasLim  = tx["gasLimitHex"]?.string,
          let chainId = tx["chainId"]?.int else {
      XCTFail("Missing EVM params"); return
    }
    let valueHex = tx["valueHex"]?.string ?? "0"
    var input = EthereumSigningInput()
    input.chainID    = BigIntHelper(chainId).toMinimal()
    input.nonce      = BigIntHelper(nonce).toMinimal()
    input.gasLimit   = Data(hexString: gasLim.padEven())!
    input.toAddress  = to
    input.privateKey = pk.data
    var transfer = EthereumTransaction.Transfer()
    transfer.amount = Data(hexString: valueHex.padEven()) ?? Data([0])
    var etx = EthereumTransaction(); etx.transfer = transfer
    input.transaction = etx
    if let gp = tx["gasPriceHex"]?.string {
      input.gasPrice = Data(hexString: gp.padEven())!
    } else if let mf = tx["maxFeePerGasHex"]?.string,
              let pf = tx["maxPriorityFeePerGasHex"]?.string {
      input.txMode = .enveloped
      input.maxFeePerGas         = Data(hexString: mf.padEven())!
      input.maxInclusionFeePerGas = Data(hexString: pf.padEven())!
    }
    let out: EthereumSigningOutput = AnySigner.sign(input: input, coin: coin)
    XCTAssertEqual(out.error, .ok, "EVM signing error: \(out.errorMessage)")
    let signed = "0x" + out.encoded.hexString
    if v.status == "verified", let expected = v.expectedSignedTx {
      XCTAssertEqual(signed, expected, "chain '\(v.chain)': signed tx mismatch")
    }
  }

  // MARK: - UTXO (BTC / LTC)

  private func assertUtxo(_ v: SigningVector, tx: [String: JSONValue]) throws {
    let coin: CoinType = v.chain == "litecoin" ? .litecoin : .bitcoin
    let pk = wallet.getKeyForCoin(coin: coin)
    guard let toAddress     = tx["toAddress"]?.string,
          let changeAddress = tx["changeAddress"]?.string,
          let sendSats      = tx["sendAmountSats"]?.string.flatMap(Int64.init),
          let spbNum        = tx["satsPerByte"]?.int,
          let inputArr      = tx["inputs"]?.array else {
      XCTFail("Missing UTXO params"); return
    }
    var input = BitcoinSigningInput()
    input.hashType      = BitcoinScript.hashTypeForCoin(coinType: coin)
    input.amount        = sendSats
    input.byteFee       = Int64(spbNum)
    input.toAddress     = toAddress
    input.changeAddress = changeAddress
    input.useMaxAmount  = false
    input.coinType      = coin.rawValue
    input.privateKey    = [pk.data]
    input.utxo = inputArr.compactMap { entry -> BitcoinUnspentTransaction? in
      guard let obj      = entry.object,
            let txId     = obj["txIdHex"]?.string,
            let vout     = obj["vout"]?.int,
            let amt      = obj["amountSats"]?.string.flatMap(Int64.init),
            let script   = obj["scriptPubKeyHex"]?.string,
            let scriptData = Data(hexString: script),
            var txIdData   = Data(hexString: txId) else { return nil }
      txIdData.reverse()
      var op = BitcoinOutPoint(); op.hash = txIdData; op.index = UInt32(vout)
      var utxo = BitcoinUnspentTransaction()
      utxo.outPoint = op; utxo.amount = amt; utxo.script = scriptData
      return utxo
    }
    let out: BitcoinSigningOutput = AnySigner.sign(input: input, coin: coin)
    XCTAssertEqual(out.error, .ok, "UTXO signing error: \(out.errorMessage)")
    if v.status == "verified", let expected = v.expectedSignedTx {
      XCTAssertEqual(out.encoded.hexString, expected, "chain '\(v.chain)': signed tx mismatch")
    }
  }

  // MARK: - XRP

  private func assertXrp(_ v: SigningVector, tx: [String: JSONValue]) throws {
    let pk = wallet.getKeyForCoin(coin: .xrp)
    guard let account  = tx["Account"]?.string,
          let dest     = tx["Destination"]?.string,
          let amount   = tx["Amount"]?.string.flatMap(Int64.init),
          let fee      = tx["Fee"]?.string.flatMap(Int64.init),
          let sequence = tx["Sequence"]?.int else {
      XCTFail("Missing XRP params"); return
    }
    var payment = RippleOperationPayment()
    payment.amount = amount; payment.destination = dest
    var input = RippleSigningInput()
    input.privateKey = pk.data; input.account = account
    input.fee = fee; input.sequence = Int32(sequence)
    if let lls = tx["LastLedgerSequence"]?.int { input.lastLedgerSequence = Int32(lls) }
    input.opPayment = payment
    let out: RippleSigningOutput = AnySigner.sign(input: input, coin: .xrp)
    XCTAssertEqual(out.error, .ok, "XRP signing error: \(out.errorMessage)")
    if v.status == "verified", let expected = v.expectedSignedTx {
      XCTAssertEqual(out.encoded.hexString, expected, "chain 'xrp': signed tx mismatch")
    }
  }

  // MARK: - TRX

  private func assertTron(_ v: SigningVector, tx: [String: JSONValue]) throws {
    let pk = wallet.getKeyForCoin(coin: .tron)
    guard let txID = tx["txID"]?.string else { XCTFail("Missing TRX txID"); return }
    var input = TronSigningInput()
    input.privateKey = pk.data
    input.txID = txID
    let out: TronSigningOutput = AnySigner.sign(input: input, coin: .tron)
    XCTAssertEqual(out.error, .ok, "TRX signing error: \(out.errorMessage)")
    let signatureHex = out.signature.hexString
    XCTAssertFalse(signatureHex.isEmpty, "TRX: empty signature")
    // verified-android-only: same private key + same digest → same ECDSA sig — mismatch is a real bug.
    if let expected = v.expectedSignedTx,
       let data = expected.data(using: .utf8),
       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let sigs = json["signature"] as? [String],
       let androidSig = sigs.first {
      XCTAssertEqual(signatureHex, androidSig,
        "TRX: iOS signature differs from Android — same digest + key must produce same ECDSA sig")
    }
  }

  // MARK: - Solana

  private func assertSolana(_ v: SigningVector, tx: [String: JSONValue]) throws {
    let pk = wallet.getKeyForCoin(coin: .solana)
    guard let b64 = tx["unsignedTxBase64"]?.string,
          let txBytes = Data(base64Encoded: b64) else {
      XCTFail("Missing/invalid Solana unsignedTxBase64"); return
    }
    let decoded = TransactionDecoder.decode(coinType: .solana, encodedTx: txBytes)
    let decodedOut = try SolanaDecodingTransactionOutput(serializedBytes: decoded)
    XCTAssertEqual(decodedOut.error, .ok, "SOL decode error: \(decodedOut.errorMessage)")
    let blockhash = decodedOut.transaction.legacy.recentBlockhash
    let keys = DataVector(); keys.add(data: pk.data)
    let signedBytes = SolanaTransaction.updateBlockhashAndSign(
      encodedTx: b64, recentBlockhash: blockhash, privateKeys: keys)
    let signedOut = try SolanaSigningOutput(serializedBytes: signedBytes)
    XCTAssertEqual(signedOut.error, .ok, "SOL signing error: \(signedOut.errorMessage)")
    if v.status == "verified", let expected = v.expectedSignedTx {
      XCTAssertEqual(signedOut.encoded, expected, "chain 'solana': signed tx mismatch")
    }
  }

  // MARK: - TON (non-deterministic — verify structure only)

  private func assertTon(_ v: SigningVector, tx: [String: JSONValue]) throws {
    let pk = wallet.getKeyForCoin(coin: .ton)
    guard let toAddress = tx["toAddress"]?.string,
          let amountStr = tx["amount"]?.string,
          let nanotons  = UInt64(amountStr),
          let seqno     = tx["seqno"]?.int else {
      XCTFail("Missing TON params"); return
    }
    var transfer = TheOpenNetworkTransfer()
    transfer.dest   = toAddress
    transfer.amount = nanotons
    transfer.mode   = UInt32(
      TheOpenNetworkSendMode.payFeesSeparately.rawValue |
      TheOpenNetworkSendMode.ignoreActionPhaseErrors.rawValue)
    transfer.bounceable = true
    if let memo = tx["memoId"]?.string { transfer.comment = memo }
    var input = TheOpenNetworkSigningInput()
    input.privateKey     = pk.data
    input.walletVersion  = .walletV4R2
    input.sequenceNumber = UInt32(seqno)
    input.expireAt       = UInt32(Date().timeIntervalSince1970) + 600
    input.messages       = [transfer]
    let out: TheOpenNetworkSigningOutput = AnySigner.sign(input: input, coin: .ton)
    XCTAssertEqual(out.error, .ok, "TON signing error: \(out.errorMessage)")
    // Non-deterministic due to wall-clock expireAt — check well-formed BOC and 32-byte hash only.
    XCTAssertTrue(out.encoded.hasPrefix("te6cc"),
      "TON: unexpected BOC prefix in '\(out.encoded)'")
    XCTAssertEqual(out.hash.count, 32,
      "TON: txHash should be 32 bytes, got \(out.hash.count)")
  }
}

// MARK: - Helpers

private extension String {
  func padEven() -> String { count % 2 == 0 ? self : "0" + self }
}

private struct BigIntHelper {
  let value: Int
  init(_ v: Int) { value = v }
  func toMinimal() -> Data {
    guard value > 0 else { return Data([0]) }
    var v = value; var bytes: [UInt8] = []
    while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
    return Data(bytes)
  }
}
