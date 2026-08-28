import Foundation

/// Minimal BIP-173 (bech32) segwit-address encoder, witness-version-0 only.
///
/// wallet-core's own `SegwitAddress` class only accepts an HRP from its closed native `HRP`
/// enum — there's no "tltc" entry (Litecoin testnet isn't in wallet-core's coin registry at
/// all; see ChainSigner.address(for:)). This reimplements just the encode half of BIP-173 by
/// hand so Litecoin testnet can still get a real native-segwit address in the same style as
/// its own mainnet "ltc1..." address, instead of falling back to a legacy P2PKH format.
///
/// Mirrors android/.../Bech32.kt exactly — see that file's Bech32Test for the algorithm's
/// verification against a real, independently-decoded mainnet address.
enum Bech32 {
  private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

  private static func polymod(_ values: [Int]) -> Int {
    let gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    var chk = 1
    for v in values {
      let b = chk >> 25
      chk = ((chk & 0x1ffffff) << 5) ^ v
      for i in 0..<5 {
        if (b >> i) & 1 == 1 { chk ^= gen[i] }
      }
    }
    return chk
  }

  private static func hrpExpand(_ hrp: String) -> [Int] {
    let bytes = Array(hrp.utf8).map { Int($0) }
    return bytes.map { $0 >> 5 } + [0] + bytes.map { $0 & 31 }
  }

  private static func createChecksum(hrp: String, data: [Int]) -> [Int] {
    let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
    let mod = polymod(values) ^ 1
    return (0..<6).map { (mod >> (5 * (5 - $0))) & 31 }
  }

  /// 8-bit bytes -> 5-bit groups (BIP-173 "convertbits", 8→5, with padding).
  private static func convertBits8to5(_ data: Data) -> [Int] {
    var acc = 0
    var bits = 0
    var out: [Int] = []
    for b in data {
      acc = (acc << 8) | Int(b)
      bits += 8
      while bits >= 5 {
        bits -= 5
        out.append((acc >> bits) & 0x1f)
      }
    }
    if bits > 0 { out.append((acc << (5 - bits)) & 0x1f) }
    return out
  }

  /// Encodes a witness-version-0 program (20 bytes for P2WPKH, 32 for P2WSH) as a lowercase
  /// bech32 segwit address under `hrp`.
  static func encodeSegwitV0(hrp: String, program: Data) -> String {
    let data = [0] + convertBits8to5(program)
    let combined = data + createChecksum(hrp: hrp, data: data)
    var result = hrp + "1"
    for d in combined { result.append(charset[d]) }
    return result
  }
}
