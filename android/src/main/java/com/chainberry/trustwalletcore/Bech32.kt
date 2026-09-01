package com.chainberry.trustwalletcore

/**
 * Minimal BIP-173 (bech32) segwit-address encoder, witness-version-0 only.
 *
 * wallet-core's own `SegwitAddress` class only accepts an HRP from its closed native `HRP`
 * enum — there's no "tltc" entry (Litecoin testnet isn't in wallet-core's coin registry at
 * all; see ChainSigner.addressForChain). This reimplements just the encode half of BIP-173 by
 * hand so Litecoin testnet can still get a real native-segwit address in the same style as its
 * own mainnet "ltc1..." address, instead of falling back to a legacy P2PKH format.
 *
 * Verified against the official BIP-173 test vectors — see Bech32Test.
 */
internal object Bech32 {
  private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

  private fun polymod(values: IntArray): Int {
    val gen = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    var chk = 1
    for (v in values) {
      val b = chk ushr 25
      chk = (chk and 0x1ffffff) shl 5 xor v
      for (i in 0 until 5) {
        if ((b ushr i) and 1 == 1) chk = chk xor gen[i]
      }
    }
    return chk
  }

  private fun hrpExpand(hrp: String): IntArray {
    val hi = hrp.map { it.code ushr 5 }
    val lo = hrp.map { it.code and 31 }
    return (hi + listOf(0) + lo).toIntArray()
  }

  private fun createChecksum(hrp: String, data: IntArray): IntArray {
    val values = hrpExpand(hrp) + data + IntArray(6)
    val mod = polymod(values) xor 1
    return IntArray(6) { (mod ushr (5 * (5 - it))) and 31 }
  }

  /** 8-bit bytes -> 5-bit groups (BIP-173 "convertbits", 8→5, with padding). */
  private fun convertBits8to5(data: ByteArray): IntArray {
    var acc = 0
    var bits = 0
    val out = mutableListOf<Int>()
    for (b in data) {
      acc = (acc shl 8) or (b.toInt() and 0xff)
      bits += 8
      while (bits >= 5) {
        bits -= 5
        out.add((acc ushr bits) and 0x1f)
      }
    }
    if (bits > 0) out.add((acc shl (5 - bits)) and 0x1f)
    return out.toIntArray()
  }

  /** Encodes a witness-version-0 program (20 bytes for P2WPKH, 32 for P2WSH) as a lowercase
   * bech32 segwit address under `hrp`. */
  fun encodeSegwitV0(hrp: String, program: ByteArray): String {
    val data = intArrayOf(0) + convertBits8to5(program)
    val combined = data + createChecksum(hrp, data)
    val sb = StringBuilder(hrp).append('1')
    for (d in combined) sb.append(CHARSET[d])
    return sb.toString()
  }
}
