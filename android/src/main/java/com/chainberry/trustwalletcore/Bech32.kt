package com.chainberry.trustwalletcore

/**
 * Minimal BIP-173 (bech32) encoder/decoder.
 *
 * `encodeSegwitV0` handles witness-version-0 segwit addresses: wallet-core's own
 * `SegwitAddress` class only accepts an HRP from its closed native `HRP` enum — there's no
 * "tltc" entry (Litecoin testnet isn't in wallet-core's coin registry at all; see
 * ChainSigner.addressForChain). This reimplements just the encode half of BIP-173 by hand so
 * Litecoin testnet can still get a real native-segwit address in the same style as its own
 * mainnet "ltc1..." address, instead of falling back to a legacy P2PKH format.
 *
 * `decode`/`encode` handle plain (non-witness-version) bech32, used by Cardano/CIP-19
 * addresses — see ChainSigner.addressForChain's CARDANO case, mirrored exactly from iOS's
 * Bech32.swift (verified there byte-for-byte against real mainnet and Preprod addresses).
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

  /** 5-bit groups -> 8-bit bytes (BIP-173 "convertbits", 5→8, no padding — trailing bits must
   * be zero, matching how `convertBits8to5` always pads with zero bits). */
  private fun convertBits5to8(data: IntArray): ByteArray? {
    var acc = 0
    var bits = 0
    val out = mutableListOf<Byte>()
    for (v in data) {
      acc = (acc shl 5) or v
      bits += 5
      if (bits >= 8) {
        bits -= 8
        out.add(((acc ushr bits) and 0xff).toByte())
      }
    }
    if (bits >= 5 || (acc and ((1 shl bits) - 1)) != 0) return null
    return out.toByteArray()
  }

  /** Plain BIP-173 bech32 decode — no witness-version handling (unlike `encodeSegwitV0`,
   * Cardano/CIP-19 addresses have no witness-version prefix; the payload is the raw header
   * byte + credential hash(es)). Returns `null` on a malformed string or bad checksum. */
  fun decode(input: String): Pair<String, ByteArray>? {
    val lower = input.lowercase()
    if (lower != input && input.uppercase() != input) return null // no mixed case
    val sepIndex = lower.lastIndexOf('1')
    if (sepIndex <= 0) return null
    val hrp = lower.substring(0, sepIndex)
    val dataPart = lower.substring(sepIndex + 1)
    if (dataPart.length < 6) return null // 6-char checksum minimum
    val values = IntArray(dataPart.length)
    for (i in dataPart.indices) {
      val idx = CHARSET.indexOf(dataPart[i])
      if (idx < 0) return null
      values[i] = idx
    }
    val payload = values.copyOfRange(0, values.size - 6)
    val checksum = values.copyOfRange(values.size - 6, values.size)
    if (!createChecksum(hrp, payload).contentEquals(checksum)) return null
    val bytes = convertBits5to8(payload) ?: return null
    return hrp to bytes
  }

  /** Plain BIP-173 bech32 encode of raw bytes under `hrp` — the general form
   * `encodeSegwitV0` specializes (see above) for BTC/LTC's witness-version-0 addresses. */
  fun encode(hrp: String, data: ByteArray): String {
    val data5 = convertBits8to5(data)
    val combined = data5 + createChecksum(hrp, data5)
    val sb = StringBuilder(hrp).append('1')
    for (d in combined) sb.append(CHARSET[d])
    return sb.toString()
  }
}
