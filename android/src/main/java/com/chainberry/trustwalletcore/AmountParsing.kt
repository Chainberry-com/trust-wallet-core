package com.chainberry.trustwalletcore

// Pure numeric-string parsing for the XRP/TON fields that need to fail closed on malformed
// input, mirroring ios/AmountParsing.swift 1:1 (same function names/behavior) so both
// platforms can be checked against the same shared fixture
// (../../../../../../conformance/amount-parsing-cases.json — see
// AmountParsingConformanceTest.kt). Android's `String.toLong()`/`toULongOrNull()` already
// throw/null-out on non-numeric input (unlike iOS's old `Int64(s) ?? 0` pattern), but neither
// platform previously rejected negative amounts, zero amounts, or an out-of-range
// DestinationTag — this closes those gaps.

private const val XRP_DESTINATION_TAG_MAX = 4_294_967_295L // XRP DestinationTag is a UInt32

/** XRP `Amount` (drops) must parse as a strictly positive Long. A non-numeric, decimal,
 * empty, or negative/zero string throws rather than silently signing a zero-value transfer. */
fun parseXrpAmountDrops(s: String): Long {
  val value = s.toLongOrNull() ?: throw ChainSigningException("Invalid XRP Amount: $s")
  if (value <= 0) throw ChainSigningException("Invalid XRP Amount: $s")
  return value
}

/** XRP `Fee` (drops) must parse as a non-negative Long (0 is a legitimate fee for some
 * transaction types — only genuinely malformed/negative input should throw). */
fun parseXrpFeeDrops(s: String): Long {
  val value = s.toLongOrNull() ?: throw ChainSigningException("Invalid XRP Fee: $s")
  if (value < 0) throw ChainSigningException("Invalid XRP Fee: $s")
  return value
}

/** XRP DestinationTag is optional; `null` passes through. A present value must be
 * non-negative and fit in 32 bits. */
fun parseXrpDestinationTag(tag: Long?): Long? {
  if (tag == null) return null
  if (tag < 0 || tag > XRP_DESTINATION_TAG_MAX) {
    throw ChainSigningException("Invalid XRP DestinationTag: must be an integer 0..4294967295")
  }
  return tag
}

/** TON `amount` (nanotons) must parse as a strictly positive value. */
fun parseTonNanotons(s: String): Long {
  val value = s.toULongOrNull() ?: throw ChainSigningException("Invalid TON amount: $s")
  if (value == 0uL) throw ChainSigningException("Invalid TON amount: $s")
  return value.toLong()
}
