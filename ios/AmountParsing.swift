import Foundation

// Pure numeric-string parsing for the fields that used to silently substitute 0 on
// malformed input (`Int64(s) ?? 0` / `UInt64(s) ?? 0`) instead of failing closed — see
// ChainSigning.swift's signXrp/signTon. Deliberately has no WalletCore/ExpoModulesCore
// dependency so it can be unit-tested standalone via the ConformanceTests SwiftPM package,
// against the same fixture Android's AmountParsing.kt conformance test reads
// (../conformance/amount-parsing-cases.json).

enum AmountParsingError: Error, CustomStringConvertible {
  case invalidXrpAmount(String)
  case invalidXrpFee(String)
  case invalidXrpDestinationTag
  case invalidTonAmount(String)

  var description: String {
    switch self {
    case .invalidXrpAmount(let s): return "Invalid XRP Amount: \(s)"
    case .invalidXrpFee(let s): return "Invalid XRP Fee: \(s)"
    case .invalidXrpDestinationTag: return "Invalid XRP DestinationTag: must be an integer 0...4294967295"
    case .invalidTonAmount(let s): return "Invalid TON amount: \(s)"
    }
  }
}

/// XRP `Amount` (drops) must parse as a strictly positive Int64. A non-numeric, decimal,
/// empty, or negative string must throw rather than silently sign a zero-value transfer.
func parseXrpAmountDrops(_ s: String) throws -> Int64 {
  guard let value = Int64(s), value > 0 else {
    throw AmountParsingError.invalidXrpAmount(s)
  }
  return value
}

/// XRP `Fee` (drops) must parse as a non-negative Int64 (0 is a legitimate fee for some
/// transaction types — only genuinely malformed input, not zero, should throw).
func parseXrpFeeDrops(_ s: String) throws -> Int64 {
  guard let value = Int64(s), value >= 0 else {
    throw AmountParsingError.invalidXrpFee(s)
  }
  return value
}

/// XRP DestinationTag is an optional UInt32. `nil` passes through unchanged; a present
/// value must be validated as non-negative and in-range *before* widening — Swift's
/// `UInt64(someNegativeInt)` traps at runtime rather than throwing, so that conversion must
/// never run on unvalidated input.
func parseXrpDestinationTag(_ tag: Int?) throws -> UInt64? {
  guard let tag else { return nil }
  guard tag >= 0, tag <= 0xFFFF_FFFF else {
    throw AmountParsingError.invalidXrpDestinationTag
  }
  return UInt64(tag)
}

/// TON `amount` (nanotons) must parse as a strictly positive UInt64.
func parseTonNanotons(_ s: String) throws -> UInt64 {
  guard let value = UInt64(s), value > 0 else {
    throw AmountParsingError.invalidTonAmount(s)
  }
  return value
}
