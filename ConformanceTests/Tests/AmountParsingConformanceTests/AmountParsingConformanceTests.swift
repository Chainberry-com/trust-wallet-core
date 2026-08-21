import XCTest
@testable import AmountParsing

// Reads ../../../conformance/amount-parsing-cases.json — the single fixture also consumed by
// Android's AmountParsingConformanceTest.kt — and asserts each platform's parser agrees on
// throw-vs-valid for every case. Keeps Swift/Kotlin numeric parsing behavior from drifting.
private enum FixtureValue: Decodable {
  case string(String)
  case number(Double)

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if let s = try? container.decode(String.self) {
      self = .string(s)
    } else {
      self = .number(try container.decode(Double.self))
    }
  }

  var stringValue: String {
    guard case .string(let s) = self else {
      fatalError("expected a string fixture value, got \(self)")
    }
    return s
  }

  var intValue: Int {
    guard case .number(let n) = self else {
      fatalError("expected a numeric fixture value, got \(self)")
    }
    return Int(n)
  }
}

private struct ConformanceCase: Decodable {
  let id: String
  let fn: String
  let input: FixtureValue
  let expect: String
}

final class AmountParsingConformanceTests: XCTestCase {
  func testConformanceCases() throws {
    let thisFile = URL(fileURLWithPath: #filePath)
    let fixtureURL = thisFile
      .deletingLastPathComponent() // .../Tests/AmountParsingConformanceTests/
      .deletingLastPathComponent() // .../Tests/
      .deletingLastPathComponent() // .../ConformanceTests/
      .deletingLastPathComponent() // .../trust-wallet-core/
      .appendingPathComponent("conformance/amount-parsing-cases.json")
      .standardizedFileURL
    let data = try Data(contentsOf: fixtureURL)
    let cases = try JSONDecoder().decode([ConformanceCase].self, from: data)
    XCTAssertFalse(cases.isEmpty, "conformance fixture at \(fixtureURL.path) should not be empty")

    for testCase in cases {
      var threw = false
      do {
        switch testCase.fn {
        case "xrpAmountDrops":
          _ = try parseXrpAmountDrops(testCase.input.stringValue)
        case "xrpFeeDrops":
          _ = try parseXrpFeeDrops(testCase.input.stringValue)
        case "xrpDestinationTag":
          _ = try parseXrpDestinationTag(testCase.input.intValue)
        case "tonNanotons":
          _ = try parseTonNanotons(testCase.input.stringValue)
        default:
          XCTFail("Unknown conformance case fn: \(testCase.fn)")
          continue
        }
      } catch {
        threw = true
      }
      let expectedThrow = testCase.expect == "throws"
      XCTAssertEqual(
        threw, expectedThrow,
        "case \(testCase.id): expected \(testCase.expect) but got \(threw ? "throws" : "valid")"
      )
    }
  }
}
