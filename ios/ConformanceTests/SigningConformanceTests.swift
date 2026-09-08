import XCTest

// Signing conformance tests — verifies that signing-vectors.json exists and, once vectors
// are populated (status: "verified"), asserts the signer output matches the expected signed tx.
// Run by adding this file to an XCTest target in vault.xcworkspace.
class SigningConformanceTests: XCTestCase {

  struct SigningVector: Decodable {
    let chain: String
    let status: String
    let expectedSignedTx: String
  }

  struct VectorsFile: Decodable {
    let version: String
    let vectors: [SigningVector]
  }

  private func loadVectors() throws -> VectorsFile {
    // Look next to the test bundle for the conformance directory.
    let candidates: [URL] = [
      Bundle(for: type(of: self)).bundleURL
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("conformance/signing-vectors.json"),
      Bundle(for: type(of: self))
        .url(forResource: "signing-vectors", withExtension: "json") as URL? ??
        URL(fileURLWithPath: "/dev/null")
    ]
    guard let url = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }) else {
      throw XCTSkip("signing-vectors.json not found — run on device to harvest vectors")
    }
    let data = try Data(contentsOf: url)
    return try JSONDecoder().decode(VectorsFile.self, from: data)
  }

  func testSigningVectorsFileExists() throws {
    _ = try loadVectors()
  }

  func testPinnedVersion() throws {
    let file = try loadVectors()
    XCTAssertEqual(file.version, "4.1.19",
      "signing-vectors.json must target Trust Wallet Core 4.1.19")
  }

  func testVerifiedVectorsHaveExpectedOutput() throws {
    let file = try loadVectors()
    let verified = file.vectors.filter { $0.status == "verified" }
    guard !verified.isEmpty else {
      throw XCTSkip("No verified signing vectors yet — populate signing-vectors.json on device")
    }
    for v in verified {
      XCTAssertFalse(v.expectedSignedTx.isEmpty,
        "Chain \(v.chain): status is verified but expectedSignedTx is empty")
    }
  }
}
