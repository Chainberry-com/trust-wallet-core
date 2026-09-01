package com.chainberry.trustwalletcore

import org.json.JSONArray
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

// Reads ../../../../../../conformance/amount-parsing-cases.json — the single fixture also
// consumed by iOS's ConformanceTests/Tests/AmountParsingConformanceTests/ — and asserts
// AmountParsing.kt agrees with AmountParsing.swift on throw-vs-valid for every case. Keeps
// the two platforms' numeric parsing behavior from drifting apart. Plain JVM unit test (no
// Robolectric/instrumentation needed — AmountParsing.kt has no Android framework dependency),
// runs via `./gradlew testDebugUnitTest` (or the autolinked module's equivalent task).
class AmountParsingConformanceTest {

  // Gradle's `Test` task runs with the working directory set to the Gradle project directory
  // (android/) by default — conformance/ is one level up, at the trust-wallet-core module root.
  private fun fixtureFile(): File {
    val projectDir = File(System.getProperty("user.dir") ?: ".")
    return File(projectDir, "../conformance/amount-parsing-cases.json").canonicalFile
  }

  @Test
  fun conformanceCasesMatch() {
    val fixture = fixtureFile()
    assertTrue("expected conformance fixture at ${fixture.path}", fixture.exists())
    val cases = JSONArray(fixture.readText())
    assertTrue("conformance fixture should not be empty", cases.length() > 0)

    for (i in 0 until cases.length()) {
      val testCase = cases.getJSONObject(i)
      val id = testCase.getString("id")
      val fn = testCase.getString("fn")
      val expect = testCase.getString("expect")

      var threw = false
      try {
        when (fn) {
          "xrpAmountDrops" -> parseXrpAmountDrops(testCase.getString("input"))
          "xrpFeeDrops" -> parseXrpFeeDrops(testCase.getString("input"))
          "xrpDestinationTag" -> parseXrpDestinationTag(testCase.getLong("input"))
          "tonNanotons" -> parseTonNanotons(testCase.getString("input"))
          else -> fail("Unknown conformance case fn: $fn")
        }
      } catch (e: ChainSigningException) {
        threw = true
      }

      val expectedThrow = expect == "throws"
      assertTrue(
        "case $id: expected $expect but got ${if (threw) "throws" else "valid"}",
        threw == expectedThrow
      )
    }
  }
}
