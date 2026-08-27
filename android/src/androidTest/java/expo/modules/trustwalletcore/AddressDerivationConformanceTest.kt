package expo.modules.trustwalletcore

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import wallet.core.jni.CoinType
import wallet.core.jni.HDWallet

// Instrumented test — must run on a device or emulator (needs the TrustWalletCore JNI library).
// Run via: ./gradlew connectedDebugAndroidTest
//
// Verifies that HDWallet.getAddressForCoin produces the expected address for every chain
// under WalletCore 4.1.19 (the pinned version). The test mnemonic is the BIP39 standard
// test vector — never use it with real funds.
//
// All 10 chains were verified on-device (real emulator, WalletCore 4.1.19 JNI) on 2026-08-27,
// cross-checked against an independent derivation via the WASM build (@trustwallet/wallet-core
// 3.3.3, run in plain Node — see conformance/address-derivation-vectors.json's _note). On-device
// 4.1.19 is authoritative wherever the two disagree.
//
// IMPORTANT — this test did not actually run before this pass. Two pre-existing bugs prevented
// it from ever executing: (1) `coin.name()` doesn't compile against this Kotlin CoinType binding
// (name is a property, not a method — fixed here), and (2) no `testInstrumentationRunner` was
// configured in build.gradle, so AGP defaulted to the legacy runner, which cannot discover
// @RunWith(AndroidJUnit4::class) tests at all ("0 tests"/"No tests found", not a real pass).
// Once actually run, it immediately caught a real bug: the ETHEREUM/SMARTCHAIN "verified" address
// below was wrong (0x9d8A62f6...) — never actually checked against real WalletCore output despite
// being marked "verified". The corrected value below is the real on-device 4.1.19 result.
//
// For any NEW chain added to ChainKey in the future: add its CoinType to PENDING, run this test,
// read the printed address in logcat, verify it independently (e.g. against a TWC 4.1.19 REPL or
// the iOS companion test — see ConformanceTests/), then move it into VERIFIED.
//
// Human-readable source of truth: conformance/address-derivation-vectors.json.
@RunWith(AndroidJUnit4::class)
class AddressDerivationConformanceTest {

  companion object {
    init { System.loadLibrary("TrustWalletCore") }

    const val MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    // Chains with expected addresses confirmed against WalletCore 4.1.19, on a real device/emulator.
    // ETH / BNB / POL all share CoinType.ETHEREUM (same secp256k1 key, BIP44 m/44'/60'/0'/0/0).
    val VERIFIED = mapOf(
      CoinType.ETHEREUM to "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", // ethereum / bnb / polygon
      CoinType.SMARTCHAIN to "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", // bnb (same key as ethereum)
      CoinType.BITCOIN to "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
      CoinType.LITECOIN to "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh",
      CoinType.XRP to "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
      CoinType.TRON to "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
      // Non-bounceable (UQ...) — WalletCore 4.1.19's default for this CoinType. The WASM build
      // (@trustwallet/wallet-core 3.3.3) derives the same underlying hash but defaults to the
      // bounceable (EQ...) encoding instead — a version/binding difference in address-flag
      // defaults, not a key-derivation discrepancy. On-device 4.1.19 (what the app actually ships)
      // is authoritative here.
      CoinType.TON to "UQAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-RKY",
      CoinType.SOLANA to "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL",
      CoinType.BITCOINCASH to "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
    )

    // Steady state is empty — add a chain's CoinType here (and drop it from VERIFIED) only while
    // actively harvesting a newly-added chain's address for the first time.
    val PENDING = emptyList<CoinType>()
  }

  @Test
  fun verifiedAddressesMatch() {
    val wallet = HDWallet(MNEMONIC, "")
    for ((coin, expected) in VERIFIED) {
      val actual = wallet.getAddressForCoin(coin)
      assertEquals("address mismatch for coin=${coin.name}", expected, actual)
    }
  }

  @Test
  fun printPendingAddressesForVerification() {
    val wallet = HDWallet(MNEMONIC, "")
    val lines = PENDING.map { coin -> "  ${coin.name} -> ${wallet.getAddressForCoin(coin)}" }
    println(
      "\n[AddressDerivationConformanceTest] Pending — verify and move to VERIFIED map:\n" +
        lines.joinToString("\n")
    )
    // This test intentionally never fails — it exists only to harvest pending addresses.
  }
}
