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
// For pending chains: run the test, read the printed addresses in logcat, verify them
// independently (e.g. against a TWC 4.1.19 REPL or the iOS companion test), then set the
// expected value and change the status comment to "verified".
//
// Human-readable source of truth: conformance/address-derivation-vectors.json.
@RunWith(AndroidJUnit4::class)
class AddressDerivationConformanceTest {

  companion object {
    init { System.loadLibrary("TrustWalletCore") }

    const val MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    // Chains with expected addresses confirmed against WalletCore 4.1.19.
    // ETH / BNB / POL all share CoinType.ETHEREUM (same secp256k1 key, BIP44 m/44'/60'/0'/0/0).
    val VERIFIED = mapOf(
      CoinType.ETHEREUM  to "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F", // ethereum
      CoinType.SMARTCHAIN to "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F", // bnb
    )

    // Chains still needing on-device verification against 4.1.19. Add to VERIFIED once confirmed.
    val PENDING = listOf(
      CoinType.BITCOIN,
      CoinType.LITECOIN,
      CoinType.XRP,
      CoinType.TRON,
      CoinType.TON,
      CoinType.SOLANA,
      CoinType.BITCOINCASH,
    )
  }

  @Test
  fun verifiedAddressesMatch() {
    val wallet = HDWallet(MNEMONIC, "")
    for ((coin, expected) in VERIFIED) {
      val actual = wallet.getAddressForCoin(coin)
      assertEquals("address mismatch for coin=${coin.name()}", expected, actual)
    }
  }

  @Test
  fun printPendingAddressesForVerification() {
    val wallet = HDWallet(MNEMONIC, "")
    val lines = PENDING.map { coin -> "  ${coin.name()} -> ${wallet.getAddressForCoin(coin)}" }
    println(
      "\n[AddressDerivationConformanceTest] Pending — verify and move to VERIFIED map:\n" +
        lines.joinToString("\n")
    )
    // This test intentionally never fails — it exists only to harvest pending addresses.
  }
}
