package expo.modules.trustwalletcore

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import wallet.core.jni.BitcoinScript
import wallet.core.jni.CoinType
import wallet.core.jni.HDWallet

// Instrumented test — must run on a device or emulator (needs the TrustWalletCore JNI library).
// Run via: ./gradlew connectedDebugAndroidTest
//
// Verifies that ChainSigner.sign() — the exact same call path TrustWalletCoreModule.kt uses in
// production — produces the expected byte-for-byte signed output for a fixed, representative
// unsignedTx per chain, under WalletCore 4.1.19 (the pinned version). Inputs are deterministic
// but NOT necessarily broadcast-valid (fake txids/blockhash/etc.) — this is a regression fixture,
// not a live-network test.
//
// BCH is intentionally absent — ChainSigner.sign() throws for BITCOINCASH (sending unsupported
// on both platforms; see ChainSigning.kt). Every other advertised chain has exactly one vector,
// except EVM: `ethereum` covers the legacy gasPriceHex path and `polygon` covers the separate
// EIP-1559 maxFeePerGasHex/maxPriorityFeePerGasHex branch in signEvm — bnb needs no case of its
// own beyond that (same code path/CoinType as ethereum).
//
// Human-readable source of truth: conformance/signing-vectors.json.
@RunWith(AndroidJUnit4::class)
class SigningConformanceTest {

  companion object {
    init { System.loadLibrary("TrustWalletCore") }

    const val MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    // Wallet's own on-device-derived addresses (see AddressDerivationConformanceTest.VERIFIED) —
    // used as toAddress/changeAddress/Account/feePayer below so every UTXO/XRP/Solana vector is a
    // (fake, never-broadcast) *self-send*, keeping this fixture self-contained with no external
    // address dependency.
    const val ETH_ADDR = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    const val BTC_ADDR = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    const val LTC_ADDR = "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"
    const val XRP_ADDR = "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"
    const val TON_ADDR = "UQAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-RKY"

    // Fixed, deterministic (not necessarily real/broadcastable) inputs per chain.
    fun vectors(): Map<String, Pair<ChainKey, Map<String, Any>>> {
      // Same 32-byte all-zero value reused below purely as a deterministic placeholder txid/hash
      // — never broadcast, so it doesn't need to reference a real UTXO/blockhash.
      val fakeTxId = "00".repeat(32)

      return linkedMapOf(
        "ethereum" to (ChainKey.ETHEREUM to mapOf(
          "to" to ETH_ADDR,
          "chainId" to 1,
          "nonce" to 0,
          "gasLimitHex" to "5208", // 21000
          "valueHex" to "de0b6b3a7640000", // 1 ETH
          "gasPriceHex" to "4a817c800", // 20 gwei — legacy path
        )),
        "polygon" to (ChainKey.POLYGON to mapOf(
          "to" to ETH_ADDR,
          "chainId" to 137,
          "nonce" to 0,
          "gasLimitHex" to "5208",
          "valueHex" to "de0b6b3a7640000",
          "maxFeePerGasHex" to "9502f9000", // EIP-1559 path
          "maxPriorityFeePerGasHex" to "3b9aca00",
        )),
        "bitcoin" to (ChainKey.BITCOIN to utxoTx(CoinType.BITCOIN, BTC_ADDR, fakeTxId)),
        "litecoin" to (ChainKey.LITECOIN to utxoTx(CoinType.LITECOIN, LTC_ADDR, fakeTxId)),
        "xrp" to (ChainKey.XRP to mapOf(
          "Account" to XRP_ADDR,
          "Destination" to XRP_ADDR,
          "Amount" to "1000000", // 1 XRP, drops
          "Fee" to "12",
          "Sequence" to 1,
          "LastLedgerSequence" to 100,
        )),
        "ton" to (ChainKey.TON to mapOf(
          "toAddress" to TON_ADDR,
          "amount" to "1000000000", // 1 TON, nanotons
          "seqno" to 1,
          "memoId" to "conformance-test",
        )),
        "tron" to (ChainKey.TRON to mapOf(
          // A genuinely all-zero digest degenerates silently in wallet-core's direct-sign path
          // (empty signature, no error) — use a non-trivial fixed fake digest instead.
          "txID" to "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )),
        "solana" to (ChainKey.SOLANA to mapOf(
          // Fixed unsigned tx built via @solana/web3.js: feePayer/from = this wallet's own
          // Solana address, to = the System Program id (32 zero bytes, a fixed valid pubkey),
          // recentBlockhash = the same all-zero value (never broadcast, only needs to be
          // shape-valid base58 for TransactionDecoder). See conformance/signing-vectors.json's
          // solana entry for the exact base64 blob and how it was generated.
          "unsignedTxBase64" to "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAC6bYGKEG7l3rSHeceyWGQBjPCbyE4TgFbAUpjemFJlUcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQECAAEMAgAAAEBCDwAAAAAA",
        )),
      )
    }

    // scriptPubKeyHex is computed here (BitcoinScript.lockScriptForAddress), not hand-derived from
    // bech32, so the UTXO vector always matches this wallet's own real P2WPKH lock script.
    private fun utxoTx(coin: CoinType, ownAddress: String, fakeTxId: String): Map<String, Any> {
      val scriptHex = BitcoinScript.lockScriptForAddress(ownAddress, coin).data()
        .joinToString("") { "%02x".format(it) }
      return mapOf(
        "toAddress" to ownAddress,
        "changeAddress" to ownAddress,
        "sendAmountSats" to "50000",
        "changeAmountSats" to "40000",
        "satsPerByte" to 10,
        "inputs" to listOf(
          mapOf(
            "txIdHex" to fakeTxId,
            "vout" to 0,
            "amountSats" to "100000",
            "scriptPubKeyHex" to scriptHex,
          )
        ),
      )
    }

    // Expected signed outputs, confirmed on-device against WalletCore 4.1.19 (harvested via
    // printSigningVectorsForVerification, see conformance/signing-vectors.json for the full
    // methodology). "ton" is deliberately absent — signTon() embeds a wall-clock
    // `expireAt = now + 600s` into the signed payload, so its output is never byte-reproducible
    // across runs; see tonVectorIsWellFormed() below for what's actually checked instead.
    val EXPECTED: Map<String, String> = mapOf(
      "ethereum" to "0xf86c808504a817c800825208949858effd232b4033e47d90003d41ec34ecaeda94880de0b6b3a76400008026a0b7cca5f69561cd482cec4e692bd2da17d9eb1d6b3a83fe3f7f11d117de99ca97a00ad0dc153460e39b355c226a2744fc2926f84b95b89c954551571f1bbc251478",
      "polygon" to "0x02f874818980843b9aca008509502f9000825208949858effd232b4033e47d90003d41ec34ecaeda94880de0b6b3a764000080c001a038b5c72ee38aa18607462b80ab0cb170a8d4df1c4090ac49acd41d6b4b0f9acca05bdee390ee8a50ff569f55d408371213df72a3065902b07317289b39788cb434",
      "bitcoin" to "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000250c3000000000000160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2cebd000000000000160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e20247304402201e8f3663c97712bbf662c96df532e701ca9b660b507ab170d7b4ffbd966d4be0022033bd537c7720b1e7be2b7663d1a0adcbe565ff18a25794aec828015529ab80e101210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c00000000",
      "litecoin" to "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000250c300000000000016001496cd3178f3de0f307bcee1aeaa4d5987862dd30acebd00000000000016001496cd3178f3de0f307bcee1aeaa4d5987862dd30a0248304502210093a73dec624132e9ea3d1a629c0c08be77be68416b0f99cbeb23381967ce8c560220385912e0b0835bcd1dd844bae68e4df208af8b07b095d5ac5ce6cd4407a27a85012102e49c9b9b5d0f127235dc26a0c252814c52fb333d651a946773f59d72c2da990400000000",
      "xrp" to "12000022000000002400000001201b000000646140000000000f424068400000000000000c7321031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae7446304402207fb80c118799a9b3d4dad6e91ad1b8f0c5c9d189a0bcdaf50e823ea44f8044e70220422f638bf4b4e634cb39a4250cf72513d5e3c7e810a13c2f35b5df54b02dc7c98114aff3c2e33458b30714ca16ffee19952dd35c17c88314aff3c2e33458b30714ca16ffee19952dd35c17c8",
      "tron" to "{\"txID\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"signature\":[\"4b63d125c56637e9f09d9578bf9fbf30e0e6796085bb0fe8aa7c466b2ae9bc690a26d26fe36ff0d42d416ce76b70b486c50c0294b50d5a6e9871d2f3a7ebd28901\"]}",
      "solana" to "Aa+eJgDHJo2f9vGrz1EpPPnfGWcZoySFIEw0sS7OVvYiF4U421YCQqLme/uESu3SLan0AM6xblAfUgYlM28StQcBAAAC6bYGKEG7l3rSHeceyWGQBjPCbyE4TgFbAUpjemFJlUcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQECAAEMAgAAAEBCDwAAAAAA",
    )
  }

  @Test
  fun printSigningVectorsForVerification() {
    val wallet = HDWallet(MNEMONIC, "")
    val lines = vectors().map { (chain, pair) ->
      val (chainKey, unsignedTx) = pair
      val result = try {
        ChainSigner.sign(chainKey, wallet, unsignedTx, isTestnet = false)
      } catch (e: Exception) {
        return@map "  $chain -> ERROR: ${e.message}"
      }
      val metaStr = result.meta?.let { " meta=$it" } ?: ""
      "  $chain -> ${result.signedTx}$metaStr"
    }
    println(
      "\n[SigningConformanceTest] Harvested signed outputs — verify and populate EXPECTED:\n" +
        lines.joinToString("\n")
    )
    // This test intentionally never fails — it exists only to harvest signing vectors.
  }

  @Test
  fun signedOutputsMatch() {
    val wallet = HDWallet(MNEMONIC, "")
    for ((chain, pair) in vectors()) {
      val expected = EXPECTED[chain] ?: continue
      val (chainKey, unsignedTx) = pair
      val actual = ChainSigner.sign(chainKey, wallet, unsignedTx, isTestnet = false).signedTx
      assertEquals("signed output mismatch for chain=$chain", expected, actual)
    }
  }

  // TON's signTon() embeds a wall-clock `expireAt = now + 600s` into the signed BOC, so its
  // output (and meta.txHash, which hashes that BOC) is never byte-reproducible across runs —
  // a real constraint of the production code, not a test gap. This checks the parts that ARE
  // deterministic instead: signing succeeds, the output is a well-formed base64 BOC, and
  // meta.txHash is present and the right shape.
  @Test
  fun tonVectorIsWellFormed() {
    val wallet = HDWallet(MNEMONIC, "")
    val (chainKey, unsignedTx) = vectors().getValue("ton")
    val result = ChainSigner.sign(chainKey, wallet, unsignedTx, isTestnet = false)
    assert(result.signedTx.startsWith("te6cc")) {
      "TON signed output doesn't look like a BOC (expected te6cc... prefix): ${result.signedTx}"
    }
    val txHash = result.meta?.get("txHash") as? String
    assertEquals("TON meta.txHash should be a 32-byte hex string", 64, txHash?.length)
  }
}
