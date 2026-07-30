import { requireNativeModule } from "expo-modules-core";

/**
 * Mnemonic/private-key material never crosses this boundary except `exportMnemonic` —
 * an explicit, biometric/passcode-gated backup flow. Every other function returns only
 * walletIds, addresses, or signed transaction bytes/hex; wallet storage and all signing
 * happen entirely inside the native module (see ios/TrustWalletCoreModule.swift,
 * android/.../TrustWalletCoreModule.kt).
 */
export type Chain =
  | "ethereum"
  | "bnb"
  | "polygon" // shares Ethereum's secp256k1 key/address — same BIP44 path, no distinct derivation
  | "solana"
  | "tron"
  | "ton"
  | "bitcoin"
  | "bitcoincash" // address derivation only — sending is unsupported, see ChainSigner
  | "litecoin"
  | "xrp";

export type WalletSummary = {
  walletId: string;
  addresses: Record<Chain, string>;
};

export type SignResult = {
  signedTx: string;
  meta?: Record<string, unknown>;
};

const TrustWalletCore = requireNativeModule("TrustWalletCore");

/** Generates a new mnemonic and persists it natively (biometry/passcode-gated).
 * strength 128 = 12 words, 256 = 24 words. */
export async function createWallet(strength: 128 | 256 = 128, passphrase = ""): Promise<WalletSummary> {
  return TrustWalletCore.createWallet(strength, passphrase);
}

/** One-time mnemonic exposure from the caller — persisted natively immediately, never
 * retained in JS after this call returns. */
export async function importWallet(mnemonic: string, passphrase = ""): Promise<WalletSummary> {
  return TrustWalletCore.importWallet(mnemonic, passphrase);
}

/** Reads only public metadata (walletId + addresses) — no biometric prompt. */
export async function listWallets(): Promise<WalletSummary[]> {
  return TrustWalletCore.listWallets();
}

export async function deleteWallet(walletId: string): Promise<void> {
  return TrustWalletCore.deleteWallet(walletId);
}

/** Triggers the native biometry/passcode prompt, then signs entirely in-process —
 * only signed transaction bytes/hex cross back. */
export async function signTransaction(
  walletId: string,
  chain: Chain,
  unsignedTx: Record<string, unknown>,
): Promise<SignResult> {
  return TrustWalletCore.signTransaction(walletId, chain, unsignedTx);
}

/** The one sanctioned mnemonic exposure — explicit backup/reveal flow only, gated behind
 * a native biometry/passcode prompt. Callers must not hold onto the result beyond the
 * immediate display/dismiss of the backup screen. */
export async function exportMnemonic(walletId: string): Promise<string> {
  return TrustWalletCore.exportMnemonic(walletId);
}
