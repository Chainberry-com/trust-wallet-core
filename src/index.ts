import {
  signEthereumTransaction as signEth,
  signSolanaTransaction as signSol,
} from "@chainberry/chainberry-wallet";
import { requireNativeModule } from "expo-modules-core";

const TrustWalletCore = requireNativeModule("TrustWalletCore");

// ─── Types ──────────────────────────────────────────────────────────────────

export type WalletResult = {
  mnemonic: string;
};

export type CoinAccount = {
  address: string;
  privateKey: string;
};

export type SupportedCoin = "ethereum" | "solana";

// Ethereum: numeric fields are bare hex strings (no 0x prefix) — use bigint.toString(16)
type LegacyGas = { gasPriceHex: string };
type Eip1559Gas = { maxFeePerGasHex: string; maxPriorityFeePerGasHex: string };

export type EthTxNative = {
  to: string;
  valueHex: string;
  nonce: number;
  gasLimitHex: string;
  chainId: number;
  dataHex?: string;
} & (LegacyGas | Eip1559Gas);

// Solana: lamports as decimal string to avoid JS precision loss
export type SolanaTxNative = {
  to: string;
  lamports: string;
  recentBlockhash: string;
};

// ─── Native calls ────────────────────────────────────────────────────────────

/** Create a new HD wallet. strength 128 → 12 words, 256 → 24 words */
export function generateWallet(
  strength = 128,
  passphrase = "",
): Promise<WalletResult> {
  return TrustWalletCore.generateWallet(strength, passphrase);
}

/** Validate and restore an existing wallet from a BIP-39 mnemonic */
export function restoreWallet(
  mnemonic: string,
  passphrase = "",
): Promise<WalletResult> {
  return TrustWalletCore.restoreWallet(mnemonic, passphrase);
}

/** Derive the address and private key for a specific coin from a mnemonic */
export function getAddressForCoin(
  mnemonic: string,
  coin: SupportedCoin,
  passphrase = "",
): Promise<CoinAccount> {
  return TrustWalletCore.getAddressForCoin(mnemonic, coin, passphrase);
}

/** Sign an Ethereum transaction; returns 0x-prefixed RLP-encoded signed tx hex */
export function signEthereumTransaction(
  privateKeyHex: string,
  tx: EthTxNative,
): Promise<string> {
  const hexToBigInt = (h: string) => (h ? BigInt("0x" + h) : 0n);
  return signEth(privateKeyHex, {
    to: tx.to,
    chainId: tx.chainId,
    nonce: tx.nonce,
    gasLimit: hexToBigInt(tx.gasLimitHex),
    value: hexToBigInt(tx.valueHex),
    data: tx.dataHex ? "0x" + tx.dataHex : undefined,
    ...("gasPriceHex" in tx
      ? { gasPrice: hexToBigInt(tx.gasPriceHex) }
      : {
          maxFeePerGas: hexToBigInt(tx.maxFeePerGasHex),
          maxPriorityFeePerGas: hexToBigInt(tx.maxPriorityFeePerGasHex),
        }),
  });
}

/** Sign a Solana SOL transfer; returns base64-encoded signed transaction */
export function signSolanaTransaction(
  privateKeyHex: string,
  tx: SolanaTxNative,
): Promise<string> {
  return signSol(privateKeyHex, {
    to: tx.to,
    lamports: BigInt(tx.lamports),
    recentBlockhash: tx.recentBlockhash,
  });
}
