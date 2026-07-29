import { requireNativeModule } from "expo-modules-core";

export type SupportedCoin = "ethereum" | "solana" | "bnb";

export type CoinAccount = {
  address: string;
  privateKey: string;
};

export type WalletResult = {
  mnemonic: string;
  wallets: Record<SupportedCoin, string>;
};

const TrustWalletCore = requireNativeModule("TrustWalletCore");

// ─── Native calls ────────────────────────────────────────────────────────────

/** Create a new HD wallet and store encrypted keys for all supported coins */
export async function generateWallet(
  strength = 128,
  passphrase = "",
): Promise<WalletResult> {
  const { mnemonic } = (await TrustWalletCore.generateWallet(
    strength,
    passphrase,
  )) as { mnemonic: string };
  const coins: SupportedCoin[] = ["ethereum", "solana", "bnb"];
  const entries = await Promise.all(
    coins.map(async (coin) => {
      const { address } = await getAddressForCoin(
        mnemonic,
        coin,
        passphrase,
      );
      return [coin, address] as const;
    }),
  );
  return {
    mnemonic,
    wallets: Object.fromEntries(entries) as Record<SupportedCoin, string>,
  };
}

/** Validate and restore an existing wallet from a BIP-39 mnemonic */
export async function restoreWallet(
  mnemonic: string,
  passphrase = "",
): Promise<WalletResult> {
  await TrustWalletCore.restoreWallet(mnemonic, passphrase);
  const coins: SupportedCoin[] = ["ethereum", "solana", "bnb"];
  const entries = await Promise.all(
    coins.map(async (coin) => {
      const { address } = await getAddressForCoin(
        mnemonic,
        coin,
        passphrase,
      );
      return [coin, address] as const;
    }),
  );
  return {
    mnemonic,
    wallets: Object.fromEntries(entries) as Record<SupportedCoin, string>,
  };
}

/** Derive the address and private key for a specific coin from a mnemonic */
export function getAddressForCoin(
  mnemonic: string,
  coin: SupportedCoin,
  passphrase = "",
): Promise<CoinAccount> {
  return TrustWalletCore.getAddressForCoin(mnemonic, coin, passphrase);
}
