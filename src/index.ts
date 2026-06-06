import {
  CredentialUtils,
  EvmChainProvider,
  MAINNET_CHAIN_IDS,
  TESTNET_CHAIN_IDS,
  type IKeyProvider,
  type WalletData,
} from "@chainberry/chainberry-wallet";
import { Buffer } from "buffer";

import { requireNativeModule } from "expo-modules-core";
import * as Keychain from "react-native-keychain";

// ethers v6 internal XHR doesn't work in React Native — replace with RN's fetch
// FetchRequest.registerGetUrl(async (req) => {
//   const response = await fetch(req.url, {
//     method: req.method,
//     headers: req.headers as Record<string, string>,
//     body: req.body ?? undefined,
//   });
//   const headers: Record<string, string> = {};
//   response.headers.forEach((value: string, key: string) => {
//     headers[key] = value;
//   });
//   return {
//     statusCode: response.status,
//     statusMessage: response.statusText,
//     headers,
//     body: new Uint8Array(await response.arrayBuffer()),
//   };
// });

const TrustWalletCore = requireNativeModule("TrustWalletCore");

// ─── Types ──────────────────────────────────────────────────────────────────

export type { WalletData };

export type SupportedCoin = "ethereum" | "solana" | "bnb";

export type WalletResult = {
  mnemonic: string;
  wallets: Record<SupportedCoin, WalletData>;
};

export type CoinAccount = {
  address: string;
  privateKey: string;
};

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

// ─── Keychain-backed key provider ───────────────────────────────────────────

const keychainKeyProvider: IKeyProvider = {
  async wrapKey(aesKey: Buffer, keyId: string): Promise<string> {
    await Keychain.setGenericPassword(keyId, aesKey.toString("base64"), {
      service: keyId,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
    return keyId;
  },
  async unwrapKey(_wrappedKey: string, keyId: string): Promise<Buffer> {
    const credentials = await Keychain.getGenericPassword({ service: keyId });
    if (!credentials)
      throw new Error(`No key in keychain for service: ${keyId}`);
    return Buffer.from(credentials.password, "base64");
  },
};

const credentialUtils = new CredentialUtils(keychainKeyProvider);

const evmProvider = new EvmChainProvider(
  {
    WALLET_ENV: "mainnet",
    BNB_RPC_URL:
      "https://twilight-patient-ensemble.bsc.quiknode.pro/7aff06038e8571d12e57988b0f18b1f411429734",
  },
  credentialUtils,
);

const CHAIN_ID_TO_NETWORK: Record<number, string> = Object.fromEntries([
  ...Object.entries(MAINNET_CHAIN_IDS).map(([n, id]) => [id, n]),
  ...Object.entries(TESTNET_CHAIN_IDS).map(([n, id]) => [id, n]),
]);

// ─── Key storage ────────────────────────────────────────────────────────────

async function storeWalletKey(
  address: string,
  privateKeyHex: string,
): Promise<WalletData> {
  const keyId = `wallet-${address}`;
  const encrypted = await credentialUtils.hybridEncrypt(privateKeyHex, keyId);
  const walletData: WalletData = {
    address,
    encryptedSecret: encrypted.ciphertext,
    iv: encrypted.iv,
    tag: encrypted.tag,
    wrappedKey: encrypted.wrappedKey,
    kmsKeyId: encrypted.kmsKeyId,
  };
  await Keychain.setGenericPassword("d", JSON.stringify(walletData), {
    service: `walletdata-${address}`,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  return walletData;
}

export async function getWalletData(address: string): Promise<WalletData> {
  const credentials = await Keychain.getGenericPassword({
    service: `walletdata-${address}`,
  });
  if (!credentials)
    throw new Error(`No wallet data in keychain for address: ${address}`);
  return JSON.parse(credentials.password) as WalletData;
}

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
      const { address, privateKey } = await getAddressForCoin(
        mnemonic,
        coin,
        passphrase,
      );
      const walletData = await storeWalletKey(address, privateKey);
      return [coin, walletData] as const;
    }),
  );
  return {
    mnemonic,
    wallets: Object.fromEntries(entries) as Record<SupportedCoin, WalletData>,
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
      const { address, privateKey } = await getAddressForCoin(
        mnemonic,
        coin,
        passphrase,
      );
      const walletData = await storeWalletKey(address, privateKey);
      return [coin, walletData] as const;
    }),
  );
  return {
    mnemonic,
    wallets: Object.fromEntries(entries) as Record<SupportedCoin, WalletData>,
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

// ─── Signing ─────────────────────────────────────────────────────────────────

/** Sign an Ethereum transaction; returns 0x-prefixed RLP-encoded signed tx hex */
export async function signEthereumTransaction(
  walletData: WalletData,
  tx: EthTxNative,
): Promise<string> {
  const network = CHAIN_ID_TO_NETWORK[tx.chainId] ?? "ETH";
  const hexToBigInt = (h: string) => (h ? BigInt("0x" + h) : 0n);
  return evmProvider.sign({
    network,
    wallet: walletData,
    toAddress: tx.to,
    amount: "0",
    txParams: {
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
    },
  });
}

/** Send BNB on BSC mainnet; returns the transaction hash */
export async function sendBnb(
  toAddress: string,
  amountBnb: string,
  address: string,
): Promise<string> {
  const walletData = await getWalletData(address);
  return evmProvider.sendBnb(toAddress, amountBnb, walletData);
}

/** Sign a Solana SOL transfer; returns base64-encoded signed transaction */
// export async function signSolanaTransaction(
//   walletData: WalletData,
//   tx: SolanaTxNative,
// ): Promise<string> {
//   const privateKeyHex = await credentialUtils.hybridDecrypt(
//     {
//       wrappedKey: walletData.wrappedKey,
//       iv: walletData.iv,
//       tag: walletData.tag,
//       encryptedSecret: walletData.encryptedSecret,
//       kmsKeyId: walletData.kmsKeyId,
//     },
//     walletData.kmsKeyId,
//   );
//   return signSol(privateKeyHex, {
//     to: tx.to,
//     lamports: BigInt(tx.lamports),
//     recentBlockhash: tx.recentBlockhash,
//   });
// }
