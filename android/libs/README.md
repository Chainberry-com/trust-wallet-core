# Vendored wallet-core (local Maven repo)

`com.trustwallet:wallet-core` (and its `wallet-core-proto` dependency) are only
published to GitHub Packages, which requires authentication even to download a
public package. To spare every dev/CI machine from needing a
`read:packages` PAT, the resolved `.aar`/`.jar` + `.pom` files are vendored
here in a plain Maven-layout directory:

```
libs/com/trustwallet/wallet-core/4.1.19/wallet-core-4.1.19.{aar,pom}
libs/com/trustwallet/wallet-core-proto/4.1.19/wallet-core-proto-4.1.19.{jar,pom}
```

`../build.gradle` points its `repositories {}` block at this directory
*before* the GitHub Packages fallback, so a normal build resolves entirely
from here — no credentials needed.

Files were downloaded from `maven.pkg.github.com/trustwallet/wallet-core` on
2026-09-04 and their sha1 checksums verified against GitHub's own
`.sha1` files (still alongside each artifact here).

## Bumping the pinned version

1. `./download.sh <new-version>` (needs `GITHUB_ACTOR`/`GITHUB_TOKEN` env vars,
   or `gpr.user`/`gpr.key` in `~/.gradle/gradle.properties` — same credentials
   the GitHub Packages fallback in `build.gradle` already uses).
2. Update the pinned version in `../build.gradle`
   (`implementation 'com.trustwallet:wallet-core:...'`) and in
   `../../ChainberryTrustWalletCoreModule.podspec` (`s.dependency 'TrustWalletCore', '...'`)
   to keep both platforms on the same wallet-core release.
3. Delete the old version's directories under `com/trustwallet/wallet-core*/`
   here (or leave them if you want to keep an easy rollback).
4. Re-run the conformance suite (`conformance/`) — a wallet-core bump can
   change derivation/signing output.
