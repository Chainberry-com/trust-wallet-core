# example (CI-only host app)

This is not a demo app — nothing in it ever runs. It exists purely so `expo prebuild` has a
real Expo project to autolink `@chainberry/trust-wallet-core` into (via the `file:..`
dependency in `package.json`), which is the only way to actually build/test this module's
Android code: `android/build.gradle`'s `useCoreDependencies()` needs a sibling
`:expo-modules-core` Gradle project (with its own NDK/CMake native build) that only a real
Expo host project's autolinking wires up — the module has no standalone Gradle wrapper of
its own. `.github/workflows/ci.yml`'s Android jobs use this app for exactly that.

`android/`, `ios/`, and `.expo/` are gitignored — `expo prebuild` regenerates them fresh
every time, so nothing durable should ever be hand-edited there.

## Running the same checks locally

```sh
cd example
npm install
npx expo prebuild --platform android --no-install
cd android
./gradlew :chainberry-trust-wallet-core:testDebugUnitTest         # JVM unit tests
./gradlew :chainberry-trust-wallet-core:connectedDebugAndroidTest # needs an emulator/device
```

(The generated project name is derived from `@chainberry/trust-wallet-core` in
`package.json` → Gradle project `:chainberry-trust-wallet-core`.)
