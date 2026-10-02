// Never actually run — this app exists only so `expo prebuild` has a host project to
// autolink @chainberry/trust-wallet-core (via the `file:..` dependency below) into.
// See README.md.
import { registerRootComponent } from "expo";

function App() {
  return null;
}

registerRootComponent(App);
