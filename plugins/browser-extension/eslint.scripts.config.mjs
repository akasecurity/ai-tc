// @ts-check
// Network-only guard for the extension's build scripts (scripts/), which the
// main `eslint src test` pass never reaches. It enforces just the no-network
// bans — not the source-only conventions — so build tooling is not dragged into
// the full ruleset. Run with `--no-config-lookup` so `eslint.config.mjs` (which
// pulls in `base`) does not also apply here.
import { networkGuard } from '@akasecurity/eslint-config';

export default [...networkGuard];
