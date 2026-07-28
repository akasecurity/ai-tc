// @ts-check
// Network-only guard for this package's dev/build scripts (scripts/), which the
// main `eslint src test` pass never reaches. It enforces just the no-network
// bans so the guarantee is uniform across every scripts/ dir in the workspace.
// Run with `--no-config-lookup` so `eslint.config.mjs` (base) does not apply.
import { networkGuard } from '@akasecurity/eslint-config';

export default networkGuard;
