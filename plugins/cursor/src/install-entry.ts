// Build entry for `scripts/install.js`. Kept apart from ./install-cli.ts so a
// test can import that module without running it.
import { main } from './install-cli.ts';

process.exit(main());
