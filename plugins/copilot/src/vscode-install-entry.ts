// Build entry for `scripts/vscode-install.js`. Kept apart from
// ./vscode-install-cli.ts so a test can import that module without running it.
import { main } from './vscode-install-cli.ts';

process.exit(main());
