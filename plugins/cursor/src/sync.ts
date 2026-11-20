// The detached attached-mode sync child `handleSessionStart` spawns. Inert
// until the machine attaches to a deployment its own organization runs.
import { commandScanFor, runAttachedSync } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';
import { scanWorktree } from '@akasecurity/scanner';
import { SOURCE_TOOL } from '@akasecurity/schema';

try {
  await runAttachedSync(undefined, {
    scan: commandScanFor(() => loadConfig(), scanWorktree, SOURCE_TOOL.Cursor),
  });
} catch {
  // A detached child has no one to report to; the next session start retries.
}
process.exit(0);
