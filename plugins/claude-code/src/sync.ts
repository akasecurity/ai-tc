/**
 * The detached policy-sync child.
 *
 * Spawned by SessionStart (see `triggerPolicySync`), at most every fifteen
 * minutes and only on a machine whose settings name a control plane and which
 * holds a credential for it. It pulls the organization's policy bundle into the
 * on-disk cache that the hook path reads; nothing on a hook path awaits this
 * process, and no hook ever makes the request itself.
 *
 *   node scripts/sync.js
 *
 * It also services the device-command channel, which is why this entry hands
 * `runAttachedSync` a scan. The scanner cannot be imported by the runtime
 * itself — `@akasecurity/scanner` already depends on it, so that edge would
 * close a cycle — and passing it here keeps the capability honest besides: a
 * host that ships no scanner passes nothing and does not poll, rather than
 * accepting a command it could never run.
 *
 * The scan SCOPE is not chosen here. `commandScanFor` owns it, so the rule
 * ("never the home directory implicitly") is written once rather than three
 * times across three plugin trees.
 *
 * Fully fail-open, and it never throws: `runAttachedSync` records an outcome
 * for `/aka:status` to render and swallows everything else. Always exits 0.
 */
import { commandScanFor, runAttachedSync } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';
import { scanWorktree } from '@akasecurity/scanner';
import { SOURCE_TOOL } from '@akasecurity/schema';

try {
  await runAttachedSync(undefined, {
    scan: commandScanFor(loadConfig(), scanWorktree, SOURCE_TOOL.ClaudeCode),
  });
} catch {
  // Nothing to report to — this process is detached with stdio ignored.
}
process.exit(0);
