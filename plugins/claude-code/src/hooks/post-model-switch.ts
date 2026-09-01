/**
 * PostModelSwitch — fires after the session's model changes, INCLUDING changes
 * Claude Code makes on its own (restoring the model when a session resumes).
 *
 * stdin:  { session_id, transcript_path, cwd, hook_event_name, from_model, to_model }
 * stdout: nothing — this is a post-action event and cannot block.
 *
 * It exists here purely to keep the recorded session model true. PreModelSwitch
 * records the model for every switch it ALLOWS, but it never sees a change the
 * harness makes on its own, and that is exactly the case that would otherwise
 * leave a resumed session enforcing against a stale model. Recording here closes
 * that gap; the enforcement itself stays in pre-model-switch.ts (preventive) and
 * user-prompt-submit.ts (containment), and the latter is what catches a model
 * this hook records as prohibited — on the very next turn, since nothing can be
 * refused at this point.
 *
 * Deliberately does NOT open the data gateway: it makes no decision, so it needs
 * no policy bundle, and a post-action event on the session's critical path
 * should cost a single small file write and nothing else.
 *
 * Fail-open: any error → no output, exit 0.
 */
import { loadConfig, recordSessionModel } from '@akasecurity/plugin-sdk';

import { getString, parseJson, readStdin } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (input === null) return;
  const config = loadConfig();
  const sessionId = getString(input, 'session_id');
  // The recorded model lands in that home, so a redirected one is worth the
  // same once-per-session note every other hook makes.
  warnIfStoreRedirected(config, sessionId);
  recordSessionModel(config.dataDir, sessionId, getString(input, 'to_model'));
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
