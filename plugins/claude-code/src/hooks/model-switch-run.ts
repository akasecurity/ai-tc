// The runnable halves of the two model-switch hooks, with their I/O taken as
// seams so they unit-test without a hook process. Hook ENTRY files run main()
// on import and must never be imported by tests, so anything left in an entry
// is unreachable to the suite and lands in the coverage denominator uncovered —
// the entries below are reduced to reading stdin and calling these.
//
// The seams are the gateway, the emitter and the clock. Everything else is
// ordinary logic and is exercised directly.
import { randomUUID } from 'node:crypto';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { buildModelRefusalEvent, recordSessionModel } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { decidePreModelSwitch, type PreModelSwitchOutput } from './model-guard.ts';

export interface PreModelSwitchDeps {
  config: PluginConfig;
  /** Null when the local store cannot be opened — the fail-open path. */
  openGateway: () => DataGateway | null;
  emit: (output: PreModelSwitchOutput) => Promise<void>;
  /** Surfaces a redirected (symlinked) home once per session, on stderr. */
  warnIfStoreRedirected: (config: PluginConfig, sessionId: string | undefined) => void;
  /** Injected so a test can pin the recorded id and timestamp. */
  newId?: () => string;
  now?: () => Date;
}

/**
 * Decide one requested model switch, and record the model when it is allowed.
 *
 * Returns whether the switch was refused, purely so a test can assert on the
 * verdict without reading stdout; the entry ignores it.
 */
export async function runPreModelSwitch(
  input: Record<string, unknown>,
  toModel: string,
  sessionId: string | undefined,
  deps: PreModelSwitchDeps,
): Promise<boolean> {
  void input;
  const { config } = deps;
  // A symlinked home redirects the policy cache this hook decides from, so the
  // prohibitions it reads may not be the ones this machine was attached with.
  deps.warnIfStoreRedirected(config, sessionId);

  // No store, no bundle, no prohibition list — allow. Deliberately silent,
  // unlike user-prompt-submit's once-per-session store warning: a model switch
  // is not the moment to explain store health, and that hook already says it.
  const gateway = deps.openGateway();
  if (gateway === null) return false;

  // Closed at each exit below rather than in a `finally` here: the refusal path
  // needs the gateway still open to record the event it is about to emit.
  let prohibited: readonly string[] | undefined;
  try {
    prohibited = (await gateway.getPolicyBundle()).prohibitedModels;
  } catch {
    await gateway.close();
    return false;
  }

  const decision = decidePreModelSwitch(toModel, prohibited);
  if (decision !== null) {
    // Best-effort, and swallowed: a refusal that cannot be written down is still
    // a refusal, so a failed write must not reach the entry's outer catch and
    // turn this deny into a fail-open allow.
    try {
      await gateway.recordAuditEvent(
        buildModelRefusalEvent({
          id: (deps.newId ?? randomUUID)(),
          sessionId,
          model: toModel,
          seam: 'switch',
          sourceTool: SOURCE_TOOL.ClaudeCode,
          occurredAt: (deps.now ?? (() => new Date()))().toISOString(),
        }),
      );
    } catch {
      // Swallowed on purpose — see above.
    }
    await gateway.close();
    await deps.emit(decision);
    return true;
  }

  await gateway.close();

  // ALLOWED — so this is the authoritative moment the session's model becomes
  // `to_model`, and recording it here is what lets user-prompt-submit decide
  // without re-reading the transcript. Recorded only on the allow path: a
  // refused switch never happened, and storing its target would make the next
  // turn enforce against a model the session is not running.
  recordSessionModel(config.dataDir, sessionId, toModel);
  return false;
}

export interface PostModelSwitchDeps {
  config: PluginConfig;
  warnIfStoreRedirected: (config: PluginConfig, sessionId: string | undefined) => void;
}

/**
 * Record the model after a switch the harness has already applied.
 *
 * Opens no gateway: it makes no decision, so it needs no policy bundle, and a
 * post-action event on the session's path should cost one small file write.
 */
export function runPostModelSwitch(
  sessionId: string | undefined,
  toModel: string | undefined,
  deps: PostModelSwitchDeps,
): void {
  deps.warnIfStoreRedirected(deps.config, sessionId);
  recordSessionModel(deps.config.dataDir, sessionId, toModel);
}
