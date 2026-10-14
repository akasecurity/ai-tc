// The runnable halves of the two model-switch hooks, with their I/O taken as
// seams so they unit-test without a hook process. Hook ENTRY files run main()
// on import and must never be imported by tests, so anything left in an entry
// is unreachable to the suite and lands in the coverage denominator uncovered —
// the entries below are reduced to reading stdin and calling these.
//
// The seams are the gateway, the emitter and the clock. Everything else is
// ordinary logic and is exercised directly.
import { randomUUID } from 'node:crypto';

import { governanceApplies } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { buildModelRefusalEvent, recordSessionModel } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { decidePreModelSwitch, type PreModelSwitchOutput } from './model-guard.ts';
import { captureScopeKey } from './shared.ts';

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
 * `cwd` is the payload's own, and only the refusal path reads it. It is keyed by
 * `captureScopeKey`, exactly as the session's path-less captures are keyed, and
 * that one key asks the gateway whether the organization's model policy governs
 * this switch (`governanceApplies`) and stamps the refusal row when it does. A
 * machine-wide attachment, a standalone store and any gateway that does not
 * answer the question are governed everywhere; a scoped attachment only in its
 * enrolled repositories. Where it is not governed, a switch the list would
 * refuse is allowed: no output, no row, and the session's model recorded as for
 * any allowed switch. A switch the list allows pays no `.git` walk and no
 * lookup. `cwd` is REQUIRED rather than optional: the hook entry is the only
 * production caller and no test can import an entry, so the compiler is the one
 * check that the entry passes it.
 *
 * Returns whether the switch was refused, purely so a test can assert on the
 * verdict without reading stdout; the entry ignores it.
 */
export async function runPreModelSwitch(
  toModel: string,
  sessionId: string | undefined,
  cwd: string | undefined,
  deps: PreModelSwitchDeps,
): Promise<boolean> {
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
    // Keyed ONCE, now that the list refuses, and the one key both asks and
    // stamps, so the verdict and the row can never disagree about where the
    // switch was requested.
    const scopeKey = captureScopeKey({ cwd });
    if (governanceApplies(gateway, scopeKey)) {
      // Best-effort, and swallowed: a refusal that cannot be written down is
      // still a refusal, so a failed write must not reach the entry's outer
      // catch and turn this deny into a fail-open allow.
      try {
        await gateway.recordAuditEvent(
          buildModelRefusalEvent({
            id: (deps.newId ?? randomUUID)(),
            sessionId,
            model: toModel,
            seam: 'switch',
            sourceTool: SOURCE_TOOL.ClaudeCode,
            occurredAt: (deps.now ?? (() => new Date()))().toISOString(),
            scopeKey,
          }),
        );
      } catch {
        // Swallowed on purpose — see above.
      }
      await gateway.close();
      await deps.emit(decision);
      return true;
    }
    // Not governed here: the switch is ALLOWED, silently and with no row, and it
    // takes the allow tail below like any other allowed switch.
  }

  await gateway.close();

  // ALLOWED — so this is the authoritative moment the session's model becomes
  // `to_model`, and recording it here is what lets user-prompt-submit decide
  // without re-reading the transcript. That holds whatever allowed the switch:
  // one the organization does not govern in this repository still changes the
  // model the session runs on, and the next turn in an enrolled repository has
  // to judge that model. PostModelSwitch records it again once the harness has
  // applied the switch; recording it here as well keeps every allowed switch
  // alike and the marker right where that hook does not fire. Recorded only on
  // the allow path: a refused switch never happened, and storing its target
  // would make the next turn enforce against a model the session is not
  // running.
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
