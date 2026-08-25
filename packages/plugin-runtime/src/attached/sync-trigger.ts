import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { readControlPlaneCredentialState } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { throttled } from '@akasecurity/plugin-sdk';
import { isAttached } from '@akasecurity/schema';

/**
 * The marker that paces the policy pull, a sibling file in the data dir.
 *
 * Named for the job rather than for the module, because what it protects is the
 * SPAWN: several sessions opening at once must not fork several children that
 * each fetch the same bundle.
 */
export const SYNC_MARKER_NAME = 'sync-last-attempt';

/**
 * The filename this module resolves as a sibling of the running script.
 *
 * EXPORTED so the one place that emits it and the one place that probes for it
 * read the same string. A build test declaring its own copy proves the two
 * copies agree and nothing else: rename the constant here and the resolver
 * looks for a file the build never emits, while a test holding the old literal
 * stays green — which is the drift that test exists to catch.
 */
export const SYNC_SCRIPT_NAME = 'sync.js';

/** How long one attempt suppresses the next. */
export const SYNC_THROTTLE_MS = 15 * 60 * 1000;

export interface SyncTriggerDeps {
  /** Where the detached child lives. Injectable because the shipped layout differs from the source tree. */
  scriptUrl?: URL;
  spawnChild?: (scriptPath: string) => void;
  isThrottled?: (dataDir: string) => boolean;
}

/**
 * Pull the organization's policy in a DETACHED CHILD, at most every fifteen
 * minutes, and never on the path a user is waiting on.
 *
 * SYNCHRONOUS AND `void`, deliberately. Hook entries exit as soon as their work
 * is done, so an un-awaited promise here would be killed mid-flight and a
 * returned one would be a promise nobody can await. All network work therefore
 * happens in a child that outlives this process, and the cost — stated rather
 * than hidden — is that a freshly attached machine enforces its local policy for
 * one more session.
 *
 * NEVER THROWS. It runs inside SessionStart, where a failure must cost a policy
 * refresh and never a session.
 *
 * ATTACHED FIRST, BEFORE THE THROTTLE IS CONSULTED. Without that ordering a
 * machine that is not attached forks a child every fifteen minutes for the life
 * of the install — one that reads its configuration, finds no attachment and
 * exits — and "not attached" is the state of almost every machine. Checking
 * first also keeps an unattached machine from writing the marker at all.
 *
 * THE THROTTLE'S VERDICT IS OBEYED, with no cold-cache exception. A machine that
 * has never synced is not throttled anyway — `throttled` treats a missing marker
 * as permitting — so the case a bypass would serve is already served. What a
 * bypass would actually do is fork on EVERY session for a machine whose control
 * plane is unreachable, because the cache stays cold and the marker only
 * advances on the permitting path. A failed sync burns the window by design;
 * staleness surfaces through status rather than through retries.
 */
export function triggerPolicySync(config: PluginConfig, deps: SyncTriggerDeps = {}): void {
  try {
    if (!isAttached(config.settings)) return;
    const connection = config.settings.controlPlane;
    if (connection === undefined) return;
    // A credential that is absent, untrusted or minted for another deployment
    // means there is nothing to sync against — and the child would only
    // rediscover that after paying a process spawn.
    if (!readControlPlaneCredentialState(config.settingsDir, connection).usable) return;

    const isThrottled =
      deps.isThrottled ?? ((dir: string) => throttled(dir, SYNC_MARKER_NAME, SYNC_THROTTLE_MS));
    if (isThrottled(config.dataDir)) return;

    const scriptPath = fileURLToPath(deps.scriptUrl ?? new URL(SYNC_SCRIPT_NAME, import.meta.url));
    (deps.spawnChild ?? spawnDetached)(scriptPath);
  } catch {
    // A policy refresh that cannot be started is a stale policy, not a broken
    // session. Status reports the staleness; nothing here does.
  }
}

/**
 * `detached` + `unref()` is what lets the child outlive an entry that is about
 * to exit; without the `unref()` the parent would wait on it, which is the
 * opposite of the intent.
 */
function spawnDetached(scriptPath: string): void {
  const child = spawn(process.execPath, [scriptPath], { detached: true, stdio: 'ignore' });
  // MANDATORY, not defensive. libuv reports fork failures (EAGAIN under process
  // -table pressure, EMFILE on fd exhaustion, EACCES, ENOENT) by emitting
  // 'error' on a LATER TICK rather than by throwing — and an unhandled 'error'
  // on an EventEmitter is rethrown as an uncaughtException. By then the
  // try/catch above has returned, so it cannot see it, and SessionStart dies
  // mid-flight instead of degrading.
  child.on('error', () => {
    // Nothing to do about a failed background spawn; the next session retries,
    // and the outcome surfaces through status as a stale sync.
  });
  child.unref();
}
