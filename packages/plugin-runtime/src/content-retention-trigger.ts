import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { throttled } from '@akasecurity/plugin-sdk';

/**
 * The marker file one pass writes to suppress the next.
 *
 * EXPORTED so the one place that writes it and the one place that probes for it
 * read the same string. A build test declaring its own copy would prove the two
 * copies agree and nothing else.
 */
export const CONTENT_RETENTION_MARKER_NAME = 'content-retention-last-attempt';

/**
 * The built child's filename, resolved as a sibling of this module.
 *
 * Exported for the same reason as the marker: the emit and the lookup must be
 * one string. The published plugin ships `scripts/` only, so this resolves
 * against the bundle rather than the source tree.
 */
export const CONTENT_RETENTION_SCRIPT_NAME = 'content-retention.js';

/**
 * How long one pass suppresses the next.
 *
 * HOURS, not minutes, and the difference is the point. The two attached-mode
 * triggers beside this one bound externally-visible staleness — how long a
 * deployment waits for policy or for activity — so they run every few minutes.
 * This one bounds nothing anybody is waiting on: it is local disk hygiene
 * against a store that grows by megabytes a day, and a pass that skips costs
 * nothing but a few hours of bytes.
 *
 * An hour rather than a day because the FIRST pass on an old store is not the
 * steady state. A machine carrying months of bodies has hundreds of thousands
 * of candidates against a per-pass cap, so it needs several passes to catch up,
 * and at a daily window that would take a week. Once caught up the passes are
 * nearly free — the candidate seek finds nothing and the child exits.
 */
export const CONTENT_RETENTION_THROTTLE_MS = 60 * 60 * 1000;

export interface ContentRetentionTriggerDeps {
  /** Where the detached child lives. Injectable because the shipped layout differs from the source tree. */
  scriptUrl?: URL;
  spawnChild?: (scriptPath: string) => void;
  isThrottled?: (dataDir: string) => boolean;
}

/**
 * Expire captured bodies past the retention horizon, in a DETACHED CHILD, at
 * most hourly, and never on the path a user is waiting on.
 *
 * SYNCHRONOUS AND `void`, deliberately — the same reason the two triggers
 * beside it are. Hook entries exit as soon as their work is done, so an
 * un-awaited promise here would be killed mid-flight and a returned one would
 * be a promise nobody can await.
 *
 * NEVER THROWS. It runs inside SessionStart, where a failure must cost a pass
 * and never a session.
 *
 * NOT GATED ON ATTACHMENT, unlike its two neighbours. Body expiry is a local
 * concern and almost every machine is standalone; gating it the way they are
 * gated would mean it never ran for nearly anybody.
 *
 * THE SETTING IS CHECKED FIRST AND THE THROTTLE LAST, which is the same
 * ordering the attached triggers use and for a sharper reason here. Expiry is
 * OFF by default, so probing the throttle first would write a marker file onto
 * the disk of every machine that has never switched this on — a file appearing
 * because of a feature nobody enabled. The child re-reads the setting anyway:
 * this check is to avoid paying a spawn, not to be the decision.
 */
export function triggerContentRetention(
  config: PluginConfig,
  deps: ContentRetentionTriggerDeps = {},
): void {
  try {
    if (!config.settings.bodyRetention.enabled) return;

    const isThrottled =
      deps.isThrottled ??
      ((dir: string) =>
        throttled(dir, CONTENT_RETENTION_MARKER_NAME, CONTENT_RETENTION_THROTTLE_MS));
    if (isThrottled(config.dataDir)) return;

    const scriptPath = fileURLToPath(
      deps.scriptUrl ?? new URL(CONTENT_RETENTION_SCRIPT_NAME, import.meta.url),
    );
    (deps.spawnChild ?? spawnDetached)(scriptPath);
  } catch {
    // A sweep that cannot be started is a store that keeps its bodies a few
    // hours longer, not a broken session.
  }
}

/**
 * `detached` + `unref()` is what lets the child outlive an entry that is about
 * to exit; without the `unref()` the parent would wait on it, which is the
 * opposite of the intent.
 */
function spawnDetached(scriptPath: string): void {
  const child = spawn(process.execPath, [scriptPath], { detached: true, stdio: 'ignore' });
  // MANDATORY, not defensive. libuv reports fork failures (EAGAIN under
  // process-table pressure, EMFILE on fd exhaustion, EACCES, ENOENT) by emitting
  // 'error' on a LATER TICK rather than by throwing — and an unhandled 'error'
  // on an EventEmitter is rethrown as an uncaughtException. By then the
  // try/catch above has returned, so it cannot see it, and SessionStart dies
  // mid-flight instead of degrading.
  child.on('error', () => {
    // Nothing to do about a failed background spawn; the next session retries.
  });
  child.unref();
}
