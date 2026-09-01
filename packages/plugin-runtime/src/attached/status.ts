import { readControlPlaneCredentialFile, readWorkspaceSettings } from '@akasecurity/persistence';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { controlPlaneName, isAttached, isHistorySyncConsentValid } from '@akasecurity/schema';

import { readForwardDrops } from './forward-drops.ts';
import { readForwardHealth } from './forward-policy.ts';
import { readHistorySyncState } from './history-state.ts';
import { createPolicyStore } from './policy-store.ts';
import type { PolicySyncOutcome } from './policy-sync.ts';
import { readSyncState } from './sync-state.ts';

/**
 * What `/aka:status` prints about attached mode.
 *
 * NO NETWORK, EVER. No `pluginWhoami`, no call of any kind — a status renderer
 * that hangs for two seconds or throws when the control plane is down is the worst
 * possible first experience of attached mode, and "is my machine managed?" is
 * exactly the question a user asks WHEN something is wrong. Every field below is
 * read from disk. If identity from the control plane is ever wanted, it belongs behind
 * an explicit flag on `attach`, not here.
 *
 * Offline is the guarantee; PURE is not. `readAttachedConnection` can WRITE:
 * `repairOrRefuseMode` chmods a too-permissive `attached.json` back to 0600 on
 * sight. That is deliberate there — tightening beats stranding a legitimately
 * attached device, and a read is where a 0644 credential actually gets noticed —
 * but it means rendering status has a filesystem side effect, and nothing here
 * should be built on the assumption that it does not.
 *
 * ALLOW-LIST, NOT DENY-LIST. The renderer names the fields it prints, one by
 * one, rather than printing a record minus a redaction list. The connection
 * object holds `apiKey`; a deny-list satisfies today's redaction test and then
 * leaks the first field someone adds afterwards. `keyPrefix` — the non-secret
 * display half — is the only key-derived thing that is ever rendered, and it is
 * rendered because it was stored separately for that purpose.
 */

export interface RenderAttachedStatusDeps {
  /** The ~/.aka root, for reading settings. */
  base: string;
  settingsDir: string;
  dataDir: string;
  now?: () => number;
}

/**
 * What to DO about a refusal — the two verdicts a human has to act on, and the
 * two whose remediations are NOT interchangeable.
 *
 * Shared by both halves of the block on purpose. Policy sync and event
 * forwarding fail on different routes and are recorded in different files, but
 * a 403 means the same thing on both, and the failure this whole surface exists
 * to prevent is a user being sent somewhere that cannot help.
 *
 * The distinction is the point:
 *
 *   401 — the credential is no longer accepted. `attach` mints a new one, and
 *         that fixes it. This is the wording the sync path has always had.
 *   403 — the credential IS accepted and is not permitted: a role demoted to
 *         read-only, an api-key scoped away from the route, a suspended account
 *         or member. Re-attaching mints a credential refused identically, so
 *         sending the user to `attach` would be a wrong instruction, not merely
 *         a vague one — they would do the work and land back here. Only someone
 *         who administers the organization can lift it, so that is who the line
 *         names.
 */
const REFUSAL_LINES: Record<'unauthorized' | 'forbidden', string> = {
  unauthorized: 'KEY REJECTED — re-attach with a valid plugin key',
  forbidden: 'ACCESS REFUSED — key is valid but not permitted; ask your org admin',
};

/** Human phrasing for each sync outcome. The two refusals are the ones that act. */
const OUTCOME_LINES: Record<PolicySyncOutcome, string> = {
  ok: 'policy synced',
  'not-modified': 'policy up to date',
  unauthorized: REFUSAL_LINES.unauthorized,
  forbidden: REFUSAL_LINES.forbidden,
  unreachable: 'control plane unreachable at last attempt',
  'invalid-bundle': 'control plane sent a policy bundle this build cannot read',
};

function ageLine(fromMs: number, nowMs: number): string {
  const deltaMs = Math.max(0, nowMs - fromMs);
  const minutes = Math.floor(deltaMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${String(minutes)}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${String(hours)}h ago`;
  return `${String(Math.floor(hours / 24))}d ago`;
}

/**
 * Render the block, offline. Never throws — the same fail-open contract as the
 * rest of the package, because this runs inside a slash-command entry.
 *
 * The NOT-ATTACHED block covers all three negative cases identically on purpose:
 * file absent, file present but unparseable, and unknown `specVersion` all mean
 * "this device is not managed", and distinguishing them in the output would
 * describe the contents of a file the reader is not otherwise shown.
 */
export function renderAttachedStatus(deps: RenderAttachedStatusDeps): string {
  try {
    const nowMs = (deps.now ?? (() => Date.now()))();
    const settings = readWorkspaceSettings(deps.base);
    if (!isAttached(settings) || settings.controlPlane === undefined) {
      return ['AKA: standalone (not attached)', '  no control plane configured'].join('\n');
    }
    const connection = settings.controlPlane;
    // The WIDE read: this block prints `keyPrefix`, which the narrow state
    // deliberately does not carry. It is a TERMINAL surface — `aka status` — so
    // nothing here crosses to a browser.
    const state = readControlPlaneCredentialFile(deps.settingsDir, connection);

    const lines = [
      // The mismatch case earns its own headline. An administrator can repoint
      // `controlPlane` across a fleet and cannot write the credential file, so
      // this is an ordinary migration rather than a fault — and reporting it as
      // a bare "not attached" would send every affected user looking for a file
      // that is present and intact.
      state.usable
        ? 'AKA: attached'
        : state.reason === 'endpoint-mismatch'
          ? 'AKA: attached — credential is for another deployment, re-attach'
          : 'AKA: attached — no usable credential, re-attach',
      // ALLOW-LISTED, field by field. The credential itself is deliberately
      // absent and must stay that way; `keyPrefix` is the non-secret half.
      //
      // And every one of them goes through `printable`, which is about the
      // field's CONTENT rather than which fields appear. The allow-list above
      // decides what is rendered; it says nothing about what those strings
      // hold. None of these is authored by this machine — `label` comes from
      // `aka attach --label` or from a `settings.json` an administrator can pin
      // fleet-wide, and the endpoint and `keyPrefix` come off the credential
      // file — and all of them land in a status block a user reads to decide
      // whether their machine is managed. An ANSI escape in any of them can
      // repaint that block or hide a line, which is the same argument
      // `printable` was written for one field over.
      `  plane      ${printable(controlPlaneName(connection))}`,
      `  attached   ${printable(connection.attachedAt, 40)}`,
    ];
    if (state.usable && state.credential.keyPrefix !== undefined) {
      // `max` matches the schema's own bound, so a conforming prefix is never
      // truncated and a longer one cannot outrun it.
      lines.push(`  key        ${printable(state.credential.keyPrefix, 16)}…`);
    }
    if (!state.usable && state.reason === 'endpoint-mismatch') {
      lines.push(`  credential ${printable(state.credentialEndpoint, 200)}`);
    }

    return [
      ...lines,
      ...policyLines(deps.dataDir, nowMs),
      ...forwardLines(deps.dataDir, nowMs),
      ...historyLines(deps.dataDir, settings, connection.endpoint, nowMs),
    ].join('\n');
  } catch {
    // A status renderer that throws is worse than one that says little.
    return 'AKA: status unavailable';
  }
}

/**
 * Policy freshness and the last sync outcome.
 *
 * Separate from the connection block because the two answer different
 * questions — "is this device managed" and "is its policy current" — and a
 * device can be soundly attached with no policy yet, which is the state a fresh
 * attach leaves behind for one session by design.
 */
function policyLines(dataDir: string, nowMs: number): string[] {
  const lines: string[] = [];
  const state = readSyncState(dataDir);
  if (state) {
    lines.push(`  sync       ${OUTCOME_LINES[state.outcome]} (${ageLine(state.atMs, nowMs)})`);
  } else {
    lines.push('  sync       no attempt recorded yet');
  }
  return lines;
}

/**
 * Whether this device is still REPORTING — the other half of "is my machine
 * managed", and the half status used to answer by implication.
 *
 * Policy sync and event forwarding are different requests against different
 * routes, and they can diverge for one credential: `GET /v1/policy-bundle` is a
 * read and carries no write-role guard, while the ingest routes do. Demote an
 * attached device's owner to a read-only role and sync keeps returning 200 —
 * so the sync line above renders `policy synced (just now)` — while every
 * forward 403s. `forward.run` returns rather than throws on each of those (G1:
 * the local write already succeeded and the caller must return it), and its six
 * discarding call sites still discard them — so the breaker's own file is the
 * only thing that outlives the refusal, and the breaker then makes the silence
 * steady: three failures, open, one probe per cooldown.
 *
 * Which is why this reads a file rather than being plumbed a value.
 * `forward-policy.ts` persists the failure count, the breaker stamp and the
 * classified cause into the SAME `dataDir` the sync state is read from, and the
 * process that observed the refusal exited long before anyone ran `/aka:status`.
 * Read strictly read-only, since a status command must never open, close or
 * re-stamp the breaker it is describing.
 *
 * It names a CAUSE only for the two statuses that carry one. `run()` classifies
 * its failure before dropping it and records the classification beside the
 * count, so a 401 and a 403 arrive here as themselves — and the demotion above
 * now renders the remediation that actually applies instead of the one that
 * sends the user to `attach` to mint a credential refused identically. Every
 * other failure — a timeout, a refused connection, a 500 — lands in the
 * `unreachable` bucket, and for those the block still says what it observed and
 * stops. That silence is deliberate rather than residual: the count and the
 * stamp are facts, and a cause guessed from them would be the same kind of
 * overstatement as the clean block this whole surface replaced.
 */
/**
 * What the batch budget threw away, if anything.
 *
 * Rendered INDEPENDENTLY of breaker state, and that is the whole reason it
 * exists: the machine this happens on is the one whose breaker is closed. A
 * plane that answers every request successfully but slowly produces no
 * failures, so every other line in this block reads healthy while the tail of
 * each batch is discarded. Appended to all three of `forwardLines`' outcomes
 * rather than to one.
 *
 * "at least" is accuracy, not hedging. Concurrent detached workers increment the
 * tally with an unlocked read-modify-write, so a simultaneous pair can lose one
 * — the same imprecision the breaker's own file carries, and the honest word for
 * a floor.
 */
function dropLines(dataDir: string, nowMs: number): string[] {
  const drops = readForwardDrops(dataDir);
  if (!drops) return [];
  return [
    `             at least ${String(drops.droppedForwards)} events dropped past the ` +
      `batch budget, last ${ageLine(drops.lastDropAtMs, nowMs)}`,
  ];
}

/**
 * What has become of the activity recorded before this machine attached.
 *
 * OFFLINE, like every other line here, and read from the drain's own state file
 * rather than from the store: this renderer is synchronous and total, and a
 * count over `audit_events` is neither.
 *
 * The numbers are what that file records — which is a snapshot as of the last
 * pass, not a live figure. That is the honest thing to show: the drain runs in a
 * child spawned by a session, so between sessions nothing moves, and a number
 * that appeared to update would be describing work nobody did.
 *
 * NO ETA and no progress bar, deliberately. The schedule is coupled to how often
 * the user opens a session, so any projection would be a guess dressed as a
 * measurement.
 */
function historyLines(
  dataDir: string,
  settings: WorkspaceSettings,
  endpoint: string,
  nowMs: number,
): string[] {
  // Absent grant is the overwhelmingly common case, and it is not a fault: this
  // is opt-in, and a machine that never opted in should read as settled rather
  // than as pending.
  if (!isHistorySyncConsentValid(settings.historySyncConsent, endpoint)) {
    return ['  history    not shared (run `aka sync-history --on`)'];
  }

  const state = readHistorySyncState(dataDir);
  // Granted but nothing recorded yet: the grant is real and the first pass has
  // not run. Saying "waiting" rather than "0 sent" avoids reporting a number
  // that no pass produced.
  if (state === null) return ['  history    sharing — waiting for the first pass'];

  const sent = count(state.sentTotal);
  const total = count(state.sentTotal + state.pendingTotal);
  const skipped = state.skippedTotal > 0 ? `, ${count(state.skippedTotal)} could not be sent` : '';

  if (state.lastOutcome === 'refused') {
    return [
      "  history    stopped — that deployment refused this machine's key",
      '             re-attach to resume',
    ];
  }
  if (state.lastOutcome === 'unreachable') {
    return [
      `  history    paused — deployment unreachable, last tried ${ageLine(state.lastPassAtMs, nowMs)}`,
      `             ${sent} of ${total} records sent${skipped}`,
    ];
  }
  if (state.phase === 'complete' && state.pendingTotal === 0) {
    return [`  history    complete — ${sent} records sent${skipped}`];
  }
  return [`  history    sending — ${sent} of ${total} records sent${skipped}`];
}

/** Thousands separators, so a six-figure backlog is readable at a glance. */
function count(n: number): string {
  return n.toLocaleString('en-US');
}

function forwardLines(dataDir: string, nowMs: number): string[] {
  const drops = dropLines(dataDir, nowMs);
  const health = readForwardHealth(dataDir, nowMs);
  // No file is the HAPPY path, not a gap: `run()` writes nothing at all unless
  // something fails. Still phrased as what is known rather than as health —
  // "no failures recorded" is also true of a device that has never forwarded.
  if (!health) return ['  forward    no failures recorded', ...drops];

  const { consecutiveFailures, openedAtMs, lastFailure } = health;
  // Closed at zero means a forward SUCCEEDED and cleared a previous run of
  // failures — the one state in which this file is evidence of health. Returned
  // early because it is also the one state with no cause to name: a success
  // clears `lastFailure` with the count.
  if (openedAtMs === null && consecutiveFailures === 0) {
    return ['  forward    reporting normally', ...drops];
  }

  const lines =
    openedAtMs !== null
      ? // `openedAtMs` is re-stamped on every half-open probe, so the gap to now
        // is bounded by one cooldown however long the control plane has been down — it
        // dates the last ATTEMPT, never the outage. The failure count is the
        // part that grows, so that is the number shown as the magnitude.
        [
          `  forward    NOT REPORTING — ${String(consecutiveFailures)} consecutive ` +
            `failures, last tried ${ageLine(openedAtMs, nowMs)}`,
        ]
      : // Closed but non-zero: failing without having reached the threshold yet.
        [`  forward    ${String(consecutiveFailures)} failures since the last success`];

  // The cause rides on its own line, under both of the above rather than only
  // under the open one. A refusal is terminal from the FIRST failure — three
  // more forwards will be refused the same way — so waiting for the breaker to
  // trip before naming it would withhold the actionable half of the message for
  // exactly as long as the user could still have acted on it early.
  if (lastFailure === 'unauthorized' || lastFailure === 'forbidden') {
    lines.push(`             ${REFUSAL_LINES[lastFailure]}`);
  }
  return [...lines, ...drops];
}

/**
 * The policy cache half, async because the store is.
 *
 * Kept OUT of `renderAttachedStatus` so that function can stay synchronous and
 * total: a slash-command entry can render the connection block with no awaits at
 * all, and only pay for the cache read when it wants the version line.
 */
/**
 * A control-plane-supplied string, made safe to print.
 *
 * `PolicyBundle.version` is a bare `z.string()` shared with the local
 * standalone bundle, so it cannot be tightened here the way `PluginWhoami`'s
 * members are — but it is rendered into a terminal all the same, and a hostile
 * or compromised plane supplying an ANSI escape could repaint the status block
 * or hide a line. Control characters are stripped and the result bounded, so
 * the worst a plane can do to this surface is occupy its own field.
 */
function printable(value: string, max = 80): string {
  const stripped = value.replace(/[\p{Cc}\p{Cf}]/gu, '');
  return stripped.length > max ? `${stripped.slice(0, max)}…` : stripped;
}

export async function renderPolicyLine(dataDir: string, nowMs = Date.now()): Promise<string> {
  try {
    const cached = await createPolicyStore(dataDir).read();
    if (!cached) return '  policy     none cached';
    return `  policy     ${printable(cached.bundle.version)} (fetched ${ageLine(cached.fetchedAtMs, nowMs)})`;
  } catch {
    return '  policy     unreadable';
  }
}
