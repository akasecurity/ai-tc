import { readControlPlaneCredentialFile, readWorkspaceSettings } from '@akasecurity/persistence';
import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import type {
  AttachmentMode,
  AttachmentScope,
  AttachmentScopeEntry,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH,
  attachmentModeOf,
  controlPlaneName,
  isAttached,
  isAttachmentScopeValid,
  isHistorySyncConsentStale,
  isHistorySyncConsentValid,
  originOnly,
  parseAttachmentScope,
  resolveScope,
} from '@akasecurity/schema';

import { readForwardDrops } from './forward-drops.ts';
import type { ForwardFailureReason } from './forward-policy.ts';
import { readForwardHealth } from './forward-policy.ts';
import { readHistorySyncState } from './history-state.ts';
import { createPolicyStore } from './policy-store.ts';
import type { PolicySyncOutcome } from './policy-sync.ts';
import { readPostureReportState } from './posture-report-state.ts';
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

/**
 * How each attachment mode reads on the `mode` line: which activity the
 * attachment forwards, not everything the machine sends. The scoped line names
 * no kind of entry, because an entry may name a repository or an account and the
 * block under it lists whichever the record holds. An exhaustive Record, so a
 * mode added later fails typecheck here instead of rendering a line with a hole
 * in it.
 */
const MODE_LINES: Record<AttachmentMode, string> = {
  machine: 'machine (activity from anywhere on this machine)',
  scoped: 'scoped (activity only from what is enrolled)',
};

/**
 * What to do about a scope that forwards no activity: printed under the "nothing
 * enrolled yet" line (a record with no entries). The lines for a list that is
 * not stored spell out their own advice, and the lines for one this build cannot
 * read carry none.
 */
const ENROLL_HINT = '             (run `aka enroll` inside a work repository to add it)';

/**
 * The last line of every scope block: what the record does not limit. A scoped
 * attachment's record decides which activity is forwarded, not whether the
 * machine pulls its deployment's policy or sends it a device report.
 */
const NOT_LIMITED_LINE =
  '             the policy pull and the device report are not limited to what is enrolled';

/**
 * The note under a SCOPED machine's history numbers when the pass that wrote
 * them counted everything recorded on this machine, keyed on what that pass
 * recorded about its counts: nothing at all (a version of aka from before passes
 * recorded it, whose drain counted the whole machine in either mode), or a
 * machine-wide count (a pass that ran while this machine was attached
 * machine-wide, kept by a re-attach that made it scoped). An exhaustive Record,
 * so a mode added later fails typecheck here instead of printing no note.
 */
const WIDE_COUNTS_NOTES: Record<'unmarked' | Exclude<AttachmentMode, 'scoped'>, string> = {
  unmarked:
    '             (counted by an older version of aka, for everything recorded on this machine)',
  machine:
    '             (counted while attached machine-wide, for everything recorded on this machine)',
};

/**
 * The note under a MACHINE-WIDE attachment's history numbers when a scoped pass
 * wrote them: a re-attach that made the machine machine-wide kept the file (only
 * a detach removes it), so its totals cover only what was enrolled and would
 * read as the whole machine's. It goes once a pass runs and counts everything.
 */
const SCOPED_COUNTS_NOTE: readonly string[] = [
  '             (counted while attached as a personal device, for what was enrolled only;',
  '             the next pass counts everything recorded on this machine)',
];

/**
 * The note, if any, that goes under the history numbers: keyed on the live mode
 * and on what the pass that wrote the file says it counted. A machine-wide
 * attachment prints a note for one marker only, the scoped one; with none, or
 * the machine-wide one, its lines are as they always were.
 */
function countsNote(scoped: boolean, countedAs: AttachmentMode | undefined): readonly string[] {
  if (scoped) return countedAs === 'scoped' ? [] : [WIDE_COUNTS_NOTES[countedAs ?? 'unmarked']];
  return countedAs === 'scoped' ? SCOPED_COUNTS_NOTE : [];
}

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
      return [
        'AKA: standalone (not attached)',
        '  no control plane configured',
        ...failOpenLines(deps.dataDir, nowMs),
      ].join('\n');
    }
    const connection = settings.controlPlane;
    // The WIDE read: this block prints `keyPrefix`, which the narrow state
    // deliberately does not carry. It is a TERMINAL surface — `aka status` — so
    // nothing here crosses to a browser.
    const state = readControlPlaneCredentialFile(deps.settingsDir, connection);
    // The mode is read off the credential, the half of an attachment no settings
    // writer rewrites, and only off one this machine can use. An unusable
    // credential forwards nothing in either mode, so naming a mode for it would
    // describe forwarding that does not happen.
    const mode: AttachmentMode | undefined = state.usable
      ? attachmentModeOf(state.credential)
      : undefined;
    // The name is the label, or the endpoint when there is none. An endpoint is an
    // address, and the settings one is checked when settings are saved through the
    // product, not when the file is edited by hand or an overlay pins it, so it
    // goes through endpointForTerminal, which also keeps userinfo, a query and a
    // fragment off the screen. A label is free text and gets the plain strip.
    const plane =
      connection.label === undefined
        ? endpointForTerminal(controlPlaneName(connection))
        : printableForTerminal(controlPlaneName(connection));

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
      // And every one of them goes through `printableForTerminal`, which is
      // about the field's CONTENT rather than which fields appear. The
      // allow-list above decides what is rendered; it says nothing about what
      // those strings hold. None of these is authored by this machine — `label`
      // comes from `aka attach --label` or from a `settings.json` an
      // administrator can pin fleet-wide, and the endpoint and `keyPrefix` come
      // off the credential file — and all of them land in a status block a user
      // reads to decide whether their machine is managed. An ANSI escape in any
      // of them can repaint that block or hide a line.
      `  plane      ${plane}`,
      `  attached   ${printableForTerminal(connection.attachedAt, 40)}`,
    ];
    if (state.usable && state.credential.keyPrefix !== undefined) {
      // `max` matches the schema's own bound, so a conforming prefix is never
      // truncated and a longer one cannot outrun it.
      lines.push(`  key        ${printableForTerminal(state.credential.keyPrefix, 16)}…`);
    }
    if (!state.usable && state.reason === 'endpoint-mismatch') {
      lines.push(`  credential ${printableForTerminal(state.credentialEndpoint, 200)}`);
    }
    if (mode !== undefined) lines.push(`  mode       ${MODE_LINES[mode]}`);
    // With a label, `plane` names the label. The scope record is bound to the
    // endpoint by exact string, so the endpoint gets its own line and a user can
    // compare it with the one a record names. Without a label, `plane` is it.
    if (mode !== undefined && connection.label !== undefined) {
      lines.push(`  endpoint   ${printableForTerminal(connection.endpoint, 200)}`);
    }

    return [
      ...lines,
      // Only a scoped attachment is filtered by its scope. A machine-wide one
      // never reads the record, so listing it there would describe a filter
      // that is not applied.
      ...(mode === 'scoped'
        ? attachmentScopeLines(settings.attachmentScope, connection.endpoint)
        : []),
      ...policyLines(deps.dataDir, nowMs),
      ...forwardLines(deps.dataDir, nowMs),
      ...postureLines(deps.dataDir, nowMs),
      ...historyLines(deps.dataDir, settings, connection.endpoint, nowMs, mode === 'scoped'),
      ...failOpenLines(deps.dataDir, nowMs),
    ].join('\n');
  } catch {
    // A status renderer that throws is worse than one that says little.
    return 'AKA: status unavailable';
  }
}

/**
 * The enrolled scope of a SCOPED attachment, as `aka status` prints it.
 *
 * Exported so any command that lists the enrolled scope prints these same lines
 * rather than a second rendering of the same states, which could disagree with
 * this one.
 *
 * THE FORWARD VERDICT'S OWN READ. The record is read with parseAttachmentScope
 * and bound with isAttachmentScopeValid, the two halves resolveScope is built
 * from, and an entry is listed only when the key set resolveScope returns holds
 * its identity. So the block lists what a forward path forwards, once per
 * identity however often it is stored.
 *
 * ONE INPUT IT CANNOT SEE. The block reads the stored record alone. resolveScope
 * can also merge extra entries, identities that never live in settings.json, into
 * the key set it returns, and this block is not given them. It matches what is
 * forwarded because no caller adds extra entries to the key set today. A caller
 * that ever does must give this block the same entries, or a forward path would
 * send an identity the block does not list.
 *
 * Each state that forwards no activity has its own line, because each has its own
 * cause: no list stored (an older settings writer dropped it, or an attach
 * stopped before writing it), a list this version cannot read (damaged, or
 * written by a newer build), a record for another deployment, or a record with
 * nothing in it yet. The first two are told apart on purpose: the missing list
 * says what to run, and the unreadable one deliberately gives no advice. Entries
 * this version cannot read are counted and never printed: one written by a newer
 * build is not this build's to describe. A record that names no account is said
 * to be one, because the next scoped attach cannot tell whose it is and starts it
 * empty.
 *
 * EVERY BLOCK ENDS WITH WHAT THE RECORD DOES NOT LIMIT. The record decides which
 * activity is forwarded, not whether the machine pulls its deployment's policy or
 * sends it a device report. So the last line says so in every state, and a block
 * that says no activity is sent does not read as a machine that sends nothing.
 *
 * Every stored string goes through printableForTerminal. The schema already
 * refuses control characters in an identity or a label; the strip is the layer
 * that holds whatever a settings file actually carries. The record's address
 * goes through endpointForTerminal, which also keeps userinfo, a query or a
 * fragment off the screen.
 *
 * `endpoint` is the deployment the machine is attached to now. Pure; no I/O.
 */
export function attachmentScopeLines(raw: unknown, endpoint: string): string[] {
  return [...scopeStateLines(raw, endpoint), NOT_LIMITED_LINE];
}

/** The lines for the record's state, before the line every block ends with. */
function scopeStateLines(raw: unknown, endpoint: string): string[] {
  // No list at all and a list this build cannot read are told apart before
  // anything is parsed: parseAttachmentScope answers undefined for both, and
  // what to do about one is not what to do about the other.
  if (raw === undefined || raw === null) {
    return [
      '  scope      no enrolled list is stored — no activity is sent',
      '             (run `aka enroll` inside a work repository to add it; an aka older than 0.9.16 also',
      '             drops the list when it saves settings)',
    ];
  }
  const record = parseAttachmentScope(raw);
  if (record === undefined) {
    return [
      '  scope      the enrolled list cannot be read by this aka — it sends no activity under it',
      '             (it may have been written by a newer aka)',
    ];
  }
  if (!isAttachmentScopeValid(raw, endpoint)) {
    return [
      `  scope      recorded for another deployment (${endpointForTerminal(record.endpoint)})`,
      '             — no activity is sent here (run `aka enroll` to enroll for this one)',
    ];
  }
  const forwarded = resolveScope({ mode: 'scoped', scope: raw, endpoint }).keys;
  const listed = new Set<string>();
  const rows: string[] = [];
  for (const entry of record.entries) {
    // The filter is redundant while resolveScope keeps every parsed entry. It stays
    // as the literal form of "listed only when the verdict's key set holds the
    // identity", so this block stays honest if resolveScope ever filters. It sees
    // the stored record only, not extra entries (see the note above).
    if (!forwarded.has(entry.identity) || listed.has(entry.identity)) continue;
    listed.add(entry.identity);
    rows.push(`             ${entryLine(entry)}`);
  }
  const lines =
    rows.length === 0
      ? ['  scope      nothing enrolled yet — no activity is sent', ENROLL_HINT]
      : [
          `  scope      ${count(rows.length)} enrolled — activity anywhere else stays on this machine`,
          ...rows,
        ];
  const unread = unreadEntries(raw, record);
  if (unread > 0) {
    const noun = unread === 1 ? 'entry' : 'entries';
    lines.push(`             ${count(unread)} ${noun} this version cannot read — not sent`);
  }
  if (!named(record.tenantName) || !named(record.userEmail)) {
    lines.push('             not tied to an account — the next `aka attach` starts it empty');
  }
  return lines;
}

/** One enrolled identity: its key, its label when it has one, and the day it was enrolled. */
function entryLine(entry: AttachmentScopeEntry): string {
  // `max` is the schema's own bound on an identity, so a conforming key is never cut.
  const identity = printableForTerminal(entry.identity, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  const label = entry.label === undefined ? '' : ` (${printableForTerminal(entry.label)})`;
  return `${identity}${label}, enrolled ${printableForTerminal(entry.enrolledAt.slice(0, 10))}`;
}

/** How many stored entries validation dropped from a record that itself parsed. */
function unreadEntries(raw: unknown, read: AttachmentScope): number {
  const stored =
    typeof raw === 'object' && raw !== null && 'entries' in raw && Array.isArray(raw.entries)
      ? raw.entries.length
      : read.entries.length;
  return stored - read.entries.length;
}

/** A binding field that names someone: present and not empty. */
function named(value: string | undefined): boolean {
  return value !== undefined && value !== '';
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
 * What the live forward gave up on, if anything.
 *
 * Rendered INDEPENDENTLY of breaker state, and that is the whole reason it
 * exists for its original cause: the machine a batch-budget drop happens on
 * is the one whose breaker is closed. A plane that answers every request
 * successfully but slowly produces no failures, so every other line in this
 * block reads healthy while the tail of each batch is discarded. Appended to
 * all three of `forwardLines`' outcomes rather than to one — the second cause
 * `forward-drops.ts` now also counts (the breaker opening mid-retry with
 * nothing left to isolate) DOES move the breaker's own file, but that alone
 * says nothing was delivered, never how much; this line is still the only
 * place that number is rendered, so it stays independent of which of the two
 * caused it.
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
    `             at least ${String(drops.droppedForwards)} events dropped by the ` +
      `live forward, last ${ageLine(drops.lastDropAtMs, nowMs)}`,
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
 *
 * On a SCOPED attachment a pass counts only its scope's rows, and records in
 * the file that it did. A file that does not say so was counted for
 * everything recorded on this machine: by an older version of aka, whose drain
 * counted the whole machine in either mode, or by a pass that ran while this
 * machine was attached machine-wide. Read bare, those numbers would describe a
 * queue far larger than the one a scoped drain sends, and one that never
 * completes, so every line with numbers then carries a note saying which. The
 * note describes the pass that wrote the file, and goes once a pass that counts
 * through the scope writes it again. While an older plugin's drain still runs
 * beside a newer one, each pass leaves a line that is true of that pass.
 *
 * A scoped attachment with nothing enrolled for this deployment sends no
 * history at all, and says so instead of any number. That is read from the
 * scope in force now, through the settings this block already read and the
 * endpoint the drain resolves the scope against, not from the file: a pass over
 * an empty scope records "complete" with nothing sent, which would read as a
 * finished drain rather than one with nothing it may send. A refusal the last
 * pass recorded still comes first: while the deployment refuses this machine's
 * key, enrolling resumes nothing, and re-attaching is the step that does.
 *
 * A machine-wide attachment prints none of this, with one exception: a file
 * marked as counted through a scope, which a re-attach that made the machine
 * machine-wide left behind. Its totals cover only what was enrolled, and read
 * bare they would pass for the whole machine's until the next pass that runs
 * rewrites the file, so each line with numbers carries a note saying so and
 * that the next pass counts everything. A machine-wide file with the other
 * marker, or none, prints exactly as it always has.
 */
function historyLines(
  dataDir: string,
  settings: WorkspaceSettings,
  endpoint: string,
  nowMs: number,
  scoped: boolean,
): string[] {
  // A grant PAUSED by a widening is not the same news as no grant, and the third
  // surface to say so. After a payload bump every machine that opted in holds a
  // stale grant, so a bare "not shared" tells a user who did opt in that they
  // did not — with no hint that a real grant exists or what widened it.
  if (isHistorySyncConsentStale(settings.historySyncConsent, endpoint)) {
    return [
      '  history    paused — your grant predates a change to what is sent',
      '             (run `aka sync-history --on` to grant it again)',
    ];
  }
  // Absent grant is the overwhelmingly common case, and it is not a fault: this
  // is opt-in, and a machine that never opted in should read as settled rather
  // than as pending.
  if (!isHistorySyncConsentValid(settings.historySyncConsent, endpoint)) {
    return ['  history    not shared (run `aka sync-history --on`)'];
  }

  const state = readHistorySyncState(dataDir);
  // A refused key stops the drain whatever is enrolled, so it is said first,
  // ahead of the nothing-to-send line below. It never printed a number, so
  // moving it up changes no line on any attachment.
  if (state?.lastOutcome === 'refused') {
    return [
      "  history    stopped — that deployment refused this machine's key",
      '             re-attach to resume',
    ];
  }
  // Nothing enrolled for this deployment: no history is sent, whatever the file
  // says. See the docblock for why this is read from the scope, not the file.
  if (
    scoped &&
    resolveScope({ mode: 'scoped', scope: settings.attachmentScope, endpoint }).keys.size === 0
  ) {
    return ['  history    nothing to send — the scope above forwards no activity'];
  }
  // Granted but nothing recorded yet: the grant is real and the first pass has
  // not run. Saying "waiting" rather than "0 sent" avoids reporting a number
  // that no pass produced.
  if (state === null) return ['  history    sharing — waiting for the first pass'];

  const sent = count(state.sentTotal);
  const total = count(state.sentTotal + state.pendingTotal);
  const skipped = state.skippedTotal > 0 ? `, ${count(state.skippedTotal)} could not be sent` : '';
  // Whether the population the pass counted is the one this attachment sends:
  // see the docblock.
  const caveat = countsNote(scoped, state.countsScope);

  if (state.lastOutcome === 'unreachable') {
    return [
      `  history    paused — deployment unreachable, last tried ${ageLine(state.lastPassAtMs, nowMs)}`,
      `             ${sent} of ${total} records sent${skipped}`,
      ...caveat,
    ];
  }
  if (state.phase === 'complete' && state.pendingTotal === 0) {
    return [`  history    complete — ${sent} records sent${skipped}`, ...caveat];
  }
  return [`  history    sending — ${sent} of ${total} records sent${skipped}`, ...caveat];
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
 * Whether this device's hourly posture self-report is LANDING — the thing the
 * control plane actually grades a device on, and until now the one send whose
 * outcome nothing on the machine wrote down.
 *
 * The send goes through the forward breaker, so a refusal moves the breaker's
 * file too — but that file is rewritten by every forward and cleared by the
 * next success, so a posture send refused an hour ago is "disproved" by a tool
 * call that landed a minute ago. The outcome is therefore recorded on its own
 * and rendered with its own age. The age is the point: the plane grades on
 * freshness, and a line that only said "reported" would read healthy on a
 * machine whose last landed report is days old.
 *
 * Same remediation split as the sync and forward lines, and for the same
 * reason: a 401 is fixed by `attach`, a 403 is not, and a wrong instruction is
 * worse than none. The other five name what was observed and stop, because
 * re-attaching fixes none of them. `rejected` is the deployment ANSWERING — a
 * 4xx body refusal, this build's snapshot shape not being one it accepts — so
 * it is not folded into `unreachable`; a 404 on the posture route carries no
 * verdict and reads as `unreachable`. `route-absent` and `invalid-request` are
 * named because the policy can return them, not because today's posture send
 * raises either.
 *
 * An exhaustive Record, not a switch with a default: a reason added to the
 * policy that this table does not name fails typecheck instead of rendering a
 * line with a hole in it.
 */
const POSTURE_FAILURE_LINES: Record<ForwardFailureReason, string> = {
  unauthorized: 'key rejected',
  forbidden: 'access refused',
  unreachable: 'control plane unreachable',
  'breaker-open': 'skipped while the forward breaker was open',
  'invalid-request': 'this build refused to send its own snapshot',
  'route-absent': 'that deployment has no posture route',
  rejected: 'that deployment refused this snapshot',
};

function postureLines(dataDir: string, nowMs: number): string[] {
  const state = readPostureReportState(dataDir);
  // No file is also what a freshly attached device looks like for its first
  // session, and a device whose hourly attempt has not fired yet. Phrased as
  // what is known, never as health.
  if (!state) return ['  posture    no report recorded yet'];
  const age = ageLine(state.atMs, nowMs);
  if (state.outcome === 'ok') return [`  posture    reported (${age})`];
  const lines = [
    `  posture    NOT REPORTED — ${POSTURE_FAILURE_LINES[state.outcome]} (last tried ${age})`,
  ];
  if (state.outcome === 'unauthorized' || state.outcome === 'forbidden') {
    lines.push(`             ${REFUSAL_LINES[state.outcome]}`);
  }
  return lines;
}

/**
 * How often a hook has thrown and fallen open on this machine, if ever.
 *
 * A fail-open is silent by contract — no output, exit 0, the session never
 * notices — so a machine whose hooks throw on every call reads exactly like
 * one whose hooks run: nothing is scanned, nothing is forwarded, and every
 * other line here describes a control plane that is simply not being asked.
 * The count the catch writes is the one local trace. Rendered in the attached
 * AND the standalone block, because the guarantee it describes holds on both,
 * and read from the SDK's own file rather than plumbed a value, because the
 * process that failed open exited long before anyone ran `aka status`.
 *
 * "at least", because concurrent hooks increment without a lock — the same
 * floor the forward drop tally states.
 */
function failOpenLines(dataDir: string, nowMs: number): string[] {
  const tally = readHookFailOpens(dataDir);
  if (!tally) return [];
  return [
    `  hooks      failed open at least ${String(tally.failOpens)} time(s), ` +
      `last ${ageLine(tally.lastAtMs, nowMs)}`,
  ];
}

/**
 * A string from outside this process, made safe to print in a terminal.
 *
 * Control and format characters are stripped and the result is bounded, so an
 * ANSI escape cannot repaint the block around it or hide a line, and the worst a
 * hostile value can do is occupy its own field. A label from an administrator's
 * overlay, a policy version from a control plane, a repository read back from
 * settings.json: none of them was authored by the code printing it.
 *
 * Exported so a command that echoes such a string can strip it with this one
 * function rather than a copy that could drift.
 */
export function printableForTerminal(value: string, max = 80): string {
  const stripped = value.replace(/[\p{Cc}\p{Cf}]/gu, '');
  return stripped.length > max ? `${stripped.slice(0, max)}…` : stripped;
}

/** What endpointForTerminal prints in place of an address it will not echo. */
const ENDPOINT_NOT_SHOWN = 'address not shown';

/**
 * A deployment address read back from a file, made safe to print in a terminal.
 *
 * The schema holds a stored address to no more than being a non-empty string,
 * so it can carry what an address must never show: userinfo, a query, a
 * fragment. An http or https address with none of them is printed as stored,
 * through printableForTerminal, so a spelling that differs from another address
 * (a trailing slash, the case of the host) stays visible. One that carries any
 * of them is printed as its origin alone, with "rest not shown" after it.
 * Anything else, a string that does not parse as a URL or one with another
 * scheme, is printed as ENDPOINT_NOT_SHOWN. Never throws.
 *
 * Exported so a command that echoes an address it read from a file prints it
 * with this one function rather than a copy that could drift.
 */
export function endpointForTerminal(endpoint: string): string {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return ENDPOINT_NOT_SHOWN;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return ENDPOINT_NOT_SHOWN;
  // The serialized URL equals scheme, host and path exactly when the address
  // carries no userinfo, query or fragment, an empty query or fragment included.
  const bare = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  return parsed.href === bare
    ? printableForTerminal(endpoint, 200)
    : `${printableForTerminal(originOnly(endpoint), 200)}, rest not shown`;
}

/**
 * The policy cache half, async because the store is.
 *
 * Kept OUT of `renderAttachedStatus` so that function can stay synchronous and
 * total: a slash-command entry can render the connection block with no awaits at
 * all, and only pay for the cache read when it wants the version line.
 *
 * `PolicyBundle.version` is a bare `z.string()` shared with the local standalone
 * bundle, so it cannot be tightened the way `PluginWhoami`'s members are, and a
 * hostile or compromised plane could put an escape in it. It is printed through
 * printableForTerminal.
 */
export async function renderPolicyLine(dataDir: string, nowMs = Date.now()): Promise<string> {
  try {
    const cached = await createPolicyStore(dataDir).read();
    if (!cached) return '  policy     none cached';
    return `  policy     ${printableForTerminal(cached.bundle.version)} (fetched ${ageLine(cached.fetchedAtMs, nowMs)})`;
  } catch {
    return '  policy     unreadable';
  }
}
