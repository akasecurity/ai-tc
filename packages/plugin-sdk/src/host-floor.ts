/**
 * Host-floor compatibility: is the Claude Code running this session new enough
 * for every hook event AKA's manifest registers?
 *
 * WHY THIS EXISTS. A host that does not recognise an event in `hooks.json` does
 * not reject the file — it drops that ENTRY and loads the rest ("unknown hook
 * event; entry ignored"). So an old host leaves the plugin looking healthy while
 * the protection behind the dropped entry silently does not exist. Nothing at
 * runtime says so, and the host's own diagnostic reads the entry as a typo
 * ("Check spelling and capitalization"), which invites deleting it — i.e.
 * removing the enforcement instead of updating the host.
 *
 * WHAT IT MAY NOT DO. Warn on a version it is not sure about. A false "update
 * Claude Code" on a correct install costs more than a missed warning, so every
 * unknown here — no transcript, no version-bearing record, an unparseable
 * string — resolves to NO gaps rather than to a guess.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  compareBinaryVersions,
  ensureDataDirSync,
  isParseableBinaryVersion,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';
import type { HostFeatureGap, HostVersionCache } from '@akasecurity/schema';

import { type ModelFromRecord, modelFromTranscriptTail } from './model-governance.ts';

/**
 * The protections whose hook events postdate some Claude Code AKA still runs on.
 *
 * Unqualified names in this module are Claude Code's; every other harness
 * spells its own, and Codex's sit at the foot of this file. A guard names one
 * table or the other, never both, so the two cannot be crossed by accident.
 *
 * A const object rather than a TS `enum`: `scan-worker.ts` is loaded by raw Node
 * under type stripping, where an `enum` emits runtime code instead of erasing.
 */
export const HOST_FEATURE = {
  ModelSwitch: 'model-switch',
  VaultPointerDisplay: 'vault-pointer-display',
} as const;

export type HostFeature = (typeof HOST_FEATURE)[keyof typeof HOST_FEATURE];

export interface HostFloorRow {
  /** Ordinary-language name, for the on-demand surfaces only. */
  readonly label: string;
  /** The `hooks.json` events this protection is delivered through. */
  readonly hookEvents: readonly string[];
  /**
   * First host version that actually DELIVERS every one of those events —
   * which is not always the version that first recognised them. A host can
   * parse an event name, list it among its loaded hooks, and still never reach
   * the handler (Antigravity's `Stop` did exactly that until 1.1.10). Read the
   * release that made the event FIRE, not the one that introduced the name.
   */
  readonly since: string;
}

/**
 * Each floor, keyed so that a member added to HOST_FEATURE is a compile error
 * here rather than a row somebody forgets.
 *
 * Every `since` is read from the host changelog's own "Added …" line, never
 * inferred from when AKA adopted the event. Confirm one before editing it: a
 * `since` that does not parse makes its row silently never fire, because
 * `compareBinaryVersions` answers 0 for an unparseable input and 0 is not < 0.
 */
export const HOST_FLOORS: Record<HostFeature, HostFloorRow> = {
  [HOST_FEATURE.ModelSwitch]: {
    label: 'model-switch protection',
    hookEvents: ['PreModelSwitch', 'PostModelSwitch'],
    since: '2.1.251',
  },
  [HOST_FEATURE.VaultPointerDisplay]: {
    label: 'vault pointer display',
    hookEvents: ['MessageDisplay'],
    since: '2.1.152',
  },
};

/**
 * Events old enough that no supported host is missing them.
 *
 * This is the other half of a partition, not a convenience list: every event in
 * `hooks.json` must be either here or named by a HOST_FLOORS row, and the guard
 * over that is what catches a newly-registered host-gated event arriving with no
 * floor — the defect this whole module exists to report.
 */
export const BASELINE_HOOK_EVENTS: readonly string[] = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'Stop',
];

/**
 * The host version stamped on one transcript record, or undefined.
 *
 * Deliberately not filtered by record `type`. Every type that carries `version`
 * is host-written, and a type allowlist goes stale the moment the host adds a
 * record kind — failing toward silence in a way nothing would notice.
 */
export const hostVersionFromRecord: ModelFromRecord = (record) => {
  if (typeof record !== 'object' || record === null) return undefined;
  const { version } = record as { version?: unknown };
  return typeof version === 'string' && version !== '' ? version : undefined;
};

/**
 * The host version named by the LAST record in a transcript that names one.
 *
 * Reuses `modelFromTranscriptTail` rather than re-rolling a reader: the bound
 * (256 KiB), the looped positional read, the dropped torn first line and the
 * newest-first scan are all identical requirements here, and a transcript is a
 * file this repo has measured at up to 133 MB. Only the per-record extractor
 * differs, which is already that function's parameter.
 */
export function hostVersionFromTranscript(transcriptPath: string | undefined): string | undefined {
  return modelFromTranscriptTail(transcriptPath, hostVersionFromRecord);
}

/**
 * The protections this host version is too old for, in declaration order.
 *
 * Empty for a current host AND for a version this cannot read, which collapses
 * "fine" and "unknown" into one silent answer by construction — so no caller can
 * branch on "unknown" and decide to warn anyway.
 */
export function hostFloorGaps(hostVersion: string | undefined): HostFeatureGap[] {
  if (hostVersion === undefined) return [];
  const gaps: HostFeatureGap[] = [];
  for (const [feature, row] of Object.entries(HOST_FLOORS)) {
    // An unparseable version — the host's or the row's — needs no guard of its
    // own here: `compareBinaryVersions` answers 0 for one, and 0 is not < 0, so
    // it yields no gap. An explicit re-check reads as defence and is dead code,
    // absorbing the very mutation that would prove this silent. The behaviour is
    // pinned in host-floor.test.ts instead, which is what would catch that
    // comparator contract changing under us.
    if (compareBinaryVersions(hostVersion, row.since) < 0) {
      gaps.push({ feature, label: row.label, since: row.since });
    }
  }
  return gaps;
}

/** The highest floor among a set of gaps — the version that clears all of them. */
export function requiredHostVersion(gaps: readonly HostFeatureGap[]): string | undefined {
  let highest: string | undefined;
  for (const gap of gaps) {
    if (highest === undefined || compareBinaryVersions(gap.since, highest) > 0) highest = gap.since;
  }
  return highest;
}

/**
 * The in-session notice, or null when there is nothing to say.
 *
 * Generic on purpose. The remedy is the same whichever protection is missing, so
 * naming one buys information rather than action — and a message that names no
 * hook event and no file cannot be read as pointing at something to delete. The
 * detail lives on `aka status`, which this line points at.
 */
export function hostFloorNotice(hostVersion: string | undefined): string | null {
  if (hostVersion === undefined) return null;
  const gaps = hostFloorGaps(hostVersion);
  const required = requiredHostVersion(gaps);
  if (required === undefined) return null;
  return (
    `This Claude Code (${hostVersion}) is older than AKA needs — some of AKA's ` +
    `protections are inactive in this session. Update Claude Code to ${required} ` +
    `or newer to turn them on. Everything else AKA does is working normally. ` +
    `Run \`aka status\` for detail.`
  );
}

/**
 * The newest Claude Code this AKA build is known to have run against.
 *
 * DELIBERATELY NOT AN INTERRUPT. A ceiling has to be bumped every release or it
 * starts firing on every up-to-date user within days, which trains people to
 * ignore the notice — the same failure as a flaky CI check. So nothing consults
 * this on a hook path: it reaches only `aka status` and /aka:health, pages a
 * person opens BECAUSE something already feels wrong. Their visit is the signal,
 * so no fault detection is needed and a stale value costs a redundant sentence
 * on a page rather than a false alarm mid-session.
 *
 * Bump it at release time when the host has moved on.
 */
export const MAX_TESTED_HOST = '2.1.260';

/**
 * The "newer than tested" line, or null when the host is within range.
 *
 * Silent on an unknown version for the same reason everything else here is:
 * an unparseable string compares equal, and equal is not greater.
 */
export function hostCeilingNotice(hostVersion: string | undefined): string | null {
  if (hostVersion === undefined) return null;
  if (compareBinaryVersions(hostVersion, MAX_TESTED_HOST) <= 0) return null;
  return (
    `This Claude Code (${hostVersion}) is newer than AKA has been tested against ` +
    `(${MAX_TESTED_HOST}). If something here looks wrong, that is the likely ` +
    `cause — we'll look into it.`
  );
}

/**
 * The host-compatibility block for the ON-DEMAND surfaces (`aka status`,
 * /aka:health), as lines.
 *
 * This is where the per-protection detail lives, and the only place it does.
 * The in-session notice stays generic — the remedy is the same whichever
 * protection is missing, so naming one there buys information rather than
 * action, and a message that names no hook event cannot be misread as pointing
 * at something to delete. Here the reader has come looking, so "which
 * protection?" is exactly the question to answer.
 *
 * Reports "unknown" rather than guessing: the cache is only written by a hook
 * that actually observed a version, so an absent one means no turn has completed
 * on this machine yet.
 */
export function hostCompatibilityLines(cache: HostVersionCache | null): string[] {
  // NOTHING, not "unknown". Only the Claude Code plugin's hooks ever write this
  // cache, so a Codex-only or CLI-only machine would otherwise be told forever
  // about a product it does not run.
  if (cache === null) return [];
  const lines = [`Claude Code: ${cache.version} (last seen)`];
  const gaps = hostFloorGaps(cache.version);
  const required = requiredHostVersion(gaps);
  if (required !== undefined) {
    lines.push(`  inactive: ${gaps.map((g) => g.label).join(', ')}`);
    lines.push(`  update Claude Code to ${required} or newer to turn them on`);
  }
  const ceiling = hostCeilingNotice(cache.version);
  if (ceiling !== null) lines.push(`  ${ceiling}`);
  return lines;
}

/** One file holding the newest host version seen on this machine. */
const HOST_VERSION_MARKER = 'host-version.json';

/**
 * Record the host version a hook observed.
 *
 * Best-effort and silent, like every other marker on a hook path: a failed write
 * costs the on-demand surfaces a reading, never a wrong decision. Refuses an
 * unparseable version rather than caching it, because `aka status` would then
 * report a string no comparison can act on.
 */
export function recordHostVersion(dataDir: string, version: string | undefined): void {
  if (version === undefined || !isParseableBinaryVersion(version)) return;
  try {
    // Keep the max. Two installs can share one machine, and this file is what
    // the on-demand surfaces read: letting an older one win would tell a user
    // whose host is current to update it. Keeping the max also makes the repeat
    // write a no-op, so the hot path stops rewriting a byte-identical payload on
    // every tool call.
    //
    // EVENTUAL, AND IT DOES NOT SELF-HEAL WITHIN A SESSION. This is a
    // read-modify-write, and only the WRITE is indivisible (§6's distinction):
    // two sessions can both read null, the newer publish, and the older publish
    // over it — the max-keeping above never runs, because both compared against
    // null rather than against each other.
    //
    // The loser then PERSISTS. The one caller sits behind a once-per-session
    // claim it KEEPS on a successful observation, so the newer session never
    // writes again: the stale value survives until some new session on that host
    // observes it — bounded by the claim TTL for a resumed session, and unbounded
    // if the newer host is simply not started again.
    //
    // What earns that is the blast radius rather than the duration: nothing on
    // the hook path reads this file, so a stale value costs a wrong line on
    // `aka status` and /aka:health and nothing else. Making it absolute means
    // moving this call outside the claim, which is a transcript read per tool
    // call — the cost the ordering above exists to avoid. See §6, which names
    // this file among the unlocked read-modify-writes on exactly this reasoning.
    const current = readHostVersionCache(dataDir);
    if (current !== null && compareBinaryVersions(version, current.version) <= 0) return;
    const cache: HostVersionCache = { version, observedAt: Date.now() };
    ensureDataDirSync(dataDir);
    // The shared publisher, not a raw write: tmp+rename makes the publish
    // indivisible, so a concurrent `aka status` read cannot land mid-write and
    // report "unknown"; it also refuses to follow a symlink planted at the
    // target and re-applies owner-only mode to an existing file.
    writeOwnerOnlyFileSync(join(dataDir, HOST_VERSION_MARKER), JSON.stringify(cache));
  } catch {
    // The surfaces fall back to silence, which is the honest reading.
  }
}

/**
 * The cached host version, or null on absence, a torn read, or anything that
 * does not parse as the shape written above.
 */
export function readHostVersionCache(dataDir: string): HostVersionCache | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(join(dataDir, HOST_VERSION_MARKER), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const { version, observedAt } = parsed as { version?: unknown; observedAt?: unknown };
    if (typeof version !== 'string' || !isParseableBinaryVersion(version)) return null;
    if (typeof observedAt !== 'number' || !Number.isFinite(observedAt)) return null;
    return { version, observedAt };
  } catch {
    return null;
  }
}

/**
 * CODEX. The same partition, for a host that reaches every one of these
 * decisions differently — so none of the reasoning above transfers by default.
 *
 * WHAT AN UNRECOGNISED EVENT COSTS HERE. The same silent absence, by a
 * different mechanism. Codex parses `hooks.json` into a struct whose per-event
 * fields are named ones (`PreToolUse`, `SessionStart`, …); that struct does not
 * opt into rejecting unknown fields, while the file wrapper around it does. So
 * an event name Codex does not recognise is dropped from the parse and the rest
 * of the file loads — the plugin installs clean and the protection behind that
 * entry is simply not there. A misspelling at the TOP level of the file is the
 * loud case instead, and is not what this table guards.
 *
 * WHERE A VERSION COMES FROM, AND WHY NOTHING READS ONE YET. Codex puts its
 * version in exactly one place: the `session_meta` record that opens a rollout
 * file, as `payload.cli_version`. It is written when the session is CREATED and
 * is not rewritten when one is resumed — a resumed session appends to the same
 * file and adds no second `session_meta` — so the version at the head of a
 * transcript names the host that STARTED that session, which on any resume is
 * not the host running now. Two consequences for anyone adding a row below:
 * the tail scanner the Claude Code side uses is the wrong reader twice over
 * (wrong end of the file, and its byte bound cannot reach line 1 of a long
 * transcript at all), and an observation is only sound on a session the host
 * reported as a fresh start — `SessionStart` carries that as `source`, whose
 * values are `startup`, `resume`, `clear`, `compact` and `fork`. Only the first
 * of those licenses reading the head record as the running host.
 */
export const CODEX_HOST_FEATURE = {} as const;

export type CodexHostFeature = (typeof CODEX_HOST_FEATURE)[keyof typeof CODEX_HOST_FEATURE];

/**
 * Codex floors — EMPTY, and that is a finding rather than an omission.
 *
 * The event set GREW, so "0.117.0 knew all five" is not on its own a reason for
 * an empty table — a host older than that reads a `hooks.json` and silently
 * drops what it does not know, which is the whole failure this guards. Read
 * from `HookEventName` in the host's own `protocol.rs` at each tag:
 *
 *     0.114.0   SessionStart, Stop
 *     0.115.0   SessionStart, Stop
 *     0.116.0   + UserPromptSubmit
 *     0.117.0   + PreToolUse, PostToolUse      (all five this plugin registers)
 *     0.122.0   + PermissionRequest
 *
 * What makes the table empty is the FEATURE GATE rather than that table. The
 * `codex_hooks` feature ships `Stage::UnderDevelopment, default_enabled: false`
 * from 0.117.0 through 0.123.0, and 0.124.0 is the first release carrying
 * `Stage::Stable, default_enabled: true` (the key is spelled `hooks` now, with
 * `codex_hooks` kept as a legacy alias). So a host that runs hooks without
 * anyone opting in by hand is 0.124.0 or newer, and every one of those has all
 * five — along with the compaction pair, the subagent pair, `SessionEnd`,
 * `Interrupt` and `PermissionRequest`, none of which this plugin registers.
 *
 * One window is genuinely exposed and is named rather than denied: 0.114.0
 * through 0.116.0 (2026-03-11 to 2026-03-25) predate the features crate
 * entirely, so hooks there are not gated at all and an incomplete event set is
 * reachable by default rather than by opt-in. A floor row would describe that
 * window correctly — and would still warn nobody, because nothing reads a Codex
 * version yet (see the note above this table on why that read is not sound).
 * That is the trade this empty table makes, not a claim the window is empty.
 *
 * The partition guard over this table is what keeps it honest: registering a
 * newer event fails CI until the version that introduced it is decided here.
 *
 * Adding the first row means adding its `CODEX_HOST_FEATURE` member in the same
 * edit. The annotation below does NOT enforce that while the table is empty:
 * `CodexHostFeature` is `never`, so `Record<CodexHostFeature, HostFloorRow>`
 * collapses to `{}` and TypeScript accepts any non-nullish value — a malformed
 * row typechecks clean. The codex plugin's manifest guard carries the row-shape
 * case that covers the gap until a member exists.
 *
 * Read the `since` off the host's own release history when that day comes, and
 * write the earliest version that HAS the event, prerelease included. Codex
 * ships most builds as prereleases, and a release outranks every prerelease of
 * the same number — so a floor written as `X.Y.0` reports a gap for every
 * `X.Y.0-alpha.N` user, including the ones whose build already carries the
 * feature.
 */
export const CODEX_HOST_FLOORS: Record<CodexHostFeature, HostFloorRow> = {};

/**
 * The Codex events old enough that no supported host is missing them.
 *
 * The other half of the partition, exactly as on the Claude Code side: an event
 * in that plugin's `hooks.json` is either named here or carries a floor row.
 */
export const CODEX_BASELINE_HOOK_EVENTS: readonly string[] = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'Stop',
];

/**
 * ANTIGRAVITY. The same partition again, for the host that reaches every one of
 * these decisions differently a THIRD time — so, as with Codex, none of the
 * reasoning above transfers by default.
 *
 * THE FAIL-CLOSED QUESTION, ANSWERED FIRST, BECAUSE IT DECIDES HOW BAD THIS IS.
 * This host reads a hook that exits non-zero, is killed on its timeout, or
 * prints nothing as a `deny` on every tool call, which is why the adapter always
 * prints an explicit allow. The obvious worry is that an event this host does
 * not recognise therefore degrades to DENIAL rather than to absence — i.e. that
 * a stale host would wedge every tool call rather than quietly drop a
 * protection. It does not, and the distinction is that the fail-closed reading
 * applies to a hook that RAN. An unrecognised event name is dropped from the
 * manifest, so no process is ever spawned for it, so there is no exit code and
 * no empty stdout for the host to interpret; the tool call follows the host's
 * own permission flow exactly as it would with no plugin installed. The failure
 * here is therefore the SAME silent absence the other two hosts have, and this
 * host is not the sharper case on that axis.
 *
 * WHERE A VERSION COMES FROM: NOWHERE, AND THAT IS THE FINDING. The Claude Code
 * reader does not transfer, and neither does the Codex one, because this host
 * publishes its version to a session through no channel at all. Three were
 * checked and each is negative:
 *
 *   - THE HOOK PAYLOAD. The host documents one closed set of common fields
 *     delivered to every event — `conversationId`, `workspacePaths`,
 *     `transcriptPath`, `artifactDirectoryPath` and `modelName`. Note the last
 *     one: the payload is not merely sparse, it carries a per-invocation fact
 *     the host had to look up, and still carries no host version.
 *   - THE TRANSCRIPT. Its records are FLAT — `source`, `type`, `created_at`,
 *     `status`, `step_index`, and optionally `content`, `thinking`,
 *     `tool_calls`, `exit_code`, `truncated_fields`. There is no header record
 *     of any kind, so Codex's `session_meta.cli_version` has no counterpart and
 *     the Claude Code trick of a version stamped on every record has nothing to
 *     read. Both ends of the file were considered; neither carries one.
 *   - THE HOST ENV. What this host exports is provider selection
 *     (`GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_GEMINI_BASE_URL`). No version var.
 *
 * A fourth avenue — spawning the CLI to ask it — is the one `hostCliVersion()`
 * already covers at INSTALL time and is unsound inside a session for the reason
 * it is unsound on the other hosts: it reports the binary on PATH rather than
 * the process running this turn. On this host it is worse than unsound, because
 * a spawn is a blocking stretch on a hook thread whose watchdog cannot preempt
 * it, and a hook that outlasts the host is a denied tool call.
 *
 * SO NOTHING BELOW HAS A RUNTIME READER, and none is wired. `hostFloorGaps`
 * reads the Claude Code table alone; that is deliberate, not an omission. The
 * table is still worth stating, for the reason the next paragraph gives.
 *
 * WHERE IT WOULD BE OBSERVED AND SAID, if a reader ever appears, so that work
 * does not start from scratch. `PreInvocation` carries `invocationNum`, a
 * 0-indexed counter, so `invocationNum === 0` identifies a genuinely fresh first
 * invocation — the equivalent of the fresh-start gate Codex needs and the
 * soundness Claude Code gets from firing after a write. And `PreInvocation` is
 * the one place a line can be SAID: its stderr is already the channel two other
 * notices use, while `PreToolUse` has no message channel at all (its `reason`
 * accompanies a deny, so saying anything there means denying the call).
 */
export const ANTIGRAVITY_HOST_FEATURE = {
  EndOfTurnCapture: 'end-of-turn-capture',
} as const;

export type AntigravityHostFeature =
  (typeof ANTIGRAVITY_HOST_FEATURE)[keyof typeof ANTIGRAVITY_HOST_FEATURE];

/**
 * Antigravity floors — ONE row, and unlike the Codex table its emptiness was
 * not an option.
 *
 * `Stop` is the row. Read from the host's own release notes at 1.1.10:
 * hooks declared in `hooks.json` were moved to run BEFORE the built-in
 * termination checks, "which lets `PostInvocation` hooks observe the final
 * invocation of a turn and lets `Stop` hooks run at all instead of sitting
 * unreachable behind the built-ins". Every earlier release therefore accepts a
 * `Stop` registration, loads it, reports it under the host's own hook listing —
 * and never runs it.
 *
 * THAT IS A DIFFERENT MECHANISM FROM A DROPPED ENTRY, AND THE SAME OUTCOME.
 * The name parsed; the handler was simply unreachable. The partition is about
 * which protections a host version actually delivers, so "recognised but never
 * reached" belongs in it exactly as "not recognised" does — from the outside
 * they are one event: the plugin installs clean and the protection is absent.
 *
 * WHAT IS LOST BELOW 1.1.10 is narrower than losing the event suggests, and
 * saying so is the point of a per-protection label. This plugin's `Stop` hook
 * does two things, and both have another caller: it TRIGGERS the background
 * reconcile worker, which `PreInvocation` and `PostToolUse` also trigger, and
 * it makes the once-per-session store-redirect check, which `PreInvocation`
 * makes too behind the same marker. So the capture path survives and what goes
 * is the end-of-turn trigger — the one that reconciles the tail of a turn once
 * no further tool call or invocation is coming. Below 1.1.10 that tail waits
 * for the next turn, and when the lost `Stop` was the session's last event
 * there is no next turn: it waits until that conversation is resumed or a
 * backfill sweeps it.
 *
 * WHY THE ROW EXISTS WITH NO READER TO ACT ON IT — the question the Codex table
 * answers the other way, and the two are not inconsistent. The partition forces
 * every registered event into one of two halves, and the baseline half asserts
 * that no supported host is missing the event. For Codex that assertion is TRUE
 * of all five, so an empty floor table states a fact. Putting `Stop` in this
 * host's baseline would state a FALSEHOOD, because 1.0.0 through 1.1.9 are
 * exactly the hosts that are missing it. A row is the only honest encoding, and
 * it costs nothing to be right early: it warns nobody today for want of a
 * version reader, and it is already correct on the day one lands.
 *
 * EVERY `since` HERE IS ON THE CLI's 1.x LINE, and that has to be stated
 * because this product family ships more than one. The `agy` CLI versions as
 * 1.x (1.1.10, 1.2.7); "Antigravity 2.0" versions as 2.x; the IDE build is a
 * third. `compareBinaryVersions` compares numeric cores and knows nothing about
 * which line a string came from, so handing it a 2.x version against a 1.x
 * floor yields a confident answer computed across two unrelated histories — it
 * reads "no gap" today only because 2 > 1. A reader that observes a version
 * must therefore establish WHICH build it belongs to before comparing it here,
 * and a floor for a non-CLI line needs its own table rather than a row in this
 * one. Hooks are what this plugin registers and hooks run in the CLI, which is
 * why one line is enough for now.
 *
 * Read any further `since` off that line's own release history, as this one was,
 * and confirm it parses — `compareBinaryVersions` answers 0 for an unparseable
 * input and 0 is not < 0, so a typo makes its row silently never fire.
 */
export const ANTIGRAVITY_HOST_FLOORS: Record<AntigravityHostFeature, HostFloorRow> = {
  [ANTIGRAVITY_HOST_FEATURE.EndOfTurnCapture]: {
    label: 'end-of-turn history capture',
    hookEvents: ['Stop'],
    since: '1.1.10',
  },
};

/**
 * The Antigravity events old enough that no supported host is missing them.
 *
 * All three date from the initial 1.0.0 release, which shipped with the hook
 * system already in place — the host's release notes carry fixes to the
 * pre-tool hook decision path and to its own hook-listing command within the
 * first sixteen patches, and add none of these three events after it.
 *
 * `PostInvocation` is absent from both halves because this plugin does not
 * register it, which the partition guard checks in that direction too: a floor
 * for an event nobody registers is a warning nobody needs.
 */
export const ANTIGRAVITY_BASELINE_HOOK_EVENTS: readonly string[] = [
  'PreInvocation',
  'PreToolUse',
  'PostToolUse',
];
