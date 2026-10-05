// GitHub Copilot stdio helpers — the only host-specific glue this adapter
// keeps. Detection, policy and persistence live in @akasecurity/plugin-sdk;
// these just move bytes between the host and the runtime.
//
// Four things differ from the Claude Code / Codex siblings, and all four are
// load-bearing:
//
//  1. THE EXIT CODE IS WHAT FAILS CLOSED — NOT THE SILENCE. On the Copilot CLI
//     `preToolUse` is the one fail-closed event, and the hooks reference is
//     specific about which channel that is: a non-zero exit other than 2
//     "denies the tool call", exit 2 denies and merges any stdout JSON into the
//     deny "even if that JSON reports `permissionDecision: \"allow\"`", and
//     "Timeouts are fail-open for every event, including `preToolUse`". Empty
//     stdout is in none of those: the same reference's `preToolUse` decision
//     table says "Empty output uses default behavior", which hands the call to
//     the host's own permission flow. So silence IS the no-opinion here,
//     exactly as CLAUDE.md §1 defines fail-open, and what this module has to
//     guarantee is the EXIT CODE.
//
//  2. NO PATH EVER EXITS NON-ZERO, and none exits 2. That is the whole of the
//     fail-open guarantee on this host. On the CLI a non-zero exit from
//     `preToolUse` denies; under VS Code exit 2 is the BLOCK channel. An
//     accidental 2 from an unhandled rejection would block a tool call by a
//     route nothing in this package ever writes to.
//
//  3. THIS ADAPTER NEVER EMITS AN ALLOW ON THE CLI. `permissionDecision:
//     "allow"` is a VERDICT — it decides that the tool executes — so printing
//     one on every clean call pre-approves the calls the user's own Copilot
//     settings would have prompted about, which is a control plane widening the
//     permissions it was installed to narrow. `CliPermissionDecisionOutput`
//     therefore carries `'deny'` alone, so an allow on that dialect is a
//     compile error rather than a convention. VS Code's shape keeps `'allow'`
//     because that host requires the verdict ALONGSIDE `updatedInput` for a
//     rewrite to be carried at all.
//
//  4. TWO DIALECTS SHARE ONE `emit`. The narrowed `HookOutput` union below
//     spans both; see `./dialect.ts` for how a payload is placed.

import { isAbsolute, normalize } from 'node:path';

import { resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

import type { Dialect, ToolCall } from './dialect.ts';
import { readCwd, readSessionId } from './dialect.ts';

/**
 * The watchdog `runHookFailOpen` races the hook body against.
 *
 * `hooks.json` registers `timeoutSec: 30`, this host's documented default, and
 * this sits comfortably under it — the same ratio Antigravity's 8s keeps under
 * its 10s. The margin is reserved for `emit`'s awaited flush, which sits
 * OUTSIDE the race by design and is therefore unbounded on a stalled pipe. 30s
 * is more headroom than Antigravity's 10s; it is not a different property.
 */
export const WATCHDOG_MS = 24_000;

export async function readStdin(): Promise<string> {
  return new Promise<string>((resolve) => {
    let data = '';
    let settled = false;

    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.stdin.removeListener('data', onData);
      process.stdin.removeListener('end', finish);
      resolve(data);
    };
    const onData = (chunk: string): void => {
      data += chunk;
    };
    // A stalled or never-closed stdin must not hang the hook past the host's
    // own timeout: settle with whatever arrived and let the caller fail open.
    const timer = setTimeout(finish, 5_000);

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', onData);
    process.stdin.on('end', finish);
    // An unhandled 'error' here would be an uncaughtException, not a
    // rejection — settle instead so the hook still exits 0.
    process.stdin.on('error', finish);
  });
}

export function parseJson(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function getString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

// ─── The wire ────────────────────────────────────────────────────────────────

/**
 * The CLI's `preToolUse` verdict. Two of the host's three values are
 * deliberately absent.
 *
 * `allow` is absent because emitting one is a DECISION that the tool executes,
 * not a way of saying nothing: the reference's own `permissionRequest` carve-out
 * ("a hook `allow` does not pre-approve the request or short-circuit the user
 * prompt" — stated there as the exception for sandbox escapes) is what says what
 * an allow does everywhere it is not excepted. A control plane that printed one
 * per clean call would suppress prompts the user's own settings would have
 * raised. Saying nothing is how this adapter declines to decide; see the header.
 *
 * `ask` is absent because it is not a third OUTCOME here: in non-interactive
 * mode it was observed resolving to `denied-no-approval-rule-and-could-not-
 * request-from-user` after a ~25s stall, i.e. a deny that costs most of the hook
 * budget first. A policy that wants a deny emits one.
 */
export interface CliPermissionDecisionOutput {
  // Recorded: a deny returned this way with exit 0 blocked the call.
  permissionDecision: 'deny';
  permissionDecisionReason?: string;
}

/**
 * The CLI's input rewrite. Observed to replace the executed shell command.
 *
 * No `systemMessage`: the reference documents exactly three `preToolUse` output
 * fields — `permissionDecision`, `permissionDecisionReason` and `modifiedArgs` —
 * and the string `systemMessage` appears nowhere in it. A message put here would
 * be dropped by the host, so anything this adapter wants to SAY on the CLI goes
 * to stderr instead. See `PreToolUseDecision.notice` in
 * ./pre-tool-use-decision.ts.
 */
export interface CliModifiedArgsOutput {
  modifiedArgs: Record<string, unknown>;
}

/** The CLI's output rewrite, for `postToolUse`. Documented; not observed. */
export interface CliModifiedResultOutput {
  modifiedResult: Record<string, unknown>;
}

/** VS Code's `PreToolUse` verdict and its input rewrite, which share a field. */
export interface VsCodePreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny';
    permissionDecisionReason?: string;
    // Validated against the tool's own input schema, and LAST HOOK WINS — a
    // user's or repo's own hook returning one discards this.
    updatedInput?: Record<string, unknown>;
  };
  systemMessage?: string;
}

/** VS Code's only channel on a tool RESULT: block it, or say something. */
export interface VsCodeBlockOutput {
  decision: 'block';
  additionalContext?: string;
  systemMessage?: string;
}

/**
 * A message with no verdict attached — VS Code's warn channel, and that host's
 * only one.
 *
 * NOT the CLI's: `systemMessage` is not among the three output fields that
 * reference documents for `preToolUse`, so the same object there would be a
 * payload the host drops. On the CLI a warn is WRITTEN to stderr instead, and
 * stdout stays empty, which is the no-opinion the header describes.
 *
 * Whether stderr reaches a human on that host is UNOBSERVED, and this comment
 * used to claim it did. The reference documents stderr surfacing only for a
 * FAILING hook ("logged as a hook failure") and says nothing about an exit-0
 * one, so what is stated here is the channel the notice is written to, never
 * that anyone reads it. `skills/setup/SKILL.md` carries the same caveat on the
 * user-facing side, and the two must not drift apart again.
 */
export interface SystemMessageOutput {
  systemMessage: string;
}

/**
 * Everything this adapter is allowed to write to stdout.
 *
 * `emit` takes this union rather than `unknown` for the reason the Claude Code
 * sibling's does: a payload outside it then cannot reach the wire at all, and
 * a widening back to `unknown` fails `test/hook-output-shapes.test.ts` rather
 * than shipping.
 *
 * Its six shapes are the CLI's `permissionDecision`, `modifiedArgs` and
 * `modifiedResult`, VS Code's `hookSpecificOutput` and `decision`, and the bare
 * `systemMessage` that VS Code alone accepts. That enumeration is DERIVED in the test
 * rather than remembered here — each variant is named by its one required key,
 * the count word is read out of this sentence, and both are driven against the
 * union in both directions. A seventh variant fails that test until this
 * sentence names it.
 */
export type HookOutput =
  | CliPermissionDecisionOutput
  | CliModifiedArgsOutput
  | CliModifiedResultOutput
  | VsCodePreToolUseOutput
  | VsCodeBlockOutput
  | SystemMessageOutput;

/**
 * Write a notice on the channel that is not the decision channel.
 *
 * stdout carries at most one JSON object and the host parses it, so a message
 * cannot simply be appended beside a verdict — and on the Copilot CLI stdout has
 * no message FIELD for `preToolUse` at all, so a notice there would reach nobody.
 * stderr has neither constraint, and is already where this package's store
 * warnings and the SDK's rule-quarantine line go.
 *
 * `message` is passed WITHOUT a trailing newline and this adds one, which is the
 * opposite convention from `storeRedirectedMessage`'s direct `write(...)` in
 * ./store-health.ts — that string carries its own. Stated because the two sit in
 * one package: route a self-terminated message through here and it gains a blank
 * line.
 *
 * NOT awaited, unlike `emit`, and the reason it is safe is a SIZE bound rather
 * than a flush. `runHookFailOpen` ends in `process.exit(0)`, which does not
 * drain a pending pipe write, so a queued write is dropped — the same hazard
 * `warnIfStoreRedirected` records with measurements: on a pipe, 65,000 bytes
 * returns true and arrives whole, 200,000 returns false and delivers 65,536.
 * Every notice reaching here is a rule-id list or a store path, hundreds of
 * bytes, so the queued case is unreachable. A notice that could approach the
 * ~64KB buffer — a per-finding dump, a file body — needs an awaited write
 * instead, not a longer message.
 *
 * Best-effort by construction: a hook must never fail over a notice. `write` is
 * a parameter so both branches are drivable without capturing a real fd.
 */
export function writeNotice(
  message: string,
  write: (text: string) => void = (text) => void process.stderr.write(text),
): void {
  try {
    write(`${message}\n`);
  } catch {
    // Advisory by construction — a notice must not cost the caller its exit 0.
    // A hook that died here would exit non-zero, which on the CLI is a DENY:
    // the one outcome worse than losing the notice.
  }
}

// Hook output protocol: write one JSON object to stdout and exit 0.
//
// The flush must be awaited: hook entries exit right after main(), and exit
// does not wait for pending pipe writes — anything past the ~64KB pipe buffer
// is dropped and the host reads a truncated object as invalid JSON.
export function emit(output: HookOutput): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      resolve();
    };
    // Same hazard as readStdin: an unhandled 'error' on stdout (e.g. EPIPE if
    // the caller closed its end) is an uncaughtException, not a rejection —
    // resolve instead so the hook still exits 0 rather than crashing on write.
    // Deliberately never removed: a hook process exits right after, so one
    // leftover no-op listener is free.
    process.stdout.on('error', finish);
    process.stdout.write(JSON.stringify(output), finish);
  });
}

/**
 * Run a hook body so the host is left with a VALID exit code rather than a
 * crash.
 *
 * A body that reaches a decision has it forwarded verbatim, which is how
 * `preToolUse` denies. A body that reaches none — it threw, it declined
 * (returned undefined), or it outran the watchdog — writes **nothing** and
 * still exits 0. On every host this package speaks to, that is the no-opinion:
 * the Copilot CLI's reference documents empty `preToolUse` output as "default
 * behavior", and VS Code treats anything but exit 2 as non-blocking. What must
 * never happen is a non-zero exit, which on the CLI is a deny — so the
 * try/catch and the watchdog exist to protect the EXIT CODE, not to manufacture
 * a payload.
 *
 * `failOpen` is therefore optional and every shipped hook omits it. It stays in
 * the signature because it is the seam the wrapper's own suite drives the
 * "a payload was written" branch through, and because a future event on a host
 * that genuinely denies on silence would need one.
 *
 * THE BOUND IS WHAT YIELDS, and it is not a detail — a path it does not cover
 * is a denied tool call. The watchdog is a `setTimeout`, so it fires only when
 * the event loop gets a turn, and a body that blocks this thread cannot be
 * preempted from this thread. (`main()` is the first element of the race, so it
 * is invoked before the timer is armed: a body that blocks before its first
 * `await` runs with no timer pending at all.) A block that clears inside the
 * host's own 30s (`hooks.json`) still emits and still exits 0 — the denial
 * needs the block to outlast the HOST, not merely the watchdog.
 *
 * Two blocking stretches sit on the capture path and compose. `openLocalDatabase`
 * is synchronous `node:sqlite`, and its `PRAGMA busy_timeout = 2000` is charged
 * PER contended statement rather than once per open — the migration probe, the
 * repository prepares and every later write each pay it, and the `preToolUse`
 * body loops a capture per scannable field, so the reachable total is a
 * multiple of 2s, not 2s. (Three processes share one `aka.db` by design.) The
 * fast-path `scan()` is the other: in-process and synchronous whenever the
 * effective ruleset carries no pulled or custom regex rule.
 *
 * `emit` is outside the race as well, so a full or stalled pipe has no deadline
 * at all — and on that one path the closing `process.exit(0)` is never reached
 * either, since `emit` settles only on stdout's completion callback or its
 * error event. Bounding any of this needs the work moved off the thread, not a
 * longer timer here.
 *
 * `watchdogMs` is a parameter so those timing properties can be driven in
 * milliseconds rather than seconds; every shipped hook takes the default.
 *
 * Never rejects, and never returns to its caller.
 */
export async function runHookFailOpen(
  main: () => Promise<HookOutput | undefined>,
  failOpen?: HookOutput,
  watchdogMs: number = WATCHDOG_MS,
): Promise<never> {
  let output: HookOutput | undefined = failOpen;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const decided = await Promise.race([
      main(),
      new Promise<undefined>((resolve) => {
        watchdog = setTimeout(() => {
          resolve(undefined);
        }, watchdogMs);
      }),
    ]);
    if (decided !== undefined) output = decided;
  } catch {
    // Fail-open: never break the user's session. `output` is still `failOpen`.
  } finally {
    // Cleared rather than left pending: a live timer would hold the event loop
    // open past the emit below on a fast path that never raced it.
    if (watchdog !== undefined) clearTimeout(watchdog);
  }
  // Nothing to say is said by writing nothing. Guarding the emit rather than
  // emitting an empty object matters: `{}` is a payload the host parses, and on
  // `preToolUse` the reference merges stdout JSON into a deny on exit 2 — so a
  // placeholder object is never equivalent to silence.
  if (output !== undefined) {
    try {
      await emit(output);
    } catch {
      // stdout is gone; exiting 0 is all that is left to try.
    }
  }
  process.exit(0);
}

/**
 * Base event metadata every hook can derive from its stdin payload: the session
 * id and the repo slug.
 *
 * The repo is resolved from the payload's own `cwd`. On the CLI that is the
 * workspace and the hook process's own cwd is an acceptable fallback; under VS
 * Code the spawn's cwd defaults to the HOME DIRECTORY unless the hook entry
 * declared one, so falling back there would resolve a repo from `~` and stamp
 * every capture with whatever happens to live in the user's home. That host
 * therefore gets no fallback, and the metadata simply carries no repo.
 *
 * The slug is read through `resolveRepoAttribution`, the memoised walk
 * `captureScopeKey` shares, so a payload cwd is walked once for both. `repo` is
 * exactly what `resolveRepo` returned here before.
 *
 * Returns undefined when nothing could be derived, so callers keep passing the
 * optional metadata through unchanged.
 */
export function baseMetadata(
  dialect: Dialect,
  input: Record<string, unknown>,
): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = readSessionId(dialect, input);
  if (sessionId) metadata.sessionId = sessionId;
  const cwd = readCwd(dialect, input) ?? (dialect === 'cli' ? process.cwd() : undefined);
  const repo = cwd ? resolveRepoAttribution(cwd).repo : undefined;
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

/**
 * The scope key of the checkout this event happened in: the canonical
 * `host/owner/repo` of its origin (else first) remote, or undefined.
 *
 * An event that names an ABSOLUTE path is keyed by the checkout that path is
 * in, and needs no payload cwd for it: the path names its own location. That
 * key never falls back to a cwd, so a path outside any checkout gets none.
 *
 * The walk starts at the named path ITSELF, not at its parent. The resolver
 * climbs by name and probes `<start>/.git` before it climbs, so one rule serves
 * every shape a path can have. A file has no `.git` of its own, so the walk
 * reaches the checkout its directory is in; a path that does not exist yet has
 * none either, and lands the same way. A directory that is a checkout's top
 * level, or a clone nested in another checkout, is found at the first probe,
 * which starting at the parent would skip: the nested clone would be keyed by
 * the checkout around it.
 *
 * The path is normalised first, because the walk climbs by name and a `..`
 * segment left in place would climb back into the checkout it left.
 * `callScopeKey` passes the target of a VS Code single-file write, and decides
 * which calls those are and what a writer without a readable target gets.
 *
 * Every other event is keyed STRICTER THAN `baseMetadata`, on purpose: only
 * from a cwd the PAYLOAD carries, on both dialects, and never from the hook
 * process's own.
 * - The slug's CLI fallback is a display guess, and a wrong one only mislabels
 *   a row. A key is what a scoped attachment is meant to decide by, so it must
 *   come from the event itself.
 * - Under VS Code the process cwd is the home directory anyway.
 * - This host never runs a session start, so there is no session-root key the
 *   fallback would need to match.
 *
 * A VS Code payload that does carry a cwd (its hook entry declared one) is keyed
 * like a CLI one: the dialect is a payload format, not a host.
 *
 * TOTAL. A key that cannot be resolved is absent, never a throw that would
 * cost the capture. The key rides beside the event (`CaptureInput.scopeKey`),
 * never inside EventMetadata.
 */
export function captureScopeKey(
  dialect: Dialect,
  input: Record<string, unknown>,
  filePath?: string,
): string | undefined {
  try {
    if (filePath !== undefined && isAbsolute(filePath)) {
      return resolveRepoAttribution(normalize(filePath)).scopeKey;
    }
    const cwd = readCwd(dialect, input);
    return cwd === undefined ? undefined : resolveRepoAttribution(cwd).scopeKey;
  } catch {
    return undefined;
  }
}

/**
 * VS Code's single-file writers, which name the one file they write in a
 * `filePath` input. Doc-derived, like `VSCODE_SCANNABLE_FIELDS`: the fixture
 * README cites `filePath` for `create_file` and `replace_string_in_file`, and
 * records only `code` and `explanation` for `insert_edit_into_file`, the same
 * kind of tool. A wrong guess costs a key, never the capture (see
 * `callScopeKey`).
 *
 * `apply_patch` is not one. On either dialect it names its files inside the
 * patch body (its `input` field), which the hook does not parse. It is recorded
 * whole as a `code_change`, so it gets NO key (see `callScopeKey`).
 */
export const VSCODE_FILE_WRITERS: ReadonlySet<string> = new Set([
  'create_file',
  'replace_string_in_file',
  'insert_edit_into_file',
]);

/**
 * The scope key of one tool call's captures. It rides beside the metadata
 * (`CaptureInput.scopeKey`), never inside it. `kind` is what the hook decided the
 * call records as.
 *
 * A `code_change` is durable content the agent authors, recorded whole, so it is
 * keyed only by what the hook can read of where it was written, and by nothing
 * otherwise:
 * - a VS Code single-file writer (`VSCODE_FILE_WRITERS`) is keyed by the file it
 *   writes and by nothing else, so a write into one checkout from a session whose
 *   cwd is another carries the key of the checkout it wrote. When `filePath` is
 *   missing or not absolute the call gets NO key rather than the cwd's: the
 *   field name is unconfirmed, and no key fails closed where the cwd's could
 *   name a checkout the file is not in. The path is not stamped as
 *   metadata.filePath, because that would change what these events carry on the
 *   wire;
 * - every other `code_change` gets NO key: an `apply_patch`, which names its
 *   files inside a patch body this hook does not read, and any tool added to the
 *   set of code_change tools without being taught here. The payload cwd's key
 *   would stamp a write into a personal checkout with an enrolled key, so the
 *   default is no key. Such content is meant to stay local on a scoped
 *   attachment, a coverage gap rather than a leak.
 *
 * Every other call names no file this hook reads, and is keyed by the payload
 * cwd alone (see `captureScopeKey`).
 */
export function callScopeKey(
  kind: 'code_change' | 'tool_use',
  dialect: Dialect,
  input: Record<string, unknown>,
  call: ToolCall,
): string | undefined {
  if (kind !== 'code_change') return captureScopeKey(dialect, input);
  if (dialect !== 'vscode' || !VSCODE_FILE_WRITERS.has(call.name)) return undefined;
  const target = getString(call.args, 'filePath');
  return target !== undefined && isAbsolute(target)
    ? captureScopeKey(dialect, input, target)
    : undefined;
}
