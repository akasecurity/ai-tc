import type { Hook, Register } from 'claude-code';
import { update } from 'claude-code';

import {
  bandFindings,
  chipText,
  createReplySlots,
  mergeFindings,
  type ModPolicy,
  parseFindingRecord,
  parseFindingsJsonl,
  parseModPolicy,
  planPromptWith,
  planRowWith,
  type PointerWant,
  revealPointers,
  severityStyle,
  statusText,
  toolCallNeedsHelper,
  type ViewFinding,
  type ViewSeverity,
} from './engine.js';

// The mod half of AKA's prompt redaction. When the user's policy says `redact`
// for a value in the prompt, the prompt is handed to the `aka` helper
// (scripts/mod-tokenize.js, run with $.process.run) and what comes back replaces
// it: a vault pointer for a user who consented to the vault, `[REDACTED:<CATEGORY>]`
// for one who did not, plus a model-only note explaining pointers. The vault key
// and the store live in the helper; this module has neither. The model never
// reads the value and the prompt is not blocked.
//
// The helper also records the prompt's event and findings, which only it can do,
// so every rewrite goes through it. Where it cannot answer in time (missing,
// failing, slow, or an answer that is not a rewrite of this prompt) the prompt
// goes on exactly as typed. It is not one-way redacted here: that would hide the
// values from the model but lose the findings, and the UserPromptSubmit command
// hook, which stays registered, then applies today's block and records them.
//
// The policy is the user's own: `aka` writes the resolved policy and the
// installed rulesets to ~/.aka/data/mod-policy.json whenever either changes, and
// this module reads it. A missing, oversized, unparsable or invalid file leaves
// the bundled packs under their default policies, which redact nothing; the
// prompt is never failed over it.
//
// There is deliberately no `.catch` on the rewrite: a handler that fails, answers
// a wrong shape or outruns its budget is skipped by the runtime and the prompt
// goes on as typed.

type Dollar = Parameters<Hook<'prompt.submit'>>[0];

// The most `$.fs.read` will return; a larger file is never opened.
const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;

// What the last read of the snapshot produced, keyed by where it was read and
// the file's mtime and size, so an unchanged file is not read or parsed again on
// every prompt. A file that could not be used is cached too (as null) for the
// same reason.
let cached: { key: string; policy: ModPolicy | null } | undefined;

// A home directory spells its separator one way; the path joins with the same.
function snapshotPath(home: string): string {
  const sep = home.includes('\\') ? '\\' : '/';
  const root = home.endsWith('/') || home.endsWith('\\') ? home.slice(0, -1) : home;
  return [root, '.aka', 'data', 'mod-policy.json'].join(sep);
}

async function loadPolicy($: Dollar): Promise<ModPolicy | null> {
  try {
    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'));
    if (home === undefined || home === '') return null;
    const path = snapshotPath(home);
    const stat = await $.fs.stat(path);
    if (stat.kind !== 'file' || stat.size > MAX_SNAPSHOT_BYTES) return null;
    const key = `${path}|${String(stat.mtimeMs)}|${String(stat.size)}`;
    if (cached?.key === key) return cached.policy;
    const policy = parseModPolicy(await $.fs.read(path));
    cached = { key, policy };
    return policy;
  } catch {
    // Missing, unreadable or over the read limit: the bundled defaults apply.
    return null;
  }
}

// The findings this session's mod holds, newest first. Module memory on purpose:
// finding detail is never written to $.state, which any installed plugin can
// read; $.state holds a bare version counter that the widgets read while drawing,
// so bumping it redraws them.
let findingsHeld: ViewFinding[] = [];

const findingsVersion = { plugin: 'aka', key: 'findings' } as const;

// The mod is zod-free, so it spells the findings file's location, id check and
// read limit itself; the writer is plugins/claude-code/src/mod/findings-log.ts,
// called by the hooks and the mod's helpers.
const MOD_FINDINGS_DIR = 'mod-findings';
const MOD_FINDINGS_MAX_BYTES = 4 * 1024 * 1024;
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

// What the last read of the findings file saw, so an unchanged file is not read again.
let lastFile: string | undefined;

// Findings at or before this time (a `$.clock.now()` reading) are hidden from
// the band; the dismiss button sets it.
let dismissedBefore = 0;

// The session the list above belongs to.
let heldSession: string | undefined;

function heldFindings(): readonly ViewFinding[] {
  return findingsHeld;
}

const STATUS_EVERY_MS = 1000;

// When the status line was last written (a `$.clock.now()` reading), and what it said.
let lastStatusAt: number | undefined;
let lastStatusText: string | undefined;

// True while a trailing write is waiting out the window.
let flushScheduled = false;

// Writes the change the window held back once it has elapsed. Never throws.
async function flushStatusLater($: Dollar, ms: number): Promise<void> {
  try {
    await $.clock.sleep(Math.max(ms, 0));
  } catch {
    // The next hook with a status line writes it. Not re-scheduled here: a clock
    // that throws would loop until the window had passed.
    return;
  } finally {
    flushScheduled = false;
  }
  await refreshStatus($);
}

// Writes the status line from the held list, at most once a second, and only when
// its text changed: a burst of findings shows its first count and the next call
// after the second shows the rest. `force` skips the wait; `evenEmpty` writes the
// line before any finding, as the session starts, so the person sees the mod is
// on. A render's `$` has no status line, so a call from one writes nothing and
// the next prompt or tool call writes it. Never throws.
async function refreshStatus(
  $: Dollar,
  { force = false, evenEmpty = false }: { force?: boolean; evenEmpty?: boolean } = {},
): Promise<void> {
  try {
    const text = statusText(heldFindings(), 'in-place');
    if (text === lastStatusText) return;
    if (lastStatusText === undefined && heldFindings().length === 0 && !evenEmpty) return;
    const now = await $.clock.now();
    const waiting =
      lastStatusAt !== undefined && now >= lastStatusAt && now - lastStatusAt < STATUS_EVERY_MS;
    if (waiting && !force) {
      if (!flushScheduled) {
        flushScheduled = true;
        void flushStatusLater($, STATUS_EVERY_MS - (now - (lastStatusAt ?? now)));
      }
      return;
    }
    await $.ui.status(text);
    lastStatusAt = now;
    lastStatusText = text;
  } catch {
    // The status line is a courtesy.
  }
}

let paneFilter: ViewSeverity | 'all' = 'all';

const SHOW_FOR_MS = 30_000;

// Values the person pressed Show on, by finding id, with the time they re-mask
// (a `$.clock.now()` reading). Module memory only: a revealed value is never
// written to $.state, a file, a log, a toast or the status line.
const paneReveals = new Map<string, { value: string; until: number }>();

// The finding ids with a reveal run in flight, so a second press starts none.
const revealing = new Set<string>();

// The finding ids whose last reveal failed.
const revealFailed = new Set<string>();

// Whether the pane may offer Show: `on` once the helper answered that consent is
// valid, `off` once it answered that it is not or did not answer, `asking` while
// it is asked. A Show button is drawn only for `on`.
let paneConsent: 'unknown' | 'asking' | 'on' | 'off' = 'unknown';

// Counts the times the reveals were forgotten (the pane closed, the session
// changed): a helper answer for an earlier count is dropped, never drawn.
let revealEpoch = 0;

function forgetReveals(): void {
  revealEpoch += 1;
  paneReveals.clear();
  revealFailed.clear();
  paneConsent = 'unknown';
}

// A new session id (a /clear or a resume in the same process) starts an empty
// list: the findings of the session before are not shown in this one. Never throws.
async function followSession($: Dollar): Promise<void> {
  try {
    const sessionId = await $.session.id();
    if (sessionId === heldSession) return;
    const hadFindings = findingsHeld.length > 0;
    heldSession = sessionId;
    findingsHeld = [];
    dismissedBefore = 0;
    paneFilter = 'all';
    forgetReveals();
    lastFile = undefined;
    if (hadFindings) {
      await update($, findingsVersion, (version) => (version ?? 0) + 1);
      await refreshStatus($, { force: true });
    }
  } catch {
    // The list stays as it was.
  }
}

// Merges findings into the session list and bumps the version when the list
// gained one it did not have. Never throws.
async function takeFindings($: Dollar, incoming: readonly ViewFinding[]): Promise<void> {
  try {
    await followSession($);
    if (incoming.length === 0) return;
    const known = new Set(heldFindings().map((f) => f.id));
    if (incoming.every((f) => known.has(f.id))) return;
    findingsHeld = mergeFindings(findingsHeld, incoming);
    await update($, findingsVersion, (version) => (version ?? 0) + 1);
    await refreshStatus($);
  } catch {
    // The widgets show what they already held.
  }
}

// Takes what the session's findings file holds when its mtime or size changed.
// A session id the writer would refuse, a missing or oversized file, or a read
// that fails leaves the list as it was. Never throws.
async function refreshFromFile($: Dollar): Promise<void> {
  try {
    await followSession($);
    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'));
    if (home === undefined || home === '') return;
    const sessionId = await $.session.id();
    if (!SESSION_ID.test(sessionId)) return;
    const sep = home.includes('\\') ? '\\' : '/';
    const root = home.endsWith('/') || home.endsWith('\\') ? home.slice(0, -1) : home;
    const path = [root, '.aka', 'data', MOD_FINDINGS_DIR, `${sessionId}.jsonl`].join(sep);
    const stat = await $.fs.stat(path);
    if (stat.kind !== 'file' || stat.size > MOD_FINDINGS_MAX_BYTES) return;
    const key = `${path}|${String(stat.mtimeMs)}|${String(stat.size)}`;
    if (lastFile === key) return;
    const text = await $.fs.read(path);
    lastFile = key;
    await takeFindings($, parseFindingsJsonl(text));
  } catch {
    // No file yet, or an unreadable one: the helper answers still count.
  }
}

// A helper script's path under the plugin root, in the root's own separator.
function helperScript(root: string, name: string): string {
  const sep = root.includes('\\') ? '\\' : '/';
  return [root.replace(/[\\/]+$/, ''), 'scripts', name].join(sep);
}

// What the helper may take before the prompt goes on without it.
const HELPER_TIMEOUT_MS = 3000;

interface HelperAnswer {
  text: string;
  note: string | null;
  findings: ViewFinding[];
}

// The findings an answer carries, each checked as a record on disk is; one that
// does not parse is dropped, and an answer without a list has none. A bad finding
// never fails the answer it rides on.
function parseAnswerFindings(value: unknown): ViewFinding[] {
  if (!Array.isArray(value)) return [];
  const out: ViewFinding[] = [];
  for (const item of value as unknown[]) {
    const finding = parseFindingRecord(item);
    if (finding !== null) out.push(finding);
  }
  return out;
}

// The helper's stdout, or null for anything that is not exactly its answer.
function parseHelperAnswer(stdout: string): HelperAnswer | null {
  try {
    const raw: unknown = JSON.parse(stdout);
    if (typeof raw !== 'object' || raw === null) return null;
    const answer = raw as { v?: unknown; text?: unknown; note?: unknown; findings?: unknown };
    if (answer.v !== 1 || typeof answer.text !== 'string' || answer.text === '') return null;
    if (answer.note !== null && typeof answer.note !== 'string') return null;
    return { text: answer.text, note: answer.note, findings: parseAnswerFindings(answer.findings) };
  } catch {
    return null;
  }
}

// The directory a capture is attributed to: one the event itself names (a subagent
// started in its own cwd), else the session's. The helper would otherwise fall back
// to its own process.cwd(), which is the plugin's, not the project's.
async function captureCwd($: Dollar, e?: object): Promise<string | undefined> {
  const own = (e as { cwd?: unknown } | undefined)?.cwd;
  if (typeof own === 'string' && own !== '') return own;
  try {
    return await $.session.cwd();
  } catch {
    return undefined;
  }
}

// A subagent row's agent, so its finding is placed in the subagent.
function agentOf(event: object | undefined): { agentId?: string } {
  const agentId = (event as { agentId?: unknown } | undefined)?.agentId;
  return typeof agentId === 'string' ? { agentId } : {};
}

// The helper's rewrite of `text`, or null for any reason there is none.
async function rewriteWithHelper(
  $: Dollar,
  text: string,
  door?: string,
  event?: object,
): Promise<HelperAnswer | null> {
  try {
    const script = helperScript($.plugin.root, 'mod-tokenize.js');
    let sessionId: string | undefined;
    try {
      sessionId = await $.session.id();
    } catch {
      sessionId = undefined;
    }
    const run = await $.process.run(['node', script], {
      stdin: JSON.stringify({
        v: 1,
        text,
        sessionId,
        cwd: await captureCwd($, event),
        ...(door === undefined ? {} : { row: { door, ...agentOf(event) } }),
      }),
      timeoutMs: HELPER_TIMEOUT_MS,
    });
    return run.exitCode === 0 ? parseHelperAnswer(run.stdout) : null;
  } catch {
    return null;
  }
}

// The one door the row backstop leaves alone on the main conversation: the
// user's own prompt row, already handled (and recorded) by prompt.submit. A
// subagent's prompt row has no prompt.submit, so it is scanned.
function isHandledElsewhere(e: Parameters<Hook<'session.append'>>[1]): boolean {
  return e.door === 'prompt' && e.agentId === undefined;
}

// The helper's rewrite of one piece of row text, or null when it stays as made:
// nothing to redact, no answer, or an answer that still holds the value. A value
// PostToolUse already pointerized or marked is not a finding here (the planner
// skips pointers and the one-way marker is no match), so on a tool result only
// what PostToolUse left raw is rewritten and recorded.
async function rewriteRowText(
  $: Dollar,
  policy: ModPolicy | null,
  text: string,
  door: string,
  row: object,
): Promise<string | null> {
  if (text === '') return null;
  const plan = planRowWith(text, policy);
  if (plan.values.length === 0) return null;
  const answer = await rewriteWithHelper($, text, door, row);
  // The widgets update apart: a host call that hangs never holds the row.
  if (answer !== null) void takeFindings($, answer.findings);
  if (answer === null || plan.values.some((value) => answer.text.includes(value))) return null;
  return answer.text;
}

// A row's text blocks, and the text inside its tool_result blocks (a string or a
// list of blocks), each with its helper rewrite. Only `text` and `tool_result`
// content are rewritable by the host, so no other block is read. A piece the
// helper cannot answer for stays as made.
async function backstopRow(
  $: Dollar,
  row: Parameters<Hook<'session.append'>>[1],
): Promise<typeof row | null> {
  const policy = await loadPolicy($);
  let changed = false;
  const content = [];
  for (const block of row.message.content) {
    if (block.type === 'text' && typeof block.text === 'string') {
      const text = await rewriteRowText($, policy, block.text, row.door, row);
      if (text === null) content.push(block);
      else {
        content.push({ ...block, text });
        changed = true;
      }
    } else if (block.type === 'tool_result' && row.door === 'tool-result') {
      const inner = block.content;
      if (typeof inner === 'string') {
        const text = await rewriteRowText($, policy, inner, row.door, row);
        if (text === null) content.push(block);
        else {
          content.push({ ...block, content: text });
          changed = true;
        }
      } else if (Array.isArray(inner)) {
        const parts = [];
        let blockChanged = false;
        for (const part of inner as { type?: unknown; text?: unknown }[]) {
          const text =
            part.type === 'text' && typeof part.text === 'string'
              ? await rewriteRowText($, policy, part.text, row.door, row)
              : null;
          if (text === null) parts.push(part);
          else {
            parts.push({ ...part, text });
            blockChanged = true;
          }
        }
        if (blockChanged) {
          content.push({ ...block, content: parts });
          changed = true;
        } else content.push(block);
      } else content.push(block);
    } else content.push(block);
  }
  return changed ? { ...row, message: { ...row.message, content } } : null;
}

// Tool output forwarding. An attached machine whose organization asks for it
// writes ~/.aka/data/attached-capture.json; with `toolOutput` set there, each
// tool result is handed to the helper as the conversation keeps it (after the
// backstop's rewrite), cut to the cap, to be recorded so it is forwarded. Nothing
// awaits it, so the row is never held. While this mod runs, PostToolUse leaves
// tool output to it; the reader of that is packages/plugin-sdk/src/mod-host-mode.ts.
// A setting that names repositories is PostToolUse's alone: it keys the output by
// the file the tool touched, which a row does not carry.

const MAX_CAPTURE_SETTINGS_BYTES = 64 * 1024;

let captureSettingsCache: { key: string; maxChars: number | null } | undefined;

function captureSettingsPath(home: string): string {
  const sep = home.includes('\\') ? '\\' : '/';
  const root = home.endsWith('/') || home.endsWith('\\') ? home.slice(0, -1) : home;
  return [root, '.aka', 'data', 'attached-capture.json'].join(sep);
}

// The forwarding cap the settings file names, or null when it names none or names
// repositories. The bounds are TOOL_OUTPUT_FORWARD_MIN_CHARS and
// TOOL_OUTPUT_FORWARD_MAX_CHARS in packages/schema/src/zod/policy.ts.
function parseToolOutputCap(text: string): number | null {
  try {
    const raw: unknown = JSON.parse(text);
    if (typeof raw !== 'object' || raw === null) return null;
    const { v, toolOutput } = raw as { v?: unknown; toolOutput?: unknown };
    if (v !== 1 || typeof toolOutput !== 'object' || toolOutput === null) return null;
    const { maxChars, repos } = toolOutput as { maxChars?: unknown; repos?: unknown };
    if (repos !== undefined) return null;
    return typeof maxChars === 'number' &&
      Number.isInteger(maxChars) &&
      maxChars >= 2 &&
      maxChars <= 65_536
      ? maxChars
      : null;
  } catch {
    return null;
  }
}

async function toolOutputCap($: Dollar): Promise<number | null> {
  try {
    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'));
    if (home === undefined || home === '') return null;
    const path = captureSettingsPath(home);
    const stat = await $.fs.stat(path);
    if (stat.kind !== 'file' || stat.size > MAX_CAPTURE_SETTINGS_BYTES) return null;
    const key = `${path}|${String(stat.mtimeMs)}|${String(stat.size)}`;
    if (captureSettingsCache?.key === key) return captureSettingsCache.maxChars;
    const maxChars = parseToolOutputCap(await $.fs.read(path));
    captureSettingsCache = { key, maxChars };
    return maxChars;
  } catch {
    return null;
  }
}

// The first `maxChars` code units of `text`, one fewer when the cut would end on
// the first half of a surrogate pair; the helper's runtime cuts the same way.
function cutToolOutput(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const last = text.charCodeAt(maxChars - 1);
  return text.slice(0, last >= 0xd800 && last <= 0xdbff ? maxChars - 1 : maxChars);
}

// Every text a tool-result row holds, in order.
function toolResultTexts(row: Parameters<Hook<'session.append'>>[1]): string[] {
  const texts: string[] = [];
  for (const block of row.message.content) {
    if (block.type !== 'tool_result') continue;
    const inner = block.content;
    if (typeof inner === 'string') {
      if (inner !== '') texts.push(inner);
    } else if (Array.isArray(inner)) {
      for (const part of inner as { type?: unknown; text?: unknown }[]) {
        if (part.type === 'text' && typeof part.text === 'string' && part.text !== '') {
          texts.push(part.text);
        }
      }
    }
  }
  return texts;
}

// The tool a row's output came from, when the row names one.
function toolOf(row: object): { tool?: string } {
  const origin = (row as { origin?: { kind?: unknown; tool?: unknown } }).origin;
  return origin?.kind === 'tool' && typeof origin.tool === 'string' ? { tool: origin.tool } : {};
}

async function forwardToolResult(
  $: Dollar,
  row: Parameters<Hook<'session.append'>>[1],
): Promise<void> {
  try {
    const maxChars = await toolOutputCap($);
    if (maxChars === null) return;
    await noteModRunning($);
    const texts = toolResultTexts(row);
    if (texts.length === 0) return;
    const script = helperScript($.plugin.root, 'mod-tokenize.js');
    const sessionId = await $.session.id();
    const cwd = await captureCwd($, row);
    for (const text of texts) {
      await $.process.run(['node', script], {
        stdin: JSON.stringify({
          v: 1,
          text: cutToolOutput(text, maxChars),
          sessionId,
          cwd,
          row: {
            door: 'tool-result',
            ...agentOf(row),
            ...toolOf(row),
            forward: { maxChars, ...(text.length > maxChars ? { length: text.length } : {}) },
          },
        }),
        timeoutMs: HELPER_TIMEOUT_MS,
      });
    }
  } catch {
    // Not forwarded: the row itself was never held for it.
  }
}

// The mod is zod-free and Node-free, so it spells the note's location and shape
// itself; the reader is packages/plugin-sdk/src/mod-host-mode.ts.
const NOTE_RENEW_MS = 60 * 1000;
let lastNote: { sessionId: string; at: number } | undefined;

// Leaves a note under ~/.aka/data/mod-sessions that this session's mod is
// running; `aka status` and /aka:health read it to say prompts are redacted in
// place. Renewed at most once a minute. Any failure leaves no note.
async function noteModRunning($: Dollar): Promise<void> {
  try {
    const now = await $.clock.now();
    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'));
    if (home === undefined || home === '') return;
    const sessionId = await $.session.id();
    if (sessionId === '') return;
    if (lastNote?.sessionId === sessionId && now - lastNote.at < NOTE_RENEW_MS) return;
    const sep = home.includes('\\') ? '\\' : '/';
    const root = home.endsWith('/') || home.endsWith('\\') ? home.slice(0, -1) : home;
    const path = [root, '.aka', 'data', 'mod-sessions', `${encodeURIComponent(sessionId)}.json`];
    await $.fs.write(path.join(sep), JSON.stringify({ v: 1, sessionId, at: now }));
    lastNote = { sessionId, at: now };
  } catch {
    // No note: the session reports as blocking, which is the safe reading.
  }
}

// The screen half: ui.render hooks on AssistantMessage and UserMessage draw each
// COMPLETE vault pointer as the real value, or as a masked badge when the user's
// `vaultInlineReveal` setting is `masked`. Display only: the stored message and
// the model keep the pointer, and nothing here touches `turn.step`.
//
// The vault and the settings are out of reach of a mod, so the `aka` helper
// (scripts/mod-reveal.js, run with $.process.run) resolves pointers. A message
// redraws about every 50 ms while it streams, so the render hook never spawns
// per draw: it draws from the answers held in this module's memory, and for a
// pointer it has none for starts one helper run (once per distinct pointer, kept
// in `inflight` until it settles) whose answer is stored there.
//
// A revealed value is NEVER written to $.state: any installed plugin may read
// every value in it, so a vault value there would be readable by all of them.
// The values (and badges) live in a module variable that only this mod can reach;
// $.state holds a bare version counter and nothing else, which is read while
// drawing so that bumping it redraws the readers. A hot reload that loses the
// module's memory costs one more helper run per pointer, never a wrong drawing.
// Until an answer is held, and wherever the helper cannot answer, the pointer is
// shown as written. A trailing partial pointer or a garbled one never
// matches the pointer grammar and is left alone. The markdown regions where a
// pointer stays masked are the MessageDisplay command hook's own, which stays
// registered for surfaces where mods do not draw; on a surface where both run,
// this hook is handed the raw text, so a value is revealed once.

type RenderArgs = Parameters<Hook<'ui.render'>>;
type RenderDollar = RenderArgs[0];

// What the screen shows for one complete vault pointer, resolved once by the
// helper. `badge` is the masked form; null means the pointer is not to be
// rewritten at all (no vault consent, or inline reveal is off). `revealed` is the
// complete replacement for a revealed pointer: undefined until a reveal was asked
// for, null once the vault declined or the mode is masked. `failedAt` (a
// `$.clock.now()` time) marks a helper that did not answer, so a redraw does not
// spawn it again until a retry interval has passed.
interface RevealEntry {
  badge: string | null;
  revealed?: string | null;
  failedAt?: number;
}

// Typed literally and used for nothing but $.state calls, as the host requires.
// Its value is a version counter that carries no pointer and no value.
const reveals = { plugin: 'aka', key: 'reveals' } as const;

// The answers, keyed by pointer text. Module memory on purpose: see above.
const held = new Map<string, RevealEntry>();

// What the helper may take before the pointers stay as written.
const REVEAL_HELPER_TIMEOUT_MS = 3000;
// How long a helper that did not answer is left alone before a redraw asks again.
const REVEAL_RETRY_AFTER_MS = 30_000;
// Resolved pointers held for the session; the oldest go first.
const REVEAL_MAX_HELD = 512;
// Distinct pointers sent in one helper run.
const REVEAL_MAX_PER_RUN = 32;

// `token|reveal` for helper runs under way. A module variable is enough: a hot
// reload losing it costs at most one repeated run, never a wrong drawing.
const inflight = new Set<string>();

function scriptPath($: RenderDollar, name: string): string {
  const sep = $.plugin.root.includes('\\') ? '\\' : '/';
  return [$.plugin.root.replace(/[\\/]+$/, ''), 'scripts', name].join(sep);
}

interface RevealAnswer {
  items: Map<string, { badge: string; revealed: string | null }>;
  isOff: boolean;
}

function parseRevealAnswer(stdout: string): RevealAnswer | null {
  try {
    const raw: unknown = JSON.parse(stdout);
    if (typeof raw !== 'object' || raw === null) return null;
    const answer = raw as { v?: unknown; mode?: unknown; items?: unknown };
    if (answer.v !== 1 || !Array.isArray(answer.items)) return null;
    const items = new Map<string, { badge: string; revealed: string | null }>();
    for (const item of answer.items as unknown[]) {
      const one = item as { token?: unknown; badge?: unknown; revealed?: unknown };
      if (typeof one !== 'object' || typeof one.token !== 'string') return null;
      if (typeof one.badge !== 'string') return null;
      if (one.revealed !== null && typeof one.revealed !== 'string') return null;
      items.set(one.token, { badge: one.badge, revealed: one.revealed });
    }
    return { items, isOff: answer.mode === 'off' };
  } catch {
    return null;
  }
}

// The tool.call half. A call that carries a vault pointer, or a value the user's
// policy says to redact or block, is handed to the `aka` helper
// (scripts/mod-tool-call.js), which runs the PreToolUse pipeline on it and answers
// what it decided: refuse the call, or run it with this input (a granted pointer
// dereferenced into a data field, a secret redacted). Everything else goes on
// untouched without spawning anything.
//
// The mod is never the only thing between a pointer and an executable field. On
// any failure (no helper, a bad answer, a timeout, a fault here) the call goes on
// exactly as it came and the PreToolUse command hook, which runs after the last
// mod, applies today's rules: it denies an ungranted pointer in an executable
// field and redacts what the policy says to. The mod and the hook do not decide a
// call twice: the helper leaves a note naming the input the tool will run with,
// and the hook steps aside for a call it matches (src/mod/handoff.ts).

interface ToolCallAnswer {
  deny: string | null;
  input: Record<string, unknown> | null;
  context: string | null;
  message: string | null;
  findings: ViewFinding[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// The helper's stdout, or null for anything that is not exactly its answer.
function parseToolCallAnswer(stdout: string): ToolCallAnswer | null {
  try {
    const raw: unknown = JSON.parse(stdout);
    if (!isRecord(raw) || raw.v !== 1) return null;
    const { deny, input, context, message, findings } = raw;
    if (deny !== null && (typeof deny !== 'string' || deny === '')) return null;
    if (input !== null && !isRecord(input)) return null;
    if (context !== null && typeof context !== 'string') return null;
    if (message !== null && typeof message !== 'string') return null;
    if (deny !== null && (input !== null || context !== null)) return null;
    return { deny, input, context, message, findings: parseAnswerFindings(findings) };
  } catch {
    return null;
  }
}

// `pane` marks a press in the findings pane: the helper then reveals under valid
// consent whatever the inline reveal setting says.
async function runRevealHelper(
  $: RenderDollar,
  items: { token: string; reveal: boolean }[],
  pane = false,
): Promise<RevealAnswer | null> {
  try {
    const run = await $.process.run(['node', scriptPath($, 'mod-reveal.js')], {
      stdin: JSON.stringify({ v: 1, ...(pane ? { pane: true } : {}), items }),
      timeoutMs: REVEAL_HELPER_TIMEOUT_MS,
    });
    return run.exitCode === 0 ? parseRevealAnswer(run.stdout) : null;
  } catch {
    return null;
  }
}

// The helper's decision for the call, or null for any reason there is none.
async function decideToolCallWithHelper(
  $: Dollar,
  tool: string,
  input: Record<string, unknown>,
  event?: object,
): Promise<ToolCallAnswer | null> {
  try {
    const script = helperScript($.plugin.root, 'mod-tool-call.js');
    let sessionId: string | undefined;
    try {
      sessionId = await $.session.id();
    } catch {
      sessionId = undefined;
    }
    const run = await $.process.run(['node', script], {
      stdin: JSON.stringify({ v: 1, tool, input, sessionId, cwd: await captureCwd($, event) }),
      timeoutMs: HELPER_TIMEOUT_MS,
    });
    return run.exitCode === 0 ? parseToolCallAnswer(run.stdout) : null;
  } catch {
    return null;
  }
}

function isRetryable(entry: RevealEntry, now: number): boolean {
  return entry.failedAt === undefined || now - entry.failedAt >= REVEAL_RETRY_AFTER_MS;
}

// What to draw for a pointer, or null when the helper is to be asked.
function drawPointer(now: number, want: PointerWant): { text: string; revealed: boolean } | null {
  const entry = held.get(want.token);
  if (entry === undefined) return null;
  if (entry.badge === null) {
    // Not to be rewritten (no consent, or reveal off), or a helper that failed.
    return isRetryable(entry, now) && entry.failedAt !== undefined
      ? null
      : { text: want.token, revealed: false };
  }
  if (want.shielded) return { text: entry.badge, revealed: false };
  if (typeof entry.revealed === 'string') return { text: entry.revealed, revealed: true };
  if (entry.revealed === undefined && isRetryable(entry, now)) return null;
  return { text: entry.badge, revealed: false };
}

function mergeReveals(
  asked: { token: string; reveal: boolean }[],
  answer: RevealAnswer | null,
  now: number,
): void {
  for (const { token, reveal } of asked) {
    const prior = held.get(token);
    const got = answer?.items.get(token);
    if (answer === null || (got === undefined && !answer.isOff)) {
      held.set(token, {
        badge: prior?.badge ?? null,
        failedAt: now,
        ...(prior?.revealed === undefined ? {} : { revealed: prior.revealed }),
      });
    } else if (got === undefined) {
      held.set(token, { badge: null });
    } else {
      held.set(
        token,
        reveal
          ? { badge: got.badge, revealed: got.revealed }
          : {
              badge: got.badge,
              ...(prior?.revealed === undefined ? {} : { revealed: prior.revealed }),
            },
      );
    }
  }
  // The oldest go first.
  for (const stale of [...held.keys()].slice(0, Math.max(0, held.size - REVEAL_MAX_HELD)))
    held.delete(stale);
}

// Resolves pointers the render hook found no answer for, once each, and keeps
// the answers in this module's memory and bumps the $.state version counter so the
// readers redraw. Runs apart from the render that started it: a render
// never writes. Never throws.
async function resolvePointers($: RenderDollar, wanted: PointerWant[]): Promise<void> {
  const byToken = new Map<string, boolean>();
  for (const { token, shielded } of wanted)
    byToken.set(token, byToken.get(token) === true || !shielded);
  const asked = [...byToken]
    .map(([token, reveal]) => ({ token, reveal }))
    .filter(({ token, reveal }) => !inflight.has(`${token}|${String(reveal)}`))
    .slice(0, REVEAL_MAX_PER_RUN);
  if (asked.length === 0) return;
  for (const { token, reveal } of asked) inflight.add(`${token}|${String(reveal)}`);
  try {
    const answer = await runRevealHelper($, asked);
    let now = 0;
    try {
      now = await $.clock.now();
    } catch {
      now = 0;
    }
    mergeReveals(asked, answer, now);
    // The readers redraw on a new version; the counter says nothing about what changed.
    await update($, reveals, (version) => (version ?? 0) + 1);
  } catch {
    // The pointers stay as written; the next redraw asks again.
  } finally {
    for (const { token, reveal } of asked) inflight.delete(`${token}|${String(reveal)}`);
  }
}

// The reveal cap is per MESSAGE, but a reply is drawn as several blocks, each its
// own render; engine.js groups them (createReplySlots). Module memory like `held`,
// for the same reason.
const replySlots = createReplySlots();

function slotsFor(e: RenderArgs[1]): (token: string) => boolean {
  return replySlots({
    component: e.component,
    requestId: e.requestId,
    isFirstOfReply: (e.props as { isFirstOfReply?: unknown }).isFirstOfReply === true,
  });
}

async function revealRender($: RenderDollar, e: RenderArgs[1], next: RenderArgs[2]) {
  try {
    const props = e.props as { text?: unknown };
    // The cheap exit for nearly every message: no pointer opening, nothing to do.
    if (typeof props.text !== 'string' || !props.text.includes('[[aka:')) return next(e);
    // Read for its subscription only: a new version redraws this instance.
    await $.state.get(reveals);
    let now = 0;
    try {
      now = await $.clock.now();
    } catch {
      now = 0;
    }
    const drawn = revealPointers(props.text, (want) => drawPointer(now, want), slotsFor(e));
    if (drawn.wanted.length > 0) void resolvePointers($, drawn.wanted);
    if (drawn.text === props.text) return next(e);
    return next({ ...e, props: { ...e.props, text: drawn.text } } as typeof e);
  } catch {
    return next(e);
  }
}

// What the host spreads beside `tool` is the tool's own arguments, and the keys
// it carries beside them are the types' documented set: `ToolCallReserved`
// (`tool`, `tool_use_id`, `consent`) and `AgentLoop` (`agentId`). None of them
// reaches the tool (the engine strips them before it runs), so none belongs in the
// input handed to the helper or in the name of the handoff note the helper leaves
// for PreToolUse, which is shown the stripped input. The list is spelled once; a key
// the host adds later is not stripped here, so it is the first thing to check when
// the host's types change.
const RESERVED_KEYS = ['tool', 'tool_use_id', 'consent', 'agentId'] as const;

function toolArguments(e: Record<string, unknown>): Record<string, unknown> {
  const input: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(e)) {
    if (!(RESERVED_KEYS as readonly string[]).includes(key)) input[key] = value;
  }
  return input;
}

function tell($: Dollar, message: string | null): void {
  if (message === null) return;
  try {
    $.ui.toast(message);
  } catch {
    // The line is a courtesy; the decision stands without it.
  }
}

type BandArgs = Parameters<Hook<'ui.render'>>;
type BandDollar = BandArgs[0];

// The band above the prompt: the session's recent findings, one chip each in the
// severity's colour, with a dismiss button. Anything unexpected draws nothing.
async function bandRender($: BandDollar, e: BandArgs[1], next: BandArgs[2]) {
  try {
    if ((e.props as { hasSurvey?: boolean }).hasSurvey === true) return next(e);
    // Read for its subscription only: a new version redraws the band.
    await $.state.get(findingsVersion);
    await refreshFromFile($);
    const now = await $.clock.now();
    const { shown, more } = bandFindings(
      heldFindings().filter((f) => f.at > dismissedBefore),
      now,
    );
    if (shown.length === 0) return next(e);
    const { Box, Text, Button } = $.ui.resolve(e);
    return h(
      Box,
      { flexDirection: 'row', gap: 2, key: 'aka-band' },
      ...shown.map((f) =>
        h(
          Text,
          {
            key: `chip-${f.id}`,
            color: severityStyle(f.severity).color,
            bold: f.severity === 'critical',
          },
          chipText(f),
        ),
      ),
      more > 0
        ? h(Text, { key: 'more', dimColor: true }, `+${String(more)} more · /aka:findings-pane`)
        : null,
      h(Button, {
        key: 'dismiss',
        label: 'Dismiss',
        role: 'dismiss',
        onPress: () => void dismissBand($),
      }),
    );
  } catch {
    return next(e);
  }
}

async function dismissBand($: BandDollar): Promise<void> {
  try {
    const newest = heldFindings().reduce((latest, f) => Math.max(latest, f.at), 0);
    dismissedBefore = Math.max(await $.clock.now(), newest);
    await update($, findingsVersion, (version) => (version ?? 0) + 1);
  } catch {
    // The band stays as it was.
  }
}

const PANE_ID = 'aka-findings';

// A bare counter, like the findings one: a filter press bumps it to redraw the pane.
const paneVersion = { plugin: 'aka', key: 'pane' } as const;

type PaneDollar = Parameters<Hook<'ui.render'>>[0];

const PANE_FILTERS: readonly (ViewSeverity | 'all')[] = [
  'all',
  'critical',
  'high',
  'medium',
  'low',
];

async function setPaneFilter($: PaneDollar, filter: ViewSeverity | 'all'): Promise<void> {
  try {
    paneFilter = filter;
    await update($, paneVersion, (version) => (version ?? 0) + 1);
  } catch {
    // The pane stays as it was.
  }
}

// The pointer with everything after its category hidden: a pane never draws
// the part that locates a value.
function maskedPointer(pointer: string): string {
  const prefix = /^\[\[aka:[a-z][a-z0-9_]*:/.exec(pointer)?.[0];
  return prefix === undefined ? '[[aka:…]]' : `${prefix}…]]`;
}

async function bumpPane($: PaneDollar): Promise<void> {
  await update($, paneVersion, (version) => (version ?? 0) + 1);
}

// Re-masks a value once its time is up, without waiting for another draw.
async function maskLater($: PaneDollar, id: string, until: number): Promise<void> {
  try {
    await $.clock.sleep(SHOW_FOR_MS);
    if (paneReveals.get(id)?.until === until) {
      paneReveals.delete(id);
      await bumpPane($);
    }
  } catch {
    // The next draw re-masks it.
  }
}

// Asks the helper for one vaulted value, on a press and never otherwise. The
// helper checks consent and audits the reveal. Never throws.
async function showValue($: PaneDollar, f: ViewFinding): Promise<void> {
  if (f.pointer === undefined || revealing.has(f.id)) return;
  revealing.add(f.id);
  const epoch = revealEpoch;
  try {
    revealFailed.delete(f.id);
    const answer = await runRevealHelper($, [{ token: f.pointer, reveal: true }], true);
    if (epoch !== revealEpoch) return;
    if (answer?.isOff === true) paneConsent = 'off';
    const revealed = answer?.isOff === true ? undefined : answer?.items.get(f.pointer)?.revealed;
    if (typeof revealed === 'string') {
      const until = (await $.clock.now()) + SHOW_FOR_MS;
      if (epoch !== revealEpoch) return;
      paneReveals.set(f.id, { value: revealed, until });
      void maskLater($, f.id, until);
    } else if (answer?.isOff !== true) {
      revealFailed.add(f.id);
    }
  } catch {
    if (epoch === revealEpoch) revealFailed.add(f.id);
  } finally {
    revealing.delete(f.id);
    try {
      await bumpPane($);
    } catch {
      // The pane stays as it was.
    }
  }
}

// Asks the helper, once per opening of the pane, whether a value may be shown:
// a pane request with no items answers the consent alone. Never throws.
async function askPaneConsent($: PaneDollar): Promise<void> {
  paneConsent = 'asking';
  const epoch = revealEpoch;
  const answer = await runRevealHelper($, [], true);
  if (epoch !== revealEpoch) return;
  paneConsent = answer === null || answer.isOff ? 'off' : 'on';
  try {
    await bumpPane($);
  } catch {
    // The next draw shows it.
  }
}

async function hideValue($: PaneDollar, id: string): Promise<void> {
  try {
    paneReveals.delete(id);
    await bumpPane($);
  } catch {
    // The pane stays as it was.
  }
}

function clockTime(at: number): string {
  const date = new Date(at);
  const two = (n: number): string => String(n).padStart(2, '0');
  return `${two(date.getHours())}:${two(date.getMinutes())}`;
}

function pointerRows(
  { Text, Button }: ReturnType<PaneDollar['ui']['resolve']>,
  $: PaneDollar,
  f: ViewFinding,
) {
  if (f.pointer === undefined) return [];
  const shown = paneReveals.get(f.id);
  const rows = [
    shown === undefined
      ? h(Text, { key: `masked-${f.id}`, dimColor: true }, maskedPointer(f.pointer))
      : h(Text, { key: `value-${f.id}` }, shown.value),
  ];
  if (shown !== undefined) {
    rows.push(
      h(Button, {
        key: `hide-${f.id}`,
        label: 'Hide',
        variant: 'secondary',
        onPress: () => void hideValue($, f.id),
      }),
    );
  } else if (paneConsent === 'on') {
    rows.push(
      h(Button, {
        key: `show-${f.id}`,
        label: 'Show',
        variant: 'secondary',
        onPress: () => void showValue($, f),
      }),
    );
  }
  if (revealFailed.has(f.id)) {
    rows.push(h(Text, { key: `failed-${f.id}`, dimColor: true }, "couldn't reveal"));
  }
  return rows;
}

// The findings pane: the session's findings newest first, a row of severity
// filters above them. Anything unexpected hands on to the engine's pane.
async function paneRender($: PaneDollar, e: BandArgs[1], next: BandArgs[2]) {
  try {
    // Read for their subscriptions only: a new version redraws the pane.
    await $.state.get(findingsVersion);
    await $.state.get(paneVersion);
    await refreshFromFile($);
    const ui = $.ui.resolve(e);
    const { Box, Text, Button } = ui;
    const rows = heldFindings().filter((f) => paneFilter === 'all' || f.severity === paneFilter);
    if (paneConsent === 'unknown' && heldFindings().some((f) => f.pointer !== undefined)) {
      void askPaneConsent($);
    }
    if (paneReveals.size > 0) {
      const now = await $.clock.now();
      for (const [id, shown] of paneReveals) if (shown.until <= now) paneReveals.delete(id);
    }
    return h(
      Box,
      { flexDirection: 'column', key: 'aka-pane' },
      h(
        Box,
        { flexDirection: 'row', gap: 1, key: 'filters' },
        ...PANE_FILTERS.map((filter) =>
          h(Button, {
            key: `filter-${filter}`,
            label: filter === 'all' ? 'All' : severityStyle(filter).word,
            variant: filter === paneFilter ? 'primary' : 'secondary',
            onPress: () => void setPaneFilter($, filter),
          }),
        ),
      ),
      rows.length === 0
        ? h(
            Text,
            { key: 'empty', dimColor: true },
            paneFilter === 'all' ? 'No findings in this session.' : `No ${paneFilter} findings.`,
          )
        : null,
      ...rows.map((f) =>
        h(
          Box,
          { flexDirection: 'column', key: `row-${f.id}` },
          h(
            Text,
            { color: severityStyle(f.severity).color, bold: f.severity === 'critical' },
            `${chipText(f)}  ${clockTime(f.at)}`,
          ),
          ...pointerRows(ui, $, f),
        ),
      ),
    );
  } catch {
    return next(e);
  }
}

export const register: Register = (on) => {
  on('session.start', async ($, e, next) => {
    await followSession($);
    void refreshStatus($, { evenEmpty: true });
    try {
      await $.command.register({
        name: 'findings-pane',
        description: "Show this session's AKA findings",
      });
    } catch {
      // The band still points at the pane; the command is the only way in.
    }
    await noteModRunning($);
    return next(e);
  });

  on('prompt.submit', async ($, e, next) => {
    await noteModRunning($);
    // Nothing to redact: nothing is spawned.
    const plan = planPromptWith(e.text, await loadPolicy($));
    const answer = plan.values.length === 0 ? null : await rewriteWithHelper($, e.text);
    // The widgets update apart: a host call that hangs never holds the prompt.
    if (answer !== null) void takeFindings($, answer.findings);
    // A rewrite that leaves a value this module detected is not one to send.
    const result =
      answer === null || plan.values.some((value) => answer.text.includes(value))
        ? await next(e)
        : await next({
            ...e,
            text: answer.text,
            ...(answer.note === null ? {} : { context: [...(e.context ?? []), answer.note] }),
          });
    void refreshFromFile($).then(() => refreshStatus($));
    return result;
  });

  // The backstop: every other row the conversation keeps (attachments and the
  // @-mentioned files they carry, memory, hook context, compaction summaries,
  // subagent rows, notes, response blocks). A prompt.mention hook cannot see or
  // rewrite the file's text, so the file is scanned here, as the row that holds
  // it is stored. A row with nothing to redact is passed on with nothing spawned.
  // The tool-result door is the same shape for every tool: PostToolUse runs first
  // for the same call and may have rewritten the output, so only what it left raw
  // is scanned here (its pointers and one-way markers are never findings), and
  // only that is recorded: a value it handled is never recorded a second time.
  on('session.append', async ($, e, next) => {
    if (isHandledElsewhere(e)) return next(e);
    const rewritten = await backstopRow($, e);
    const row = rewritten ?? e;
    if (row.door === 'tool-result') void forwardToolResult($, row);
    return next(row);
  });

  on('ui.render', { component: 'AssistantMessage' }, revealRender);
  on('ui.render', { component: 'UserMessage' }, revealRender);
  on('ui.render', { component: 'AbovePrompt' }, bandRender);
  on('ui.render', { component: 'Pane', requestId: PANE_ID }, paneRender);

  on('ui.close', async ($, e, next) => {
    if (e.id === PANE_ID) forgetReveals();
    return next(e);
  });

  on('command.run', { command: 'findings-pane' }, async ($) => {
    try {
      await $.ui.open({ id: PANE_ID, title: 'AKA findings', focus: true, closeOnEscape: true });
    } catch {
      // Nothing to open.
    }
    return { text: '' };
  });

  on('tool.call', async ($, e, next) => {
    void refreshStatus($);
    // Renewed before the tool runs, so PostToolUse for this call sees the mod running.
    void noteModRunning($);
    const input = toolArguments(e);
    const needsHelper = toolCallNeedsHelper(e.tool, input, await loadPolicy($));
    if (!needsHelper) return next(e);
    const answer = await decideToolCallWithHelper($, e.tool, input, e);
    if (answer === null) return next(e);
    // The widgets update apart: a host call that hangs never holds the call.
    void takeFindings($, answer.findings);
    if (answer.deny !== null) {
      const first = answer.findings[0];
      tell($, first === undefined ? answer.message : `Blocked: ${first.label}`);
      return { deny: answer.deny };
    }
    // The helper leaves a message only when it says more than the band shows.
    tell($, answer.message);
    const result = await next(answer.input === null ? e : ({ ...e, ...answer.input } as typeof e));
    if (answer.context === null || result.deny !== undefined) return result;
    return { ...result, context: [...(result.context ?? []), answer.context] };
  });
};
