import type { Hook, Register, StateValue } from 'claude-code';
import { update } from 'claude-code';

import {
  type ModPolicy,
  parseModPolicy,
  planPromptWith,
  planRowWith,
  type PointerWant,
  revealPointers,
  toolCallNeedsHelper,
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
}

// The helper's stdout, or null for anything that is not exactly its answer.
function parseHelperAnswer(stdout: string): HelperAnswer | null {
  try {
    const raw: unknown = JSON.parse(stdout);
    if (typeof raw !== 'object' || raw === null) return null;
    const answer = raw as { v?: unknown; text?: unknown; note?: unknown };
    if (answer.v !== 1 || typeof answer.text !== 'string' || answer.text === '') return null;
    if (answer.note !== null && typeof answer.note !== 'string') return null;
    return { text: answer.text, note: answer.note };
  } catch {
    return null;
  }
}

// The helper's rewrite of `text`, or null for any reason there is none.
async function rewriteWithHelper(
  $: Dollar,
  text: string,
  door?: string,
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
        ...(door === undefined ? {} : { row: { door } }),
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
): Promise<string | null> {
  if (text === '') return null;
  const plan = planRowWith(text, policy);
  if (plan.values.length === 0) return null;
  const answer = await rewriteWithHelper($, text, door);
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
      const text = await rewriteRowText($, policy, block.text, row.door);
      if (text === null) content.push(block);
      else {
        content.push({ ...block, text });
        changed = true;
      }
    } else if (block.type === 'tool_result' && row.door === 'tool-result') {
      const inner = block.content;
      if (typeof inner === 'string') {
        const text = await rewriteRowText($, policy, inner, row.door);
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
              ? await rewriteRowText($, policy, part.text, row.door)
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
// per draw: it reads the answers held in $.state, draws from them, and for a
// pointer it has none for starts one helper run (once per distinct pointer, kept
// in `inflight` until it settles) whose answer is written to $.state, which
// redraws the readers. Until then, and wherever the helper cannot answer, the
// pointer is shown as written. A trailing partial pointer or a garbled one never
// matches the pointer grammar and is left alone. The markdown regions where a
// pointer stays masked are the MessageDisplay command hook's own, which stays
// registered for surfaces where mods do not draw; on a surface where both run,
// this hook is handed the raw text, so a value is revealed once.

type RenderArgs = Parameters<Hook<'ui.render'>>;
type RenderDollar = RenderArgs[0];
type RevealEntry = StateValue<'aka', 'reveals'>[string];

// Typed literally and used for nothing but $.state calls, as the host requires.
const reveals = { plugin: 'aka', key: 'reveals' } as const;

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
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// The helper's stdout, or null for anything that is not exactly its answer.
function parseToolCallAnswer(stdout: string): ToolCallAnswer | null {
  try {
    const raw: unknown = JSON.parse(stdout);
    if (!isRecord(raw) || raw.v !== 1) return null;
    const { deny, input, context, message } = raw;
    if (deny !== null && (typeof deny !== 'string' || deny === '')) return null;
    if (input !== null && !isRecord(input)) return null;
    if (context !== null && typeof context !== 'string') return null;
    if (message !== null && typeof message !== 'string') return null;
    if (deny !== null && (input !== null || context !== null)) return null;
    return { deny, input, context, message };
  } catch {
    return null;
  }
}

async function runRevealHelper(
  $: RenderDollar,
  items: { token: string; reveal: boolean }[],
): Promise<RevealAnswer | null> {
  try {
    const run = await $.process.run(['node', scriptPath($, 'mod-reveal.js')], {
      stdin: JSON.stringify({ v: 1, items }),
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
      stdin: JSON.stringify({ v: 1, tool, input, sessionId }),
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
function drawPointer(
  held: Readonly<Record<string, RevealEntry>>,
  now: number,
  want: PointerWant,
): { text: string; revealed: boolean } | null {
  const entry = held[want.token];
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
  held: Readonly<Record<string, RevealEntry>>,
  asked: { token: string; reveal: boolean }[],
  answer: RevealAnswer | null,
  now: number,
): Record<string, RevealEntry> {
  const next: Record<string, RevealEntry> = { ...held };
  for (const { token, reveal } of asked) {
    const prior = held[token];
    const got = answer?.items.get(token);
    if (answer === null || (got === undefined && !answer.isOff)) {
      next[token] = { badge: prior?.badge ?? null, failedAt: now };
      if (prior?.revealed !== undefined)
        next[token] = { ...next[token]!, revealed: prior.revealed };
    } else if (got === undefined) {
      next[token] = { badge: null };
    } else {
      next[token] = reveal
        ? { badge: got.badge, revealed: got.revealed }
        : {
            badge: got.badge,
            ...(prior?.revealed === undefined ? {} : { revealed: prior.revealed }),
          };
    }
  }
  const keys = Object.keys(next);
  for (const stale of keys.slice(0, Math.max(0, keys.length - REVEAL_MAX_HELD))) delete next[stale];
  return next;
}

// Resolves pointers the render hook found no answer for, once each, and writes
// the answers to $.state. Runs apart from the render that started it: a render
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
    await update($, reveals, (held) => mergeReveals(held ?? {}, asked, answer, now));
  } catch {
    // The pointers stay as written; the next redraw asks again.
  } finally {
    for (const { token, reveal } of asked) inflight.delete(`${token}|${String(reveal)}`);
  }
}

async function revealRender($: RenderDollar, e: RenderArgs[1], next: RenderArgs[2]) {
  try {
    const props = e.props as { text?: unknown };
    // The cheap exit for nearly every message: no pointer opening, nothing to do.
    if (typeof props.text !== 'string' || !props.text.includes('[[aka:')) return next(e);
    const { value: held = {} } = await $.state.get(reveals);
    let now = 0;
    try {
      now = await $.clock.now();
    } catch {
      now = 0;
    }
    const drawn = revealPointers(props.text, (want) => drawPointer(held, now, want));
    if (drawn.wanted.length > 0) void resolvePointers($, drawn.wanted);
    if (drawn.text === props.text) return next(e);
    return next({ ...e, props: { ...e.props, text: drawn.text } } as typeof e);
  } catch {
    return next(e);
  }
}

// What the host spreads beside `tool` is the tool's own arguments.
function toolArguments(e: Record<string, unknown>): Record<string, unknown> {
  const { tool: _tool, tool_use_id: _id, agentId: _agent, ...input } = e;
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

export const register: Register = (on) => {
  on('session.start', async ($, e, next) => {
    await noteModRunning($);
    return next(e);
  });

  on('prompt.submit', async ($, e, next) => {
    await noteModRunning($);
    // Nothing to redact: nothing is spawned.
    const plan = planPromptWith(e.text, await loadPolicy($));
    if (plan.values.length === 0) return next(e);
    const answer = await rewriteWithHelper($, e.text);
    // A rewrite that leaves a value this module detected is not one to send.
    if (answer === null || plan.values.some((value) => answer.text.includes(value))) {
      return next(e);
    }
    return next({
      ...e,
      text: answer.text,
      ...(answer.note === null ? {} : { context: [...(e.context ?? []), answer.note] }),
    });
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
    return next(rewritten ?? e);
  });

  on('ui.render', { component: 'AssistantMessage' }, revealRender);
  on('ui.render', { component: 'UserMessage' }, revealRender);

  on('tool.call', async ($, e, next) => {
    const input = toolArguments(e);
    const needsHelper = toolCallNeedsHelper(e.tool, input, await loadPolicy($));
    if (!needsHelper) return next(e);
    const answer = await decideToolCallWithHelper($, e.tool, input);
    if (answer === null) return next(e);
    if (answer.deny !== null) return { deny: answer.deny };
    tell($, answer.message);
    const result = await next(answer.input === null ? e : ({ ...e, ...answer.input } as typeof e));
    if (answer.context === null || result.deny !== undefined) return result;
    return { ...result, context: [...(result.context ?? []), answer.context] };
  });
};
