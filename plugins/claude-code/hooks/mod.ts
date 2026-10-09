import type { Hook, Register } from 'claude-code';

import { type ModPolicy, parseModPolicy, planPromptWith, planRowWith } from './engine.js';

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
    const sep = $.plugin.root.includes('\\') ? '\\' : '/';
    const script = [$.plugin.root.replace(/[\\/]+$/, ''), 'scripts', 'mod-tokenize.js'].join(sep);
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
};
