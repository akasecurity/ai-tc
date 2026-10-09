import type { Hook, Register } from 'claude-code';

import { type ModPolicy, parseModPolicy, planPromptWith } from './engine.js';

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
async function rewriteWithHelper($: Dollar, text: string): Promise<HelperAnswer | null> {
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
      stdin: JSON.stringify({ v: 1, text, sessionId }),
      timeoutMs: HELPER_TIMEOUT_MS,
    });
    return run.exitCode === 0 ? parseHelperAnswer(run.stdout) : null;
  } catch {
    return null;
  }
}

export const register: Register = (on) => {
  on('prompt.submit', async ($, e, next) => {
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
};
