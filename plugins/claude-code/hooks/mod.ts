import type { Hook, Register } from 'claude-code';

import { type ModPolicy, parseModPolicy, redactPromptWith } from './engine.js';

// The mod half of AKA's prompt redaction. It rewrites each detected value whose
// policy is `redact` to [REDACTED:<CATEGORY>] before the prompt enters the
// session, so the model never reads the value and the prompt is not blocked.
//
// The policy is the user's own: `aka` writes the resolved policy and the
// installed rulesets to ~/.aka/data/mod-policy.json whenever either changes, and
// this module reads it. A missing, oversized, unparsable or invalid file leaves
// the bundled packs under their default policies, which redact nothing; the
// prompt is never failed over it.
//
// There is deliberately no `.catch` on the rewrite: a handler that fails, answers
// a wrong shape or outruns its budget is skipped by the runtime and the prompt
// goes on as typed. The UserPromptSubmit command hook stays registered and
// decides every prompt this rewrite leaves alone.

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

export const register: Register = (on) => {
  on('prompt.submit', async ($, e, next) =>
    next({ ...e, text: redactPromptWith(e.text, await loadPolicy($)) }),
  );
};
