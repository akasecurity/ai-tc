import type { Register } from 'claude-code';

import { redactPrompt } from './engine.js';

// The mod half of AKA's prompt redaction. It rewrites each detected value whose
// policy is `redact` to [REDACTED:<CATEGORY>] before the prompt enters the
// session, so the model never reads the value and the prompt is not blocked.
//
// There is deliberately no `.catch`: a handler that fails, answers a wrong shape
// or outruns its budget is skipped by the runtime and the prompt goes on as
// typed. The UserPromptSubmit command hook stays registered and decides every
// prompt this rewrite leaves alone.
export const register: Register = (on) => {
  on('prompt.submit', (_$, e, next) => next({ ...e, text: redactPrompt(e.text) }));
};
