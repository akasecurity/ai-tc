import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { ActionTaken } from '@akasecurity/schema';
import { builtinPolicyToAction, POINTER_TOKEN_PATTERN } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

// The prompt rewrite in hooks/engine.js, driven in Node. The same module runs
// in the mod runtime (test/mod-runtime/redact-prompt.test.ts, via
// `pnpm test:mod-runtime`); this file is the part CI can run.

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOKS_DIR = join(PLUGIN_ROOT, 'hooks');

interface PromptEngine {
  registerBundledPacks: () => void;
  bundledActionFor: (ruleId: string) => ActionTaken;
  createPromptRedactor: (actionFor: (ruleId: string) => ActionTaken) => (text: string) => string;
  redactPrompt: (text: string) => string;
  planPromptWith: (text: string, policy: null) => { text: string; values: string[] };
}

async function loadEngine(): Promise<PromptEngine> {
  const mod = (await import(pathToFileURL(join(HOOKS_DIR, 'engine.js')).href)) as PromptEngine;
  mod.registerBundledPacks();
  return mod;
}

// The values come from bundled rules' own examples, so no secret-shaped literal
// lives in this file.
function example(ruleId: string): string {
  const value = bundledDetections()
    .flatMap((p) => p.rules)
    .find((r) => r.id === ruleId)?.examples?.[0];
  if (value === undefined) throw new Error(`bundled rule ${ruleId} has no example`);
  return value;
}

const SECRET_RULE = 'secrets/twilio-key';
const SECRET = example(SECRET_RULE);
const EMAIL_RULE = 'core-pii/email';
const EMAIL = example(EMAIL_RULE);

describe('the prompt rewrite', () => {
  it('rewrites a value under a redact action and keeps the rest of the prompt', async () => {
    const { createPromptRedactor } = await loadEngine();
    const rewrite = createPromptRedactor(() => 'redact');
    expect(rewrite(`deploy with ${SECRET} now`)).toBe('deploy with [REDACTED:SECRET] now');
  });

  it('leaves a prompt with no findings as it came', async () => {
    const { createPromptRedactor } = await loadEngine();
    const rewrite = createPromptRedactor(() => 'redact');
    expect(rewrite('rename this variable')).toBe('rename this variable');
  });

  it.each<ActionTaken>(['warn', 'log', 'allow'])(
    'leaves the value alone under a %s action',
    async (action) => {
      const { createPromptRedactor } = await loadEngine();
      const text = `deploy with ${SECRET} now`;
      expect(createPromptRedactor(() => action)(text)).toBe(text);
    },
  );

  it('leaves the whole prompt to the command hook when any finding is a block', async () => {
    const { createPromptRedactor } = await loadEngine();
    const text = `mail ${EMAIL} the key ${SECRET}`;
    const rewrite = createPromptRedactor((ruleId) => (ruleId === SECRET_RULE ? 'block' : 'redact'));
    expect(rewrite(text)).toBe(text);
  });

  it('rewrites only the findings whose action is redact', async () => {
    const { createPromptRedactor } = await loadEngine();
    const rewrite = createPromptRedactor((ruleId) => (ruleId === SECRET_RULE ? 'redact' : 'warn'));
    const out = rewrite(`mail ${EMAIL} the key ${SECRET}`);
    expect(out).toContain(EMAIL);
    expect(out).toContain('[REDACTED:SECRET]');
    expect(out).not.toContain(SECRET);
  });

  it('propagates an action source that throws, so the runtime can skip the hook', async () => {
    const { createPromptRedactor } = await loadEngine();
    const rewrite = createPromptRedactor(() => {
      throw new Error('policy fault');
    });
    expect(() => rewrite(`key ${SECRET}`)).toThrow('policy fault');
  });
});

describe('the bundled default policies', () => {
  it('resolve every bundled rule the way a fresh install does', async () => {
    const { bundledActionFor } = await loadEngine();
    const got: Record<string, ActionTaken> = {};
    const want: Record<string, ActionTaken> = {};
    for (const pack of bundledDetections()) {
      const action =
        pack.defaultPolicyId === undefined ? 'log' : builtinPolicyToAction(pack.defaultPolicyId);
      for (const rule of pack.rules) {
        got[rule.id] = bundledActionFor(rule.id);
        want[rule.id] = action;
      }
    }
    expect(Object.keys(want).length).toBeGreaterThan(100);
    expect(got).toEqual(want);
  });

  it('enforce no redact today, so the shipped mod rewrites nothing until a policy says so', async () => {
    const { redactPrompt } = await loadEngine();
    const text = `deploy with ${SECRET} now`;
    expect(redactPrompt(text)).toBe(text);
  });

  it('leave an unknown rule id at log', async () => {
    const { bundledActionFor } = await loadEngine();
    expect(bundledActionFor('nobody/knows-this')).toBe('log');
  });
});

describe('the prompt plan', () => {
  // A pointer in the pinned grammar, built from the schema's own pattern's parts.
  const POINTER = `[[aka:secret:AB.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;

  it('names the values it would remove, and none when it removes nothing', async () => {
    const { createPromptRedactor } = await loadEngine();
    expect(createPromptRedactor(() => 'redact')(`x ${SECRET}`)).toBe('x [REDACTED:SECRET]');
    const mod = (await import(pathToFileURL(join(HOOKS_DIR, 'engine.js')).href)) as PromptEngine & {
      createPromptPlanner: (
        a: () => ActionTaken,
      ) => (t: string) => { text: string; values: string[] };
    };
    const plan = mod.createPromptPlanner(() => 'redact');
    expect(plan(`x ${SECRET}`).values).toEqual([SECRET]);
    expect(plan('nothing here')).toEqual({ text: 'nothing here', values: [] });
  });

  it('never sees a vault pointer, so a pointer is never tokenized again', async () => {
    expect(POINTER_TOKEN_PATTERN.test(POINTER)).toBe(true);
    const mod = (await import(pathToFileURL(join(HOOKS_DIR, 'engine.js')).href)) as {
      createPromptPlanner: (
        a: () => ActionTaken,
      ) => (t: string) => { text: string; values: string[] };
      registerBundledPacks: () => void;
    };
    mod.registerBundledPacks();
    const plan = mod.createPromptPlanner(() => 'redact');
    expect(plan(`use ${POINTER} here`)).toEqual({ text: `use ${POINTER} here`, values: [] });
    expect(plan(`use ${POINTER} and ${SECRET}`)).toEqual({
      text: `use ${POINTER} and [REDACTED:SECRET]`,
      values: [SECRET],
    });
  });
});

describe('the mod module', () => {
  const hooksJson = JSON.parse(readFileSync(join(HOOKS_DIR, 'hooks.json'), 'utf8')) as {
    modules?: string[];
    hooks: Record<string, unknown>;
  };

  it('is named by hooks.json, once, and exists', () => {
    expect(hooksJson.modules).toEqual(['./mod.ts']);
    expect(existsSync(join(HOOKS_DIR, 'mod.ts'))).toBe(true);
  });

  it('keeps the UserPromptSubmit command hook registered as the fallback', () => {
    expect(Object.keys(hooksJson.hooks)).toContain('UserPromptSubmit');
  });

  it('imports only the built engine, statically, and attaches no catch', () => {
    const src = readFileSync(join(HOOKS_DIR, 'mod.ts'), 'utf8');
    const imports = [...src.matchAll(/^import [^;]* from '([^']+)';$/gm)].map((m) => m[1]);
    expect([...new Set(imports.filter((i) => i !== 'claude-code'))]).toEqual(['./engine.js']);
    expect(src).not.toMatch(/\bimport\s*\(|\brequire\s*\(/);
    expect(src).not.toMatch(/\)\.catch\s*\(/);
    expect(existsSync(join(HOOKS_DIR, 'engine.js'))).toBe(true);
  });
});
