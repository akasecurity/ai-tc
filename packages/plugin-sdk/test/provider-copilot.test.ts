// Copilot's provider resolver, and the two properties that make it different
// from its three siblings rather than an unfinished copy of them.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { resolveCopilotProvider } from '../src/provider-copilot.ts';

afterEach(() => {
  vi.unstubAllEnvs();
});

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULE = join(HERE, '..', 'src', 'provider-copilot.ts');

describe('resolveCopilotProvider', () => {
  it("answers 'unknown' rather than naming a backend", () => {
    expect(resolveCopilotProvider()).toEqual({ provider: 'unknown' });
  });

  // Every sibling resolver's answer MOVES with the host env, which is exactly
  // why each of them carries an `n/no-process-env` opt-out and a row in
  // CLAUDE.md §3. This one must not, so the property to pin is that a plausible
  // base-url override changes nothing here.
  it('is unmoved by the base-url variables its siblings read', () => {
    const before = resolveCopilotProvider();
    vi.stubEnv('OPENAI_BASE_URL', 'https://gateway.example.test');
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://gateway.example.test');
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', 'https://gateway.example.test');
    expect(resolveCopilotProvider()).toEqual(before);
  });

  // The structural half of the same claim, and the one that survives a future
  // rewrite: this module must not READ the environment at all. Reading the
  // source rather than the behaviour is what catches an env read added on a
  // branch the two cases above happen not to take.
  it('reads no environment at all', () => {
    expect(readFileSync(MODULE, 'utf8')).not.toContain('process.env');
  });
});
