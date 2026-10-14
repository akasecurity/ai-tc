/**
 * Unit tests for GitHub Copilot provider resolution.
 *
 * Its three siblings each read a documented host env var; this one reads none,
 * because Copilot publishes none. So the cases here are the constant answer,
 * the shape it slots into, and — the one that keeps CLAUDE.md §3's opt-out
 * table honest — that the module source contains no `process.env` read at all.
 * That absence is what makes this file need no `n/no-process-env` opt-out and
 * no row in that table, and it is asserted rather than remembered.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it, vi } from 'vitest';

import { resolveCopilotProvider } from '../src/provider-copilot.ts';

const SOURCE_PATH = fileURLToPath(new URL('../src/provider-copilot.ts', import.meta.url));

describe('resolveCopilotProvider', () => {
  it('answers unknown', () => {
    expect(resolveCopilotProvider()).toEqual({ provider: 'unknown' });
  });

  it('answers unknown regardless of what the environment says', () => {
    // The three sibling resolvers each key off one of these. This one must not
    // move for any of them — a session that set OPENAI_BASE_URL in the same
    // shell still reaches GitHub's endpoint.
    vi.stubEnv('OPENAI_BASE_URL', 'https://litellm.internal:4000/v1');
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://gateway.internal');
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', 'https://gemini.internal');
    try {
      expect(resolveCopilotProvider()).toEqual({ provider: 'unknown' });
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('sets no gatewayHost', () => {
    expect(resolveCopilotProvider().gatewayHost).toBeUndefined();
  });

  it('returns a fresh object per call, so a caller cannot mutate the next answer', () => {
    const first = resolveCopilotProvider();
    const second = resolveCopilotProvider();
    expect(first).not.toBe(second);
  });
});

describe('the module reads no environment', () => {
  // The source, comments stripped: a plain text match would be satisfied by the
  // module comment, which says "reads NO environment" and names three env vars.
  const source = readFileSync(SOURCE_PATH, 'utf8')
    .replaceAll(/\/\*[\s\S]*?\*\//gu, '')
    .replaceAll(/\/\/.*$/gmu, '');

  it('contains no process.env read', () => {
    expect(source).not.toContain('process.env');
  });

  it('imports nothing', () => {
    // An env read reached through a helper would be invisible to the check
    // above; with no imports at all there is nowhere for one to hide.
    expect(source).not.toMatch(/^\s*import\s/mu);
  });

  it('still carries the paragraph explaining why there is no model-id heuristic', () => {
    // The positive control for both checks above: a file emptied of everything
    // would pass them and fail this.
    const whole = readFileSync(SOURCE_PATH, 'utf8');
    expect(whole).toContain('copilotProviderFromModelId');
    expect(whole).toContain('export function resolveCopilotProvider');
  });
});
