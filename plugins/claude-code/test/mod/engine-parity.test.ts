import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { getLoadedRules, redact, scan } from '@akasecurity/detections';
import { bundledDetections, registerBundledPacks } from '@akasecurity/plugin-sdk';
import type { EventKind } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

// Parity gate: the engine module a Claude Code mod imports (hooks/engine.js,
// built by build/engine.mjs) must agree with the Node engine on every rule
// fixture — same rule ids, same spans, same redacted text. Any drift between
// the two engines fails here, in CI, with no Claude Code installed.

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const RULES_ROOT = join(PLUGIN_ROOT, '..', '..', 'rules');
const ENGINE_PATH = join(PLUGIN_ROOT, 'hooks', 'engine.js');

interface FixtureCase {
  label: string;
  text: string;
  shouldMatch: boolean;
  filePath?: string;
  eventKind?: EventKind;
}

function loadFixtures(): { file: string; cases: FixtureCase[] }[] {
  const out: { file: string; cases: FixtureCase[] }[] = [];
  for (const pack of readdirSync(RULES_ROOT, { withFileTypes: true })) {
    if (!pack.isDirectory()) continue;
    const dir = join(RULES_ROOT, pack.name, 'fixtures');
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
      const cases = JSON.parse(readFileSync(join(dir, name), 'utf8')) as FixtureCase[];
      out.push({ file: `${pack.name}/${name}`, cases });
    }
  }
  return out;
}

interface ModEngine {
  registerBundledPacks(): void;
  scan: typeof scan;
  redact: typeof redact;
  getLoadedRules: typeof getLoadedRules;
}

const project = (findings: ReturnType<typeof scan>) =>
  findings
    .map((f) => ({ ruleId: f.ruleId, span: f.span }))
    .sort(
      (a, b) =>
        a.span.start - b.span.start || a.span.end - b.span.end || a.ruleId.localeCompare(b.ruleId),
    );

describe('mod engine parity', () => {
  it('exists after the build', () => {
    expect(existsSync(ENGINE_PATH)).toBe(true);
  });

  it('registers exactly the rules the Node engine registers (parsed at build time)', async () => {
    const mod = (await import(pathToFileURL(ENGINE_PATH).href)) as ModEngine;
    registerBundledPacks();
    mod.registerBundledPacks();
    const node = getLoadedRules();
    const built = mod.getLoadedRules();
    expect(built.length).toBe(bundledDetections().reduce((n, p) => n + p.rules.length, 0));
    expect(built).toEqual(node);
  });

  it('agrees with the Node engine on every rule fixture', async () => {
    const mod = (await import(pathToFileURL(ENGINE_PATH).href)) as ModEngine;
    registerBundledPacks();
    mod.registerBundledPacks();
    const fixtures = loadFixtures();
    let compared = 0;
    const diffs: string[] = [];
    for (const { file, cases } of fixtures) {
      for (const c of cases) {
        const context = { filePath: c.filePath, eventKind: c.eventKind };
        const a = scan(c.text, undefined, context);
        const b = mod.scan(c.text, undefined, context);
        const ra = redact(c.text, a);
        const rb = mod.redact(c.text, b);
        compared++;
        if (JSON.stringify(project(a)) !== JSON.stringify(project(b)) || ra !== rb) {
          diffs.push(`${file}: ${c.label}`);
        }
      }
    }
    expect(compared).toBeGreaterThan(700);
    expect(diffs).toEqual([]);
  });

  it('is free of Node built-ins, require and dynamic import', () => {
    const src = readFileSync(ENGINE_PATH, 'utf8');
    expect(src).not.toMatch(/["'`]node:/);
    expect(src).not.toMatch(/\brequire\s*\(/);
    expect(src).not.toMatch(/\bimport\s*\(/);
  });

  it('carries no zod', () => {
    const src = readFileSync(ENGINE_PATH, 'utf8');
    expect(src).not.toMatch(/ZodError|\$ZodType|safeParse/);
    expect(statSizeKb(src)).toBeLessThan(120);
  });
});

function statSizeKb(s: string): number {
  return Buffer.byteLength(s) / 1024;
}
