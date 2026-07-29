import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The /aka:setup triage path ships raw, unmasked findings to the judge
// subprocess — a deliberate, consent-gated carve-out. That carve-out must never
// silently gain vault tokenization: a triage module that starts calling the
// plugin-sdk vault glue would mint pointers for values that are ABOUT to leave
// the machine raw anyway, polluting the vault and misrepresenting what the
// judge path does. This test walks the static import graph from every triage
// module (following relative imports transitively) and asserts that no
// reachable source references the glue's symbols. A plain '@akasecurity/plugin-sdk'
// import stays allowed — only the tokenization surface is fenced off.

const SRC_DIR = fileURLToPath(new URL('../src', import.meta.url));
const TRIAGE_DIR = join(SRC_DIR, 'triage');

const GLUE_SYMBOLS = [
  'createVaultGlue',
  'tokenizeText',
  'tokenizeValue',
  'detokenizeText',
  'substituteModelPointers',
];

// Static import/export specifiers, including dynamic import(...) and bare
// side-effect imports. A regex over source text is deliberate: it is robust to
// refactors and needs no TS program.
function specifiersOf(source: string): string[] {
  const out: string[] = [];
  for (const re of [
    /from\s+['"]([^'"]+)['"]/g,
    /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /^import\s+['"]([^'"]+)['"]/gm,
  ]) {
    for (const match of source.matchAll(re)) {
      const spec = match[1];
      if (spec !== undefined) out.push(spec);
    }
  }
  return out;
}

// Resolve a relative specifier to a file on disk (imports in this repo carry
// their .ts extension, but tolerate the extensionless forms too).
function resolveLocal(fromFile: string, spec: string): string | null {
  const base = resolve(dirname(fromFile), spec);
  for (const candidate of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts')]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

// Every local module reachable from the triage entry files.
function reachableFiles(): Map<string, string> {
  const entries = readdirSync(TRIAGE_DIR)
    .filter((name) => name.endsWith('.ts'))
    .map((name) => join(TRIAGE_DIR, name));
  const seen = new Map<string, string>();
  const queue = [...entries];
  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || seen.has(file)) continue;
    const source = readFileSync(file, 'utf8');
    seen.set(file, source);
    for (const spec of specifiersOf(source)) {
      if (!spec.startsWith('.')) continue;
      const local = resolveLocal(file, spec);
      if (local !== null && !seen.has(local)) queue.push(local);
    }
  }
  return seen;
}

describe('triage import graph', () => {
  it('walks a non-trivial graph (sanity check on the walker itself)', () => {
    const files = reachableFiles();
    // Every triage module is in the set, plus at least one transitive import
    // from outside the directory — otherwise the walker is broken and the
    // guard below would pass vacuously.
    const triageCount = readdirSync(TRIAGE_DIR).filter((n) => n.endsWith('.ts')).length;
    expect(files.size).toBeGreaterThan(triageCount);
  });

  it('never reaches the plugin-sdk vault glue from a triage module', () => {
    const offenders: string[] = [];
    for (const [file, source] of reachableFiles()) {
      for (const symbol of GLUE_SYMBOLS) {
        if (new RegExp(`\\b${symbol}\\b`).test(source)) {
          offenders.push(`${file}: ${symbol}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
