import { readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// Drizzle defines the local-store and registry schemas, and this is the package
// that imports it. Every consumer is walled off by a lint ban on the specifier,
// and that ban sees only a specifier somebody WROTE — which is not the shape
// this failure takes. A value import of `@akasecurity/schema` that reaches a
// re-exported Drizzle module pulls the runtime in with the word appearing
// nowhere in the consumer, and with its lint, typecheck, test and build green.
// dashboard-ui and ui-kit render in a browser, so that lands in a user's bundle.
//
// So the property is about this package's ENTRY, not about any consumer: the `.`
// export must reach no drizzle-orm import that SURVIVES COMPILATION.
//
// The margin is one keyword, not one file. src/index.ts re-exports ./zod/index.ts
// -> ./zod/local.ts, which names ../drizzle/local/sqlite.ts — the one module here
// that imports drizzle-orm. That edge is `import type`, so TypeScript erases it
// and nothing ships. Drop the `type` and drizzle-orm is in the bundle, with no
// other file changing and no lint rule anywhere able to say so.

const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** The package's `.` export — what a bare `@akasecurity/schema` import resolves to. */
const ENTRY = 'src/index.ts';

/** The one module in this package that imports drizzle-orm. */
const DRIZZLE_MODULE = 'src/drizzle/local/sqlite.ts';

/** The type-only edge that keeps DRIZZLE_MODULE out of every consumer's bundle. */
const ERASED_EDGE = 'src/zod/local.ts';

const BANNED_PREFIX = 'drizzle-';

const posix = (p: string) => p.split('\\').join('/');
const abs = (rel: string) => join(PKG_ROOT, rel);

interface Edge {
  readonly specifier: string;
  /** False for `import type` / `export type`, which the compiler erases. */
  readonly emitted: boolean;
}

// Static and dynamic both, mirroring the lint ban's two halves — a walk that
// followed only `from '…'` would miss a lazily-imported module, the exact form
// the static ban cannot see either.
const STATIC_STATEMENT =
  /(?:^|\n)\s*(?:import|export)\s+(type\s+)?([\s\S]*?)from\s*['"]([^'"]+)['"]/g;
const DYNAMIC_CALL = /(?:^|[^\w.])(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

/** A brace list whose every binding is inline-`type` is erased too. */
function bindingsAllTypeOnly(body: string): boolean {
  const braced = /^\s*\{([^}]*)\}\s*$/.exec(body);
  if (braced?.[1] === undefined) return false;
  const bindings = braced[1]
    .split(',')
    .map((b) => b.trim())
    .filter((b) => b.length > 0);
  return bindings.length > 0 && bindings.every((b) => /^type\s/.test(b));
}

function edgesOf(file: string): Edge[] {
  const src = readFileSync(file, 'utf8');
  const edges: Edge[] = [];
  for (const m of src.matchAll(STATIC_STATEMENT)) {
    const [, typeKeyword, body = '', specifier] = m;
    if (specifier === undefined) continue;
    edges.push({
      specifier,
      emitted: typeKeyword === undefined && !bindingsAllTypeOnly(body),
    });
  }
  for (const m of src.matchAll(DYNAMIC_CALL)) {
    if (m[1] !== undefined) edges.push({ specifier: m[1], emitted: true });
  }
  return edges;
}

interface Graph {
  readonly files: string[];
  readonly externals: string[];
  readonly offenders: { file: string; specifier: string }[];
}

/**
 * Walk local imports transitively from `root`. `emittedOnly` follows just the
 * edges that survive compilation — the ones that decide what a bundle contains.
 */
function walk(root: string, { emittedOnly }: { emittedOnly: boolean }): Graph {
  const seen = new Set<string>();
  const externals = new Set<string>();
  const offenders: { file: string; specifier: string }[] = [];
  const queue = [abs(root)];

  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || seen.has(file)) continue;
    seen.add(file);

    for (const edge of edgesOf(file)) {
      if (emittedOnly && !edge.emitted) continue;
      if (edge.specifier.startsWith('.')) {
        queue.push(resolve(dirname(file), edge.specifier));
        continue;
      }
      externals.add(edge.specifier);
      if (edge.specifier.startsWith(BANNED_PREFIX)) {
        offenders.push({ file: posix(relative(PKG_ROOT, file)), specifier: edge.specifier });
      }
    }
  }

  return {
    files: [...seen].map((f) => posix(relative(PKG_ROOT, f))).sort(),
    externals: [...externals].sort(),
    offenders,
  };
}

describe('the package entry ships no Drizzle', () => {
  const emitted = walk(ENTRY, { emittedOnly: true });

  // Without this the suite is vacuous: a walker that resolved nothing returns an
  // empty graph and satisfies every absence assertion below.
  it('walked a real graph, so the assertions below are not vacuous', () => {
    expect(emitted.files.length).toBeGreaterThan(5);
    expect(emitted.files).toContain(ENTRY);
    expect(emitted.files).toContain('src/zod/local.ts');
    expect(emitted.externals).toContain('zod');
  });

  // The detector's positive control. Walking the module that DOES import
  // drizzle-orm must find it — otherwise "no offenders" means only that the
  // matcher is broken, and the guard passes however the entry changes.
  it('finds Drizzle when it walks the module that really imports it', () => {
    const direct = walk(DRIZZLE_MODULE, { emittedOnly: true });
    expect(direct.offenders.map((o) => o.specifier).sort()).toEqual([
      'drizzle-orm',
      'drizzle-orm/sqlite-core',
    ]);
  });

  it('reaches no emitted drizzle-orm import', () => {
    expect(
      emitted.offenders,
      emitted.offenders.length
        ? 'The `.` export of @akasecurity/schema now SHIPS Drizzle. Every consumer imports this ' +
            "entry, and dashboard-ui and ui-kit render in a browser, so this puts drizzle-orm's " +
            'runtime into a user bundle — and no lint ban can see it, because the specifier ' +
            'appears in no consumer. Make the edge `import type`, or move the export to the ' +
            './drizzle subpath:\n  ' +
            emitted.offenders.map((o) => `${o.file} -> ${o.specifier}`).join('\n  ')
        : undefined,
    ).toEqual([]);
  });

  // The margin itself. The entry DOES name the drizzle module — following every
  // edge reaches it — and the only thing stopping it shipping is that the edge is
  // type-only. Pin that, or the day it becomes a value import nothing here moves.
  it('reaches the drizzle module only through an erased edge', () => {
    const all = walk(ENTRY, { emittedOnly: false });
    expect(all.files, 'the entry no longer names the drizzle module at all').toContain(
      DRIZZLE_MODULE,
    );
    expect(
      emitted.files,
      `${ERASED_EDGE}'s import of ${DRIZZLE_MODULE} must stay \`import type\`: it is the only ` +
        'reason drizzle-orm is absent from every consumer bundle.',
    ).not.toContain(DRIZZLE_MODULE);
  });
});
