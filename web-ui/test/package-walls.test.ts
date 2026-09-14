import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The human reveal path (web dashboard → vault) must reach the vault ONLY
// through @akasecurity/persistence. Neither web-ui nor @akasecurity/dashboard-ui may take a
// runtime dependency on the plugin stack — the plugin SDK's vault glue is
// hook-path machinery, and pulling it into the dashboard would route reveals
// around the persistence wall. web-ui's devDependencies legitimately carry
// @akasecurity/plugin-sdk for test-fixture seeding (a documented dev-only
// exception), which is why only the runtime edges are pinned here.

const FORBIDDEN = [
  '@akasecurity/plugin-sdk',
  '@akasecurity/plugin-runtime',
  '@akasecurity/ai-tc-claude-code',
];

interface PackageManifest {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

function runtimeDeps(relativePath: string): string[] {
  const file = fileURLToPath(new URL(relativePath, import.meta.url));
  const pkg = JSON.parse(readFileSync(file, 'utf8')) as PackageManifest;
  return [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.peerDependencies ?? {})];
}

describe('package walls — the human reveal path', () => {
  it('web-ui has no runtime dependency on the plugin stack', () => {
    const deps = runtimeDeps('../package.json');
    for (const name of FORBIDDEN) {
      expect(deps).not.toContain(name);
    }
    // The wall is about the route, not isolation: persistence IS the vault path.
    expect(deps).toContain('@akasecurity/persistence');
  });

  it('@akasecurity/dashboard-ui has no runtime dependency on the plugin stack', () => {
    const deps = runtimeDeps('../../packages/dashboard-ui/package.json');
    for (const name of FORBIDDEN) {
      expect(deps).not.toContain(name);
    }
  });
});

// Dependency lists alone cannot pin the wall: plugin-sdk is a legitimate
// web-ui DEV dependency (test-fixture seeding), so a runtime import added to
// app code would resolve and typecheck. Walk the actual source import
// specifiers instead.
describe('runtime source imports stay behind the wall', () => {
  const FORBIDDEN = /@akasecurity\/(plugin-sdk|plugin-runtime|ai-tc-claude-code)/;

  function walk(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
        out.push(...walk(full));
      } else if (/\.(ts|tsx)$/.test(entry.name)) {
        out.push(full);
      }
    }
    return out;
  }

  it('no web-ui app file or dashboard-ui source file imports a plugin package', () => {
    const roots = [
      fileURLToPath(new URL('../app', import.meta.url)),
      fileURLToPath(new URL('../../packages/dashboard-ui/src', import.meta.url)),
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const file of walk(root)) {
        const source = readFileSync(file, 'utf8');
        for (const line of source.split('\n')) {
          if (/^\s*(import|export)\b/.test(line) && FORBIDDEN.test(line)) {
            offenders.push(file);
            break;
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  // `@akasecurity/dashboard-ui` is consumed by more than this app, so it must not
  // reach for a router. The package declares no `next` dependency, but nothing
  // stopped an import: it resolves here through the workspace, typechecks, and
  // ships a view that only works under Next.
  //
  // The href props on the security widgets rest on exactly this — the views take
  // link targets as strings and the host builds them — so the guarantee is worth a
  // failing test rather than a convention.
  it('no dashboard-ui source file imports next', () => {
    const root = fileURLToPath(new URL('../../packages/dashboard-ui/src', import.meta.url));
    const files = walk(root);
    // The vacuity control: a wrong root would walk nothing and read as a clean pass.
    expect(files.length).toBeGreaterThan(20);

    // COMMENTS ARE STRIPPED FIRST, and that is not tidiness. A pattern that spans
    // lines has to, because it cannot tell code from prose: this package documents
    // its own rule in six "router-agnostic" doc comments, and one extended to quote
    // a specifier would fail the guard on the file that just became more compliant.
    //
    // The `[^:]` guard keeps `https://` inside a string from being read as a line
    // comment.
    const stripComments = (source: string): string =>
      source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

    // Anchored to the START of a statement, then allowed to run to the specifier.
    // `[^;]` spans newlines, so the prettier-wrapped form every multi-name import in
    // this directory uses is still caught — the `import {` line carries no `from`,
    // and the `} from 'next/navigation';` line does not start with `import`, so a
    // per-line test sees neither.
    //
    // Four forms, all of which reach the module: a static or re-exported specifier,
    // a bare side-effect import, and a dynamic `import()`/`require()` — which §4's
    // own module bans treat as equivalent to a static one.
    const NEXT = String.raw`['"]next(?:\/[^'"]*)?['"]`;
    const patterns = [
      // Quotes are excluded from the span before `from` — a string literal on an
      // `export` statement would otherwise trip this — but allowed INSIDE a brace
      // group, because an ES2022 arbitrary module namespace name puts one there:
      // `import { "x" as y } from 'next/link'` is a real import of `next`.
      // Excluding quotes everywhere closed the false positive and opened that as a
      // false negative; the brace group is what separates the two.
      new RegExp(String.raw`^\s*(?:import|export)(?:[^;'"{]|\{[^}]*\})*?\bfrom\s*${NEXT}`, 'm'),
      new RegExp(String.raw`^\s*import\s*${NEXT}`, 'm'),
      new RegExp(String.raw`\bimport\s*\(\s*${NEXT}`),
      new RegExp(String.raw`\brequire\s*\(\s*${NEXT}`),
    ];
    const offenders = files.filter((file) => {
      const source = stripComments(readFileSync(file, 'utf8'));
      return patterns.some((re) => re.test(source));
    });
    expect(offenders).toEqual([]);
  });
});
