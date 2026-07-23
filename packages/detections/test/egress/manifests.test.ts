import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { EgressEcosystem } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { redactSnippet } from '../../src/egress/extract.ts';
import {
  extractManifestSdks,
  LOCKFILE_BASENAMES,
  type ManifestKind,
  manifestKindOf,
} from '../../src/egress/manifests.ts';
import { resolveSdk } from '../../src/egress/registry.ts';

const fixturesDir = join(fileURLToPath(new URL('.', import.meta.url)), '../../src/egress/fixtures');

interface ExpectedHit {
  ecosystem: EgressEcosystem;
  pkg: string;
  line: number;
}

interface ManifestCase {
  label: string;
  kind: ManifestKind;
  text: string | string[];
  expect: ExpectedHit[];
}

function loadCases(): ManifestCase[] {
  return JSON.parse(readFileSync(join(fixturesDir, 'manifests.json'), 'utf8')) as ManifestCase[];
}

function textOf(c: ManifestCase): string {
  return Array.isArray(c.text) ? c.text.join('\n') : c.text;
}

function byLineThenPkg(a: ExpectedHit, b: ExpectedHit): number {
  if (a.line !== b.line) return a.line - b.line;
  return a.pkg < b.pkg ? -1 : a.pkg > b.pkg ? 1 : 0;
}

const cases = loadCases();

describe('extractManifestSdks — fixture corpus', () => {
  it('carries at least 2 positive and 2 negative cases', () => {
    expect(cases.filter((c) => c.expect.length > 0).length).toBeGreaterThanOrEqual(2);
    expect(cases.filter((c) => c.expect.length === 0).length).toBeGreaterThanOrEqual(2);
  });

  it('covers every ManifestKind at least once', () => {
    const kinds: ManifestKind[] = [
      'package.json',
      'requirements.txt',
      'pyproject.toml',
      'go.mod',
      'pom.xml',
      'build.gradle',
      'Gemfile',
      'Cargo.toml',
      'composer.json',
      'csproj',
      'packages.config',
    ];
    const covered = new Set(cases.map((c) => c.kind));
    for (const kind of kinds) expect(covered.has(kind)).toBe(true);
  });

  it.each(cases.map((c) => [c.label, c] as const))('%s', (_label, c) => {
    const text = textOf(c);
    const hits = extractManifestSdks(text, c.kind);
    const actual = hits.map((h) => ({ ecosystem: h.ecosystem, pkg: h.pkg, line: h.line }));
    expect(actual.sort(byLineThenPkg)).toEqual([...c.expect].sort(byLineThenPkg));

    const sourceLines = text.split('\n');
    for (const hit of hits) {
      expect(hit.snippet.length).toBeLessThanOrEqual(200);
      // The snippet must come from the exact line the hit is attributed to,
      // not merely be some redacted line somewhere in the file.
      expect(hit.snippet).toBe(redactSnippet(sourceLines[hit.line - 1] ?? ''));
    }
  });
});

describe('extractManifestSdks — general shape', () => {
  it('returns nothing for a malformed package.json', () => {
    expect(extractManifestSdks('{ not valid json', 'package.json')).toEqual([]);
  });

  it('returns nothing for a malformed composer.json', () => {
    expect(extractManifestSdks('{ "require": ', 'composer.json')).toEqual([]);
  });

  it('carries a redacted, capped snippet on every hit', () => {
    const hits = extractManifestSdks("gem 'sentry-ruby'", 'Gemfile');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.snippet).toBe("gem 'sentry-ruby'");
  });
});

describe('PEP-503 normalization interop with resolveSdk', () => {
  it.each(['sentry_sdk==1.0.0', 'sentry-sdk==1.0.0', 'SENTRY_SDK==1.0.0'])(
    'requirements.txt line %s resolves to the sentry provider',
    (line) => {
      const hits = extractManifestSdks(line, 'requirements.txt');
      expect(hits).toHaveLength(1);
      const pkg = hits[0]?.pkg;
      expect(pkg).toBeDefined();
      expect(resolveSdk('pypi', pkg ?? '')?.id).toBe('sentry');
    },
  );
});

describe('manifestKindOf', () => {
  it.each<[string, ManifestKind | null]>([
    ['package.json', 'package.json'],
    ['requirements.txt', 'requirements.txt'],
    ['pyproject.toml', 'pyproject.toml'],
    ['go.mod', 'go.mod'],
    ['pom.xml', 'pom.xml'],
    ['build.gradle', 'build.gradle'],
    ['build.gradle.kts', 'build.gradle'],
    ['Gemfile', 'Gemfile'],
    ['Cargo.toml', 'Cargo.toml'],
    ['composer.json', 'composer.json'],
    ['Api.csproj', 'csproj'],
    ['MyLib.csproj', 'csproj'],
    ['packages.config', 'packages.config'],
    ['package-lock.json', null],
    ['yarn.lock', null],
    ['pnpm-lock.yaml', null],
    ['Cargo.lock', null],
    ['composer.lock', null],
    ['Gemfile.lock', null],
    ['poetry.lock', null],
    ['go.sum', null],
    ['packages.lock.json', null],
    ['README.md', null],
    ['Dockerfile', null],
    ['', null],
    // Object.prototype member names must not resolve through the prototype
    // chain of the plain-object basename table.
    ['constructor', null],
    ['toString', null],
    ['valueOf', null],
    ['hasOwnProperty', null],
    ['__proto__', null],
  ])('classifies %s as %s', (basename, kind) => {
    expect(manifestKindOf(basename)).toBe(kind);
  });
});

describe('LOCKFILE_BASENAMES', () => {
  it('holds exactly the nine known lockfile basenames', () => {
    expect([...LOCKFILE_BASENAMES].sort()).toEqual(
      [
        'package-lock.json',
        'yarn.lock',
        'pnpm-lock.yaml',
        'Cargo.lock',
        'composer.lock',
        'Gemfile.lock',
        'poetry.lock',
        'go.sum',
        'packages.lock.json',
      ].sort(),
    );
  });

  it('every member classifies to null via manifestKindOf', () => {
    for (const basename of LOCKFILE_BASENAMES) {
      expect(manifestKindOf(basename)).toBeNull();
    }
  });
});
