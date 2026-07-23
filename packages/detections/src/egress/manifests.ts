// Static SDK-dependency extraction for one dependency-manifest file's text: a
// project that declares a known provider's SDK is recorded as talking to that
// provider even with no URL literal anywhere in its source.
//
// Pure like everything in @akasecurity/detections: no I/O, no Node-API
// imports, no XML/TOML parser dependency — every parser here is line- or
// regex-oriented over raw text. Callers gate what reaches extractManifestSdks:
// resolve a basename with manifestKindOf first (lockfiles and unrecognized
// basenames return null and are never parsed).
import type { EgressEcosystem } from '@akasecurity/schema';

import { redactSnippet } from './extract.ts';
import { normalizePypi } from './registry.ts';

/** One dependency-manifest file kind this module knows how to parse. */
export type ManifestKind =
  | 'package.json'
  | 'requirements.txt'
  | 'pyproject.toml'
  | 'go.mod'
  | 'pom.xml'
  | 'build.gradle'
  | 'Gemfile'
  | 'Cargo.toml'
  | 'composer.json'
  | 'csproj'
  | 'packages.config';

/** One SDK dependency found in a manifest, attributing egress to its provider. */
export interface ManifestSdkHit {
  ecosystem: EgressEcosystem;
  /** Ecosystem-native identifier: PEP-503-normalized for pypi, raw otherwise. */
  pkg: string;
  /** 1-based, counted in the raw text. */
  line: number;
  /** Redacted, capped at 200 characters (see redactSnippet). */
  snippet: string;
}

// Lockfiles are regenerated dependency-resolution output: every transitive
// package's own registry download URL shows up as a literal, none of it real
// egress. Callers skip these basenames entirely before ever reaching
// manifestKindOf/extractManifestSdks.
export const LOCKFILE_BASENAMES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'Cargo.lock',
  'composer.lock',
  'Gemfile.lock',
  'poetry.lock',
  'go.sum',
  'packages.lock.json',
]);

const EXACT_KIND_BY_BASENAME: Readonly<Record<string, ManifestKind>> = {
  'package.json': 'package.json',
  'requirements.txt': 'requirements.txt',
  'pyproject.toml': 'pyproject.toml',
  'go.mod': 'go.mod',
  'pom.xml': 'pom.xml',
  'build.gradle': 'build.gradle',
  'build.gradle.kts': 'build.gradle',
  Gemfile: 'Gemfile',
  'Cargo.toml': 'Cargo.toml',
  'composer.json': 'composer.json',
  'packages.config': 'packages.config',
};

/**
 * Classify one file basename as a manifest kind, or null when it names no
 * manifest this module parses (including every LOCKFILE_BASENAMES member).
 */
export function manifestKindOf(basename: string): ManifestKind | null {
  if (LOCKFILE_BASENAMES.has(basename)) return null;
  // Object.hasOwn guards against basenames that collide with inherited
  // Object.prototype members ('constructor', 'toString', 'valueOf',
  // 'hasOwnProperty', '__proto__') — a plain bracket lookup resolves those
  // through the prototype chain instead of returning undefined.
  const exact = Object.hasOwn(EXACT_KIND_BY_BASENAME, basename)
    ? EXACT_KIND_BY_BASENAME[basename]
    : undefined;
  if (exact !== undefined) return exact;
  if (basename.endsWith('.csproj')) return 'csproj';
  return null;
}

/** Parse one manifest file's text for the SDK dependencies it declares. */
export function extractManifestSdks(text: string, kind: ManifestKind): ManifestSdkHit[] {
  switch (kind) {
    case 'package.json':
      return extractPackageJson(text);
    case 'requirements.txt':
      return extractRequirementsTxt(text);
    case 'pyproject.toml':
      return extractPyprojectToml(text);
    case 'go.mod':
      return extractGoMod(text);
    case 'pom.xml':
      return extractPomXml(text);
    case 'build.gradle':
      return extractBuildGradle(text);
    case 'Gemfile':
      return extractGemfile(text);
    case 'Cargo.toml':
      return extractCargoToml(text);
    case 'composer.json':
      return extractComposerJson(text);
    case 'csproj':
      return extractCsproj(text);
    case 'packages.config':
      return extractPackagesConfig(text);
    default:
      return [];
  }
}

function makeHit(
  ecosystem: EgressEcosystem,
  pkg: string,
  line: number,
  rawLine: string,
): ManifestSdkHit {
  return { ecosystem, pkg, line, snippet: redactSnippet(rawLine) };
}

// ── package.json (npm) ───────────────────────────────────────────────────

function extractPackageJson(text: string): ManifestSdkHit[] {
  const parsed = parseJson(text);
  if (parsed === null) return [];
  const seen = new Set<string>();
  const hits: ManifestSdkHit[] = [];
  for (const pkg of objectKeys(parsed.dependencies)) {
    seen.add(pkg);
    hits.push(hitAtQuotedKey('npm', pkg, text, 'dependencies'));
  }
  for (const pkg of objectKeys(parsed.optionalDependencies)) {
    if (seen.has(pkg)) continue;
    seen.add(pkg);
    hits.push(hitAtQuotedKey('npm', pkg, text, 'optionalDependencies'));
  }
  return hits;
}

// ── requirements.txt (pypi) ──────────────────────────────────────────────

// Package names are PEP 508's leading identifier (letters, digits, '.', '_',
// '-'); anything after it (version specifiers, extras, environment markers)
// is not part of the name. Option lines ('-r base.txt', '-e .', '--hash=...')
// and comment lines ('#...') both start with a character outside this class,
// so they never match.
const REQUIREMENTS_NAME = /^\s*([A-Za-z0-9][\w.-]*)/;

function extractRequirementsTxt(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  eachLine(text, (rawLine, lineNumber) => {
    const match = REQUIREMENTS_NAME.exec(rawLine);
    const name = match?.[1];
    if (name === undefined) return;
    hits.push(makeHit('pypi', normalizePypi(name), lineNumber, rawLine));
  });
  return hits;
}

// ── pyproject.toml (pypi) ────────────────────────────────────────────────

const TOML_SECTION = /^\s*\[([^\]]+)\]\s*$/;
const TOML_QUOTED = /"([^"]*)"|'([^']*)'/g;
const PEP508_NAME = /^([A-Za-z0-9][\w.-]*)/;
const POETRY_KEY = /^\s*([A-Za-z0-9][\w.-]*)\s*=/;

function extractPyprojectToml(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  let section = '';
  let inDependenciesArray = false;

  eachLine(text, (rawLine, lineNumber) => {
    const sectionMatch = TOML_SECTION.exec(rawLine);
    if (sectionMatch) {
      section = sectionMatch[1]?.trim() ?? '';
      inDependenciesArray = false;
      return;
    }

    if (!inDependenciesArray && /^\s*dependencies\s*=\s*\[/.test(rawLine)) {
      inDependenciesArray = true;
    }

    if (inDependenciesArray) {
      for (const spec of quotedStrings(rawLine)) {
        const name = PEP508_NAME.exec(spec)?.[1];
        if (name !== undefined)
          hits.push(makeHit('pypi', normalizePypi(name), lineNumber, rawLine));
      }
      if (rawLine.includes(']')) inDependenciesArray = false;
      return;
    }

    if (section === 'tool.poetry.dependencies') {
      const key = POETRY_KEY.exec(rawLine)?.[1];
      // 'python' pins the interpreter version, not a dependency — the same
      // platform-package exclusion composer.json applies to 'php'.
      if (key !== undefined && key !== 'python') {
        hits.push(makeHit('pypi', normalizePypi(key), lineNumber, rawLine));
      }
    }
  });

  return hits;
}

function quotedStrings(line: string): string[] {
  return [...line.matchAll(TOML_QUOTED)].map((m) => m[1] ?? m[2] ?? '');
}

// ── go.mod (go) ───────────────────────────────────────────────────────────

// go.mod has four block-form directives — require, exclude, replace, retract
// — that share the same `<keyword> (\n ... \n)` shape. Only require lines
// name a real dependency; exclude/replace/retract bodies name module paths
// too (an excluded version, a replacement target, a retracted range) but
// none of those are things the project actually talks to.
const GO_BLOCK_OPEN = /^\s*(require|exclude|replace|retract)\s*\(/;
const GO_BLOCK_CLOSE = /^\s*\)/;
const GO_REQUIRE_SINGLE_LINE = /^\s*require\s+([\w./-]+)\s+v\d/;
const GO_MODULE_VERSION_LINE = /^\s*([\w./-]+)\s+v\d/;

function extractGoMod(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  let blockKeyword: string | null = null;

  eachLine(text, (rawLine, lineNumber) => {
    if (blockKeyword === null) {
      const open = GO_BLOCK_OPEN.exec(rawLine)?.[1];
      if (open !== undefined) {
        blockKeyword = open;
        return;
      }
      const path = GO_REQUIRE_SINGLE_LINE.exec(rawLine)?.[1];
      if (path !== undefined) hits.push(makeHit('go', path, lineNumber, rawLine));
      return;
    }

    if (GO_BLOCK_CLOSE.test(rawLine)) {
      blockKeyword = null;
      return;
    }
    if (blockKeyword === 'require') {
      const path = GO_MODULE_VERSION_LINE.exec(rawLine)?.[1];
      if (path !== undefined) hits.push(makeHit('go', path, lineNumber, rawLine));
    }
  });

  return hits;
}

// ── pom.xml (maven) ──────────────────────────────────────────────────────

// Container elements whose ancestry decides whether a <groupId> names a real
// project dependency. Everything else (artifactId, version, scope, ...) is
// ignored for context purposes.
const POM_CONTEXT_TAGS = new Set([
  'project',
  'parent',
  'dependencyManagement',
  'dependencies',
  'dependency',
  'build',
  'plugins',
  'plugin',
  'exclusions',
  'exclusion',
]);
const XML_TAG = /<(\/?)([A-Za-z][\w.-]*)([^<>]*)>/g;
const LEADING_TEXT = /^([^<]*)/;

function extractPomXml(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  const stack: string[] = [];
  let inComment = false;

  eachLine(text, (rawLine, lineNumber) => {
    const stripped = stripXmlComments(rawLine, inComment);
    inComment = stripped.inComment;
    const visible = stripped.visible;

    for (const match of visible.matchAll(XML_TAG)) {
      const name = match[2];
      if (name === undefined) continue;
      const closing = match[1] === '/';
      const rest = match[3] ?? '';
      const selfClosing = rest.trimEnd().endsWith('/');

      if (closing) {
        if (POM_CONTEXT_TAGS.has(name) && stack[stack.length - 1] === name) stack.pop();
        continue;
      }
      if (selfClosing) continue;

      if (name === 'groupId') {
        const after = visible.slice(match.index + match[0].length);
        const value = LEADING_TEXT.exec(after)?.[1]?.trim() ?? '';
        if (value !== '' && isProjectDependencyGroupId(stack)) {
          hits.push(makeHit('maven', value, lineNumber, rawLine));
        }
        continue;
      }

      if (POM_CONTEXT_TAGS.has(name)) stack.push(name);
    }
  });

  return hits;
}

// A <groupId> names a real project dependency only directly under
// <dependencies><dependency> — excluding the project's own top-level
// coordinates, a <parent> block, anything under <dependencyManagement>
// (version pins, not dependencies), and anything under <build> (plugin
// coordinates, including a plugin's own nested <dependencies> config block).
function isProjectDependencyGroupId(stack: readonly string[]): boolean {
  return (
    stack[stack.length - 1] === 'dependency' &&
    stack[stack.length - 2] === 'dependencies' &&
    !stack.includes('dependencyManagement') &&
    !stack.includes('parent') &&
    !stack.includes('build')
  );
}

// ── build.gradle / build.gradle.kts (maven) ─────────────────────────────

// Matches implementation/api/compile dependency declarations in both the
// Groovy ('implementation "group:artifact:1.0"') and Kotlin DSL
// ('implementation("group:artifact:1.0")') forms, including the platform()
// BOM wrapper ('implementation platform("group:artifact-bom:1.0")').
const GRADLE_DEPENDENCY =
  /\b(?:implementation|api|compile)\b\s*[('"]*(?:platform\s*\(\s*['"])?([\w.-]+):[\w.-]+/g;
const LINE_COMMENT = /^\s*\/\//;

function extractBuildGradle(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  eachLine(text, (rawLine, lineNumber) => {
    if (LINE_COMMENT.test(rawLine)) return;
    for (const match of rawLine.matchAll(GRADLE_DEPENDENCY)) {
      const groupId = match[1];
      if (groupId !== undefined) hits.push(makeHit('maven', groupId, lineNumber, rawLine));
    }
  });
  return hits;
}

// ── Gemfile (rubygems) ────────────────────────────────────────────────────

const GEMFILE_DEPENDENCY = /^\s*gem\s+['"]([\w-]+)['"]/;

function extractGemfile(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  eachLine(text, (rawLine, lineNumber) => {
    const name = GEMFILE_DEPENDENCY.exec(rawLine)?.[1];
    if (name !== undefined) hits.push(makeHit('rubygems', name, lineNumber, rawLine));
  });
  return hits;
}

// ── Cargo.toml (cargo) ────────────────────────────────────────────────────

const CARGO_KEY = /^([A-Za-z0-9_-]+)\s*=/;

function extractCargoToml(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  // 'plain' is a bare [dependencies] table (crate = spec per line); 'dotted'
  // is a [dependencies.crate] table, where the crate name is the section
  // header itself and subsequent lines are detail fields, not new crates.
  let mode: 'none' | 'plain' | 'dotted' = 'none';

  eachLine(text, (rawLine, lineNumber) => {
    const sectionMatch = TOML_SECTION.exec(rawLine);
    if (sectionMatch) {
      const name = sectionMatch[1]?.trim() ?? '';
      if (name === 'dependencies') {
        mode = 'plain';
      } else if (name.startsWith('dependencies.')) {
        mode = 'dotted';
        const crate = name.slice('dependencies.'.length);
        if (crate !== '') hits.push(makeHit('cargo', crate, lineNumber, rawLine));
      } else {
        mode = 'none';
      }
      return;
    }

    if (mode === 'plain') {
      const crate = CARGO_KEY.exec(rawLine)?.[1];
      if (crate !== undefined) hits.push(makeHit('cargo', crate, lineNumber, rawLine));
    }
  });

  return hits;
}

// ── composer.json (composer) ─────────────────────────────────────────────

function extractComposerJson(text: string): ManifestSdkHit[] {
  const parsed = parseJson(text);
  if (parsed === null) return [];
  const pkgs = objectKeys(parsed.require).filter((pkg) => pkg !== 'php' && !pkg.startsWith('ext-'));
  return pkgs.map((pkg) => hitAtQuotedKey('composer', pkg, text, 'require'));
}

// ── .csproj (nuget) ───────────────────────────────────────────────────────

const CSPROJ_PACKAGE_REFERENCE = /<PackageReference\s+Include="([^"]+)"/;

function extractCsproj(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  let inComment = false;
  eachLine(text, (rawLine, lineNumber) => {
    const stripped = stripXmlComments(rawLine, inComment);
    inComment = stripped.inComment;
    const name = CSPROJ_PACKAGE_REFERENCE.exec(stripped.visible)?.[1];
    if (name !== undefined) hits.push(makeHit('nuget', name, lineNumber, rawLine));
  });
  return hits;
}

// ── packages.config (nuget) ───────────────────────────────────────────────

const PACKAGES_CONFIG_PACKAGE = /<package\s+id="([^"]+)"/;

function extractPackagesConfig(text: string): ManifestSdkHit[] {
  const hits: ManifestSdkHit[] = [];
  let inComment = false;
  eachLine(text, (rawLine, lineNumber) => {
    const stripped = stripXmlComments(rawLine, inComment);
    inComment = stripped.inComment;
    const name = PACKAGES_CONFIG_PACKAGE.exec(stripped.visible)?.[1];
    if (name !== undefined) hits.push(makeHit('nuget', name, lineNumber, rawLine));
  });
  return hits;
}

// ── shared helpers ────────────────────────────────────────────────────────

// Removes XML comment text from one line, carrying the "still inside a
// multi-line <!-- ... --> block" state across calls so a commented-out
// element spanning several lines is never read as live markup. A line with a
// same-line '<!--'...'-->' pair loses only the commented span; text before
// and after it stays visible.
function stripXmlComments(
  line: string,
  inComment: boolean,
): { visible: string; inComment: boolean } {
  let visible = '';
  let rest = line;
  let comment = inComment;

  for (;;) {
    if (comment) {
      const end = rest.indexOf('-->');
      if (end === -1) return { visible, inComment: true };
      rest = rest.slice(end + 3);
      comment = false;
      continue;
    }
    const start = rest.indexOf('<!--');
    if (start === -1) return { visible: visible + rest, inComment: false };
    visible += rest.slice(0, start);
    rest = rest.slice(start + 4);
    comment = true;
  }
}

function eachLine(text: string, fn: (rawLine: string, lineNumber: number) => void): void {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    fn(lines[i] ?? '', i + 1);
  }
}

interface JsonManifest {
  dependencies: unknown;
  optionalDependencies: unknown;
  require: unknown;
}

// Parses JSON manifest text into an untyped field lookup, tolerating a
// malformed file (returns null rather than throwing).
function parseJson(text: string): JsonManifest | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const record = parsed as Record<string, unknown>;
  return {
    dependencies: record.dependencies,
    optionalDependencies: record.optionalDependencies,
    require: record.require,
  };
}

function objectKeys(value: unknown): string[] {
  if (typeof value !== 'object' || value === null) return [];
  return Object.keys(value);
}

// Line of a JSON manifest's '"<pkg>"' occurrence inside the named owning
// section (e.g. 'dependencies', 'optionalDependencies', 'require') — scoped
// to that section's own key so a same-named entry in an earlier sibling
// section (devDependencies, require-dev, ...) is never mistaken for the
// production one. The keys this module reads always came from parsing that
// same text, so the quoted form is always present somewhere at or after the
// section key.
function hitAtQuotedKey(
  ecosystem: EgressEcosystem,
  pkg: string,
  text: string,
  sectionKey: string,
): ManifestSdkHit {
  const sectionStart = text.indexOf(`"${sectionKey}"`);
  const searchFrom = sectionStart === -1 ? 0 : sectionStart;
  const index = text.indexOf(`"${pkg}"`, searchFrom);
  if (index === -1) return makeHit(ecosystem, pkg, 1, pkg);
  return makeHit(ecosystem, pkg, lineNumberAt(text, index), lineContaining(text, index));
}

function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (text[i] === '\n') line += 1;
  }
  return line;
}

function lineContaining(text: string, index: number): string {
  const start = text.lastIndexOf('\n', index) + 1;
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? text.length : end);
}
