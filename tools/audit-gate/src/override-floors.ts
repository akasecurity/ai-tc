// Reviews the floors in the root `pnpm.overrides`: an override whose value is a
// single lower bound (`^x.y.z`, `~x.y.z` or `>=x.y.z`) on a package the lockfile
// resolves. A floor is stale when its package (or the major it names) is gone
// from the lockfile, or when resolving the workspace without the floors puts
// nothing below it. Exact pins, aliases and removals are not floors and are not
// reviewed.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve as resolvePath } from 'node:path';

export interface Version {
  major: number;
  minor: number;
  patch: number;
  prerelease: string;
}

export type FloorSelector =
  { kind: 'any' } | { kind: 'major'; major: number } | { kind: 'below'; version: Version };

export interface OverrideFloor {
  selector: string;
  floor: string;
  name: string;
  matches: FloorSelector;
  minimum: Version;
}

export interface StaleOverride {
  selector: string;
  floor: string;
  why: string;
}

export interface OverrideReview {
  stale: StaleOverride[];
  unchecked: StaleOverride[];
  error?: string;
}

export type LockfileVersions = Map<string, Version[]>;

const VERSION = /^(\d+)(?:\.(\d+)(?:\.(\d+)(?:-([0-9A-Za-z.-]+))?)?)?$/;
const FLOOR_OPERATOR = /^(?:\^|~|>=)/;
const FLOOR = /^(?:\^|~|>=)\s*(\S+)$/;

export function parseVersion(text: string): Version | undefined {
  const match = VERSION.exec(text.trim());
  if (!match) return undefined;
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    prerelease: match[4] ?? '',
  };
}

export function compareVersions(a: Version, b: Version): number {
  for (const part of ['major', 'minor', 'patch'] as const) {
    if (a[part] !== b[part]) return a[part] - b[part];
  }
  if (a.prerelease === b.prerelease) return 0;
  // A prerelease sorts before its release.
  if (a.prerelease === '') return 1;
  if (b.prerelease === '') return -1;
  return comparePrerelease(a.prerelease.split('.'), b.prerelease.split('.'));
}

const NUMERIC = /^\d+$/;

// Semver precedence: identifiers compare left to right, numeric ones by value
// and below any alphanumeric one, and a shorter list sorts first when it is a
// prefix of the longer.
function comparePrerelease(a: string[], b: string[]): number {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const left = a[i] ?? '';
    const right = b[i] ?? '';
    if (left === right) continue;
    const leftNumeric = NUMERIC.test(left);
    const rightNumeric = NUMERIC.test(right);
    if (leftNumeric && rightNumeric) return Number(left) - Number(right);
    if (leftNumeric) return -1;
    if (rightNumeric) return 1;
    return left < right ? -1 : 1;
  }
  return a.length - b.length;
}

export const formatVersion = (version: Version): string =>
  `${String(version.major)}.${String(version.minor)}.${String(version.patch)}${version.prerelease ? `-${version.prerelease}` : ''}`;

// Splits `name@spec` at the `@` that follows the name, so a scoped name keeps
// its leading `@`.
function splitAtVersion(key: string): [string, string | undefined] {
  const at = key.indexOf('@', 1);
  return at === -1 ? [key, undefined] : [key.slice(0, at), key.slice(at + 1)];
}

/**
 * Sorts the root overrides into floors this review can judge and floors it
 * cannot. A value that is not a lower bound is not a floor and appears in
 * neither list.
 */
export function parseOverrideFloors(overrides: Record<string, unknown>): {
  floors: OverrideFloor[];
  unchecked: StaleOverride[];
} {
  const floors: OverrideFloor[] = [];
  const unchecked: StaleOverride[] = [];
  for (const [selector, value] of Object.entries(overrides)) {
    if (typeof value !== 'string') continue;
    const bound = FLOOR.exec(value.trim());
    const minimum = bound?.[1] === undefined ? undefined : parseVersion(bound[1]);
    if (minimum === undefined) {
      if (FLOOR_OPERATOR.test(value.trim())) {
        unchecked.push({ selector, floor: value, why: 'the value is not a single lower bound' });
      }
      continue;
    }

    if (selector.includes('>')) {
      unchecked.push({ selector, floor: value, why: 'a parent-scoped selector is not reviewed' });
      continue;
    }
    const [name, spec] = splitAtVersion(selector);
    let matches: FloorSelector | undefined;
    if (spec === undefined) {
      matches = { kind: 'any' };
    } else if (/^\d+$/.test(spec)) {
      matches = { kind: 'major', major: Number(spec) };
    } else {
      const below = /^<\s*(\S+)$/.exec(spec);
      const version = below?.[1] === undefined ? undefined : parseVersion(below[1]);
      if (version !== undefined) matches = { kind: 'below', version };
    }
    if (matches === undefined) {
      unchecked.push({
        selector,
        floor: value,
        why: `selector \`${spec ?? ''}\` is not one of: a bare name, \`name@major\`, \`name@<version\``,
      });
      continue;
    }
    floors.push({ selector, floor: value, name, matches, minimum });
  }
  return { floors, unchecked };
}

const unquote = (text: string): string => text.replace(/^(['"])(.*)\1$/, '$2');

// The keys of one top-level lockfile section: the lines indented by exactly two
// spaces and ending in `:`, up to the next top-level key.
function sectionKeys(lockfile: string, section: string): string[] {
  const keys: string[] = [];
  let inside = false;
  for (const line of lockfile.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inside = line === `${section}:`;
      continue;
    }
    if (!inside) continue;
    const key = /^ {2}(\S.*):$/.exec(line)?.[1];
    if (key !== undefined) keys.push(unquote(key));
  }
  return keys;
}

/** Every registry version the lockfile resolves, by package name. */
export function lockfileVersions(lockfile: string): LockfileVersions {
  const versions: LockfileVersions = new Map();
  for (const key of sectionKeys(lockfile, 'packages')) {
    const [name, spec] = splitAtVersion(key);
    const version = spec === undefined ? undefined : parseVersion(spec.replace(/\(.*$/, ''));
    if (version === undefined) continue;
    const list = versions.get(name) ?? [];
    list.push(version);
    versions.set(name, list);
  }
  return versions;
}

/** The workspace directories the lockfile records, relative to its root. */
export const lockfileImporters = (lockfile: string): string[] => sectionKeys(lockfile, 'importers');

function selected(floor: OverrideFloor, version: Version): boolean {
  switch (floor.matches.kind) {
    case 'any':
      return true;
    case 'major':
      return version.major === floor.matches.major;
    case 'below':
      return compareVersions(version, floor.matches.version) < 0;
  }
}

function describeTarget(floor: OverrideFloor): string {
  return floor.matches.kind === 'major'
    ? `${floor.name}@${String(floor.matches.major)}`
    : floor.name;
}

/**
 * Judges each floor against the lockfile as committed (`current`) and as pnpm
 * resolves it with the floors removed (`floorless`). A `floorless` that is a
 * string is the reason that resolution could not be made; floors still present
 * in the tree are then reported as unchecked rather than guessed at.
 */
export function reviewOverrideFloors(
  floors: OverrideFloor[],
  current: LockfileVersions,
  floorless: LockfileVersions | string,
): Pick<OverrideReview, 'stale' | 'unchecked'> {
  // An empty parse cannot tell a package that left the tree from a lockfile
  // whose shape was not read, and calling every floor stale would tell the
  // reader to remove live ones.
  if (current.size === 0) {
    return {
      stale: [],
      unchecked: floors.map((floor) => ({
        selector: floor.selector,
        floor: floor.floor,
        why: 'no versions could be read from pnpm-lock.yaml',
      })),
    };
  }
  const stale: StaleOverride[] = [];
  const unchecked: StaleOverride[] = [];
  for (const floor of floors) {
    const entry = { selector: floor.selector, floor: floor.floor };
    const present = current.get(floor.name) ?? [];
    // A `<version` selector rewrites every version it matches, so after the
    // override only the package name can still be looked for.
    const inTree =
      floor.matches.kind === 'below'
        ? present.length > 0
        : present.some((version) => selected(floor, version));
    if (!inTree) {
      stale.push({ ...entry, why: `no ${describeTarget(floor)} left in pnpm-lock.yaml` });
      continue;
    }
    if (typeof floorless === 'string') {
      unchecked.push({ ...entry, why: floorless });
      continue;
    }
    const below = (floorless.get(floor.name) ?? [])
      .filter((version) => selected(floor, version))
      .filter((version) => compareVersions(version, floor.minimum) < 0);
    if (below.length === 0) {
      stale.push({
        ...entry,
        why: `without the override nothing resolves below ${formatVersion(floor.minimum)}`,
      });
    }
  }
  return { stale, unchecked };
}

function insideRoot(root: string, path: string): string | undefined {
  const target = resolvePath(root, path);
  const fromRoot = relative(root, target);
  return fromRoot === '' || fromRoot.startsWith('..') || isAbsolute(fromRoot) ? undefined : target;
}

/**
 * Writes a copy of the workspace's manifests into `dest` with the given floors
 * removed from the root `pnpm.overrides`, ready for
 * `pnpm install --lockfile-only`. Copies the lockfile, `pnpm-workspace.yaml`,
 * `.npmrc` and every importer's `package.json`; nothing else is needed to
 * resolve.
 */
export function writeFloorlessWorkspace(
  repoRoot: string,
  dest: string,
  floorSelectors: string[],
): void {
  const lockfile = readFileSync(join(repoRoot, 'pnpm-lock.yaml'), 'utf8');
  writeFileSync(join(dest, 'pnpm-lock.yaml'), lockfile);
  for (const file of ['pnpm-workspace.yaml', '.npmrc']) {
    const source = join(repoRoot, file);
    if (existsSync(source)) writeFileSync(join(dest, file), readFileSync(source));
  }
  for (const importer of lockfileImporters(lockfile)) {
    if (importer === '.') continue;
    const source = insideRoot(repoRoot, join(importer, 'package.json'));
    const target = insideRoot(dest, join(importer, 'package.json'));
    if (source === undefined || target === undefined || !existsSync(source)) continue;
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, readFileSync(source));
  }

  const manifest = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
    pnpm?: { overrides?: Record<string, unknown> };
  };
  if (manifest.pnpm?.overrides !== undefined) {
    const removed = new Set(floorSelectors);
    const kept = Object.entries(manifest.pnpm.overrides).filter(([key]) => !removed.has(key));
    if (kept.length > 0) manifest.pnpm.overrides = Object.fromEntries(kept);
    else delete manifest.pnpm.overrides;
  }
  writeFileSync(join(dest, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
}

// pnpm prints its error code after a banner of warnings, so the report starts
// from the code where there is one.
const errorText = (error: unknown): string => {
  const text = (error instanceof Error ? error.message : String(error)).replace(/\s+/g, ' ').trim();
  const code = text.indexOf('ERR_PNPM_');
  return (code === -1 ? text : text.slice(code)).slice(0, 400);
};

/**
 * Reviews every floor in the root `pnpm.overrides` of `repoRoot`. `resolve`
 * is handed a directory written by `writeFloorlessWorkspace` and must leave a
 * re-resolved `pnpm-lock.yaml` in it; a throw from it marks the floors still in
 * the tree as unchecked. Never throws: a review that cannot start reports why in
 * `error`.
 */
export function reviewRootOverrides(
  repoRoot: string,
  resolve: (workspaceDir: string) => void,
): OverrideReview {
  let overrides: Record<string, unknown>;
  let lockfile: string;
  try {
    const manifest = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
      pnpm?: { overrides?: Record<string, unknown> };
    } | null;
    overrides = manifest?.pnpm?.overrides ?? {};
    lockfile = readFileSync(join(repoRoot, 'pnpm-lock.yaml'), 'utf8');
  } catch (error) {
    return { stale: [], unchecked: [], error: `could not read the overrides: ${errorText(error)}` };
  }

  const { floors, unchecked } = parseOverrideFloors(overrides);
  if (floors.length === 0) return { stale: [], unchecked };

  let floorless: LockfileVersions | string;
  let resolveError: string | undefined;
  const dir = mkdtempSync(join(tmpdir(), 'override-floors-'));
  try {
    writeFloorlessWorkspace(
      repoRoot,
      dir,
      floors.map((floor) => floor.selector),
    );
    resolve(dir);
    floorless = lockfileVersions(readFileSync(join(dir, 'pnpm-lock.yaml'), 'utf8'));
  } catch (failure) {
    resolveError = `pnpm could not resolve the workspace without the floors: ${errorText(failure)}`;
    floorless = 'the workspace could not be resolved without the floors';
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const review = reviewOverrideFloors(floors, lockfileVersions(lockfile), floorless);
  const result: OverrideReview = {
    stale: review.stale,
    unchecked: [...unchecked, ...review.unchecked],
  };
  if (resolveError !== undefined) result.error = resolveError;
  return result;
}
