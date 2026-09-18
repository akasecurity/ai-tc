import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  crossPackageSpecifiers,
  declaredTestInputs,
  turboRootInput,
} from '../../../test/helpers/turbo-inputs.ts';
import { NAME, SETUP_DESCRIPTION, TAGLINE } from '../src/identity.ts';

function read(relative: string): string {
  return readFileSync(new URL(relative, import.meta.url), 'utf8');
}

const setupMd = read('../commands/setup.md');

// Reads the `description:` value from the leading YAML frontmatter block —
// the string Claude Code registers as the /aka:setup slash-command description.
function frontmatterDescription(source: string): string {
  const frontmatter = /^---\n([\s\S]*?)\n---/.exec(source)?.[1];
  const value = frontmatter ? /^description:[ \t]*(.*)$/m.exec(frontmatter)?.[1] : undefined;
  if (value === undefined) throw new Error('setup.md has no frontmatter description');
  return value.trim();
}

const STALE_SETUP_DESCRIPTION =
  'Set up the AKA Control Plane plugin — evidence-first detection posture and historical access';
const STALE_TAGLINE = 'Agent Harness Security for Claude Code.';

// The three READMEs whose prose must carry the canonical name and tagline.
const READMES = [
  ['repo-root README.md', '../../../README.md'],
  ['cli/README.md', '../../../cli/README.md'],
  ['plugins/claude-code/README.md', '../README.md'],
] as const;

interface Manifest {
  owner?: { name?: string };
  author?: { name?: string };
  version?: string;
}

function readManifest(relative: string): Manifest {
  return JSON.parse(read(relative)) as Manifest;
}

describe('identity/description consistency guard', () => {
  it('setup.md frontmatter description equals the canonical constant', () => {
    expect(frontmatterDescription(setupMd)).toBe(SETUP_DESCRIPTION);
  });

  it('setup.md carries no stale command description', () => {
    expect(setupMd).not.toContain(STALE_SETUP_DESCRIPTION);
  });

  it('setup.md body prose carries no phased-out product descriptor', () => {
    expect(setupMd).not.toContain('AKA Control Plane');
  });

  it('the shared triage rubric carries no phased-out product descriptor', () => {
    expect(read('../../../packages/setup-wizard/assets/triage-rubric.md')).not.toContain(
      'AKA Control Plane',
    );
  });

  it.each(READMES)('%s prose carries the canonical name and tagline', (_label, relative) => {
    const readme = read(relative);
    expect(readme).toContain(NAME);
    expect(readme).toContain(TAGLINE);
  });

  it.each(READMES)('%s carries no stale tagline variant', (_label, relative) => {
    expect(read(relative)).not.toContain(STALE_TAGLINE);
  });

  // The CLI's init copy single-sources its identity from @akasecurity/schema rather
  // than spelling the name and tagline out, so a substring scan for the literals
  // would fail. Pin the single-sourcing itself instead: the import of both
  // constants and the composed offer line. Scanning the source (not importing the
  // module) keeps this test off the CLI's dependency graph, which the plugin
  // workspace does not carry.
  it('cli init plugin-offer copy composes the identity from the canonical constants', () => {
    const initSource = read('../../../cli/src/commands/init.ts');
    expect(initSource).toContain('PRODUCT_NAME');
    expect(initSource).toContain('PRODUCT_TAGLINE');
    expect(initSource).toContain('@akasecurity/schema');
    expect(initSource).toContain('`${PRODUCT_NAME} — ${PRODUCT_TAGLINE}`');
  });

  it('marketplace.json owner name equals the canonical NAME', () => {
    const manifest = readManifest('../../../.claude-plugin/marketplace.json');
    expect(manifest.owner?.name).toBe(NAME);
  });

  it('plugin.json author name equals the canonical NAME', () => {
    const manifest = readManifest('../.claude-plugin/plugin.json');
    expect(manifest.author?.name).toBe(NAME);
  });

  it('plugin.json version equals package.json version (lockstep)', () => {
    const plugin = readManifest('../.claude-plugin/plugin.json');
    const pkg = readManifest('../package.json');
    expect(plugin.version).toBe(pkg.version);
  });
});

describe('turbo hashes every cross-package file this suite reads', () => {
  // Most of what this suite asserts is about files in other packages or in
  // none: the READMEs, the marketplace manifest, the CLI's init command, the
  // shared triage rubric. Unnamed, an edit to one leaves this task's hash
  // untouched and turbo replays a cached pass at the one moment the case
  // reading it exists to fail.
  //
  // The files are derived from this file's own relative literals rather than
  // listed, so a read added above is demanded here without anyone remembering.
  const packageDir = fileURLToPath(new URL('..', import.meta.url));
  const reads = crossPackageSpecifiers({
    testFile: fileURLToPath(import.meta.url),
    packageDir,
    repoRoot: fileURLToPath(new URL('../../..', import.meta.url)),
  });

  it('finds the reads it is meant to cover', () => {
    // Without this a scan that matched nothing would demand nothing, and the
    // membership check below would pass over an empty list.
    expect(reads).toEqual([
      '.claude-plugin/marketplace.json',
      'README.md',
      'cli/README.md',
      'cli/src/commands/init.ts',
      'packages/setup-wizard/assets/triage-rubric.md',
    ]);
  });

  it('names each of them in plugins/claude-code/turbo.json', () => {
    const inputs = declaredTestInputs(packageDir);
    expect(
      reads.filter((file) => !inputs.includes(turboRootInput(file))),
      'read by this suite and not hashed by its test task, so an edit there replays a cached pass',
    ).toEqual([]);
  });

  it("keeps the package's own files in the hash", () => {
    // Naming inputs REPLACES the default set, so dropping this entry would leave
    // the task hashing the cross-package files and nothing of this package.
    expect(declaredTestInputs(packageDir)).toContain('$TURBO_DEFAULT$');
  });
});
