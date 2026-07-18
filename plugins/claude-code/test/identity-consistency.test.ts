import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

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

  it.each(READMES)('%s prose carries the canonical name and tagline', (_label, relative) => {
    const readme = read(relative);
    expect(readme).toContain(NAME);
    expect(readme).toContain(TAGLINE);
  });

  it.each(READMES)('%s carries no stale tagline variant', (_label, relative) => {
    expect(read(relative)).not.toContain(STALE_TAGLINE);
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
