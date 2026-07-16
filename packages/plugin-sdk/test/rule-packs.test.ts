import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getLoadedRules, scan } from '@akasecurity/detections';
import { PackManifest, Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { bundledDetections, registerBundledPacks, uniqueRuleIds } from '../src/rule-packs.ts';

// The repo-root rules/ registry the bundle is generated from — resolved from this
// file (packages/plugin-sdk/src/) so the test reads the SAME source the generator
// does, and fails if the committed bundled-packs.generated.ts drifts from it.
const RULES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'rules');

function onDiskPacks(): { id: string; name: string; version: string; ruleStems: string[] }[] {
  return readdirSync(RULES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(RULES_DIR, d.name, 'manifest.json')))
    .map((d) => {
      const m = PackManifest.parse(
        JSON.parse(readFileSync(join(RULES_DIR, d.name, 'manifest.json'), 'utf8')),
      );
      return { id: m.id, name: m.name, version: m.version, ruleStems: m.rules };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}

describe('registerBundledPacks', () => {
  it('loads the bundled secret + PII rule JSON and makes it scannable', () => {
    registerBundledPacks();
    // Every rule the on-disk manifests declare is loaded (full registry, no subset).
    const expectedRules = onDiskPacks().reduce((n, p) => n + p.ruleStems.length, 0);
    expect(getLoadedRules().length).toBe(expectedRules);
    // A canonical AWS key is caught by the bundled secret pack.
    const findings = scan('export AWS_KEY=AKIAIOSFODNN7EXAMPLE');
    expect(findings.some((f) => f.category === 'secret')).toBe(true);
  });
});

describe('bundledDetections', () => {
  it('covers the complete on-disk registry — every pack, every manifest rule', () => {
    const disk = onDiskPacks();
    const packs = bundledDetections();

    // Same set of packs as the rules/ directory (no hand-maintained subset).
    expect(packs.map((p) => p.packId).sort()).toEqual(disk.map((p) => p.id));

    for (const d of disk) {
      const bundled = packs.find((p) => p.packId === d.id);
      expect(bundled, `pack ${d.id} is bundled`).toBeDefined();
      expect(bundled?.namespace).toBe('aka');
      expect(bundled?.name).toBe(d.name);
      expect(bundled?.version).toBe(d.version);
      // The EXACT set of manifest-declared ids — not just the count. A count +
      // prefix check would pass a same-count swap (drop one stem, add another,
      // leave the old .json on disk, forget to regenerate); the id-set equality
      // catches that and ships the right rules or fails CI.
      const expectedIds = d.ruleStems.map((stem: string) => `${d.id}/${stem}`).sort();
      expect((bundled?.rules.map((r) => r.id) ?? []).sort()).toEqual(expectedIds);
      // Every bundled rule parses against the versioned Rule schema.
      expect(() => bundled?.rules.forEach((r) => Rule.parse(r))).not.toThrow();
    }
  });
});

describe('uniqueRuleIds', () => {
  it('dedupes and joins rule ids for a one-line summary', () => {
    expect(uniqueRuleIds([{ ruleId: 'a' }, { ruleId: 'a' }, { ruleId: 'b' }])).toBe('a, b');
    expect(uniqueRuleIds([])).toBe('');
  });
});
