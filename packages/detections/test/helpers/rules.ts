import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import type { Rule } from '@akasecurity/schema';
import { Rule as RuleSchema } from '@akasecurity/schema';

// Shared rule-discovery primitives for the test suites that walk `rules/`.
//
// The fixtures gate (`engine.test.ts`) and the ReDoS gate (`security/redos.test.ts`)
// both need to find and parse every bundled rule. Keeping the walk in one place
// means the two cannot drift: if a future layout change silently dropped a pack
// from discovery, both suites would shrink together — and the fixtures gate's
// per-rule tests would surface it — rather than one quietly gating fewer rules.

// Repo-root `rules/`, resolved from this file. `test/helpers/` sits two levels
// under `packages/detections/`, so four hops reach the repo root.
export const RULES_DIR = resolve(__dirname, '../../../../rules');

export interface BundledRuleFile {
  /** Pack directory name, e.g. `core-pii`. */
  packDir: string;
  /** Absolute path to the pack directory. */
  packDirAbs: string;
  /** Rule file stem (no extension), e.g. `email`. */
  ruleFile: string;
}

/** Every pack directory name under `rules/` — the raw listing, manifest or not. */
export function bundledPackDirs(): string[] {
  return readdirSync(RULES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);
}

/** Every manifest-listed rule file across every pack. */
export function discoverBundledRuleFiles(): BundledRuleFile[] {
  const out: BundledRuleFile[] = [];
  for (const packDir of bundledPackDirs()) {
    const packDirAbs = resolve(RULES_DIR, packDir);
    const manifestPath = resolve(packDirAbs, 'manifest.json');
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as { rules: string[] };
    for (const ruleFile of manifest.rules) out.push({ packDir, packDirAbs, ruleFile });
  }
  return out;
}

/** Parse a single rule JSON. `packDirAbs` is an absolute pack directory path. */
export function loadRule(packDirAbs: string, ruleFile: string): Rule {
  const raw: unknown = JSON.parse(readFileSync(resolve(packDirAbs, `${ruleFile}.json`), 'utf-8'));
  return RuleSchema.parse(raw);
}
