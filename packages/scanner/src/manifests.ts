// Dependency-manifest discovery for the egress pass. The source walk
// (./walk.ts) only yields files whose extension is in SOURCE_EXTENSIONS, so it
// never sees package.json, go.mod, Gemfile or their siblings — yet a declared
// SDK dependency is egress evidence on its own, with no URL literal anywhere in
// the tree. This walk finds those files.
//
// Stat-only: the returned candidates carry the mtime and size the scan ledger
// needs to decide "unchanged, skip", and nothing is read here. The caller reads
// content only for the candidates that survive that decision.
import { type Dirent, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';

import type { ManifestKind } from '@akasecurity/plugin-sdk';
import { manifestKindOf } from '@akasecurity/plugin-sdk';

import { SKIP_DIRS } from './walk.ts';

// Matches the source walk's default cap, so one oversized generated manifest
// costs the same as one oversized source file.
const MAX_MANIFEST_BYTES = 512 * 1024;

/** One dependency manifest found on disk, before its content is read. */
export interface ManifestCandidate {
  path: string; // absolute path
  kind: ManifestKind;
  mtime: string; // ISO timestamp, same form as the scan ledger stores
  size: number; // bytes
}

/**
 * Find every dependency manifest under `rootDir`, skipping the same directories
 * the source walk skips and any file over `maxFileSizeBytes`. Basenames are
 * classified by `manifestKindOf`, which returns null for lockfiles and for
 * anything this pass does not parse — those are never returned. Best-effort:
 * an unreadable directory or entry is skipped rather than aborting the walk.
 */
export function collectManifests(
  rootDir: string,
  maxFileSizeBytes: number = MAX_MANIFEST_BYTES,
): ManifestCandidate[] {
  const found: ManifestCandidate[] = [];

  const visit = (dir: string): void => {
    let dirents: Dirent[];
    try {
      dirents = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
    } catch {
      return;
    }

    for (const entry of dirents) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) visit(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;

      const kind = manifestKindOf(basename(entry.name));
      if (kind === null) continue;

      try {
        const st = statSync(fullPath);
        if (st.size > maxFileSizeBytes) continue;
        found.push({ path: fullPath, kind, mtime: st.mtime.toISOString(), size: st.size });
      } catch {
        continue;
      }
    }
  };

  visit(rootDir);
  return found;
}
