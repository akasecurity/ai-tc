// Dependency-manifest discovery for the egress pass. The source walk
// (./walk.ts) only yields files whose extension is in SOURCE_EXTENSIONS, so it
// never sees package.json, go.mod, Gemfile or their siblings — yet a declared
// SDK dependency is egress evidence on its own, with no URL literal anywhere in
// the tree. This walk finds those files.
//
// File discovery is delegated to walkTree (./walk.ts) so this walk honors
// SKIP_DIRS and .akaignore — including `!` negations — with exactly the same
// interpretation the source walk uses, rather than a second implementation
// that could silently diverge from it.
//
// Stat-only: the returned candidates carry the mtime and size the scan ledger
// needs to decide "unchanged, skip", and nothing is read here. The caller reads
// content only for the candidates that survive that decision.
import { statSync } from 'node:fs';

import type { ManifestKind } from '@akasecurity/plugin-sdk';
import { manifestKindOf } from '@akasecurity/plugin-sdk';

import { walkTree } from './walk.ts';

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
 * Find every dependency manifest under `rootDir`, skipping the same
 * directories and .akaignore matches the source walk skips, and any file over
 * `maxFileSizeBytes`. Basenames are classified by `manifestKindOf`, which
 * returns null for lockfiles and for anything this pass does not parse —
 * those are never returned. Best-effort: an unreadable directory or entry is
 * skipped rather than aborting the walk.
 */
export function collectManifests(
  rootDir: string,
  maxFileSizeBytes: number = MAX_MANIFEST_BYTES,
): ManifestCandidate[] {
  const found: ManifestCandidate[] = [];

  for (const file of walkTree(rootDir)) {
    const kind = manifestKindOf(file.name);
    if (kind === null) continue;

    try {
      const st = statSync(file.path);
      if (st.size > maxFileSizeBytes) continue;
      found.push({ path: file.path, kind, mtime: st.mtime.toISOString(), size: st.size });
    } catch {
      continue;
    }
  }

  return found;
}
