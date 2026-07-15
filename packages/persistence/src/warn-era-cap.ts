import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { SimpleDetectionPolicy } from '@akasecurity/schema';

import type { LocalDatabase } from './database.ts';
import { DATA_FILE_MODE } from './paths.ts';

const MARKER = 'warn-era-capped';

// Caps existing block/redact category policies to warn, once, for a store
// whose onboarding handling was 'warn'. A redact-era store is a no-op.
// Marker-guarded: runs at most once per dataDir, ever.
export function capWarnEraEnforcementOnce(
  db: LocalDatabase,
  policyMode: SimpleDetectionPolicy,
  dataDir: string,
): { capped: number; skipped?: 'not-warn' | 'already-run' } {
  if (policyMode !== 'warn') return { capped: 0, skipped: 'not-warn' };
  const marker = join(dataDir, MARKER);
  if (existsSync(marker)) return { capped: 0, skipped: 'already-run' };

  const capped = db.policies.capCategoryActions();
  writeFileSync(marker, `${new Date(Date.now()).toISOString()}\n`, { mode: DATA_FILE_MODE });
  return { capped };
}
