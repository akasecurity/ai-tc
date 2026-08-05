import type { LocalDatabase } from '@akasecurity/persistence';

import { renderPosture } from './render.ts';

// The install-complete card's per-category posture block, read from the local
// store (the wizard's policy write) so the card shows what's actually enforced
// rather than the single settings.policy string.
//
// Best-effort by design: this OWNS the catch so a policies fault degrades to ''
// — renderFirstRun then hides only the Posture section instead of letting the
// throw propagate to firstrun's outer fail-open handler and collapse the entire
// card into the store-unavailable note. The store is opened INSIDE the guarded
// scope via the injected opener, so an open failure degrades identically to a
// read failure. Always closes the handle when one was opened, on both paths.
export async function readPostureBlock(
  open: () => Pick<LocalDatabase, 'policies' | 'close'>,
): Promise<string> {
  let db: Pick<LocalDatabase, 'policies' | 'close'> | undefined;
  try {
    db = open();
    const policies = await db.policies.readPolicies();
    return renderPosture(
      policies
        .map((p) => ({
          category: (p.target as { category?: string }).category ?? '',
          action: p.action,
        }))
        .filter((r) => r.category !== ''),
    );
  } catch {
    // Best-effort: an unreadable or unopenable policies store just omits the
    // Posture section.
    return '';
  } finally {
    db?.close();
  }
}
