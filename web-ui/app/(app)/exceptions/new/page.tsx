import Link from 'next/link';

import { db } from '../../../lib/db';
import { NewExceptionClient } from './NewExceptionClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export default function NewExceptionPage() {
  // Rule options come from the installed snapshot (the scan authority) — the
  // same enabled rules the add action verifies against.
  const { rules } = db().installedPacks.installedRuleset();
  const options = rules.map((r) => ({ id: r.id, name: r.name }));

  return (
    <div className="px-8 pb-10 pt-7">
      <div className="pb-4 text-xs">
        <Link href="/exceptions" className="text-text-3 hover:text-text-2">
          ← All exceptions
        </Link>
      </div>
      <h1 className="pb-1 font-display text-2xl font-semibold text-text">Pre-authorize a value</h1>
      <p className="pb-6 text-sm text-text-3">
        Grant an exception for a value that hasn’t been blocked yet — the web twin of{' '}
        <code className="font-mono">aka exception add</code>.
      </p>
      <NewExceptionClient rules={options} />
    </div>
  );
}
