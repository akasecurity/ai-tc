import { AmbiguousExceptionIdError } from '@akasecurity/persistence';
import { toExceptionDescriptor } from '@akasecurity/schema';
import Link from 'next/link';
import { notFound } from 'next/navigation';

import { db } from '../../../lib/db';
import { renderInstant } from '../../../lib/rendered-at';
import { ExceptionDetailClient } from './ExceptionDetailClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // Short prefix keeps the tab title readable while still telling two open
  // exception tabs apart (matches the page's own id-prefix lookup).
  return { title: `Exception ${id.slice(0, 8)}` };
}

export default async function ExceptionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  let exception;
  try {
    exception = await db().exceptions.getByIdPrefix(id);
  } catch (err) {
    if (err instanceof AmbiguousExceptionIdError) {
      return (
        <div className="px-8 pb-10 pt-7 text-sm text-text-2">
          The id prefix “{id}” matches more than one exception — use a longer prefix from the{' '}
          <Link href="/exceptions" className="text-primary underline">
            list
          </Link>
          .
        </div>
      );
    }
    throw err;
  }
  if (!exception) notFound();

  return (
    <div className="px-8 pb-10 pt-7">
      <div className="pb-4 text-xs">
        <Link href="/exceptions" className="text-text-3 hover:text-text-2">
          ← All exceptions
        </Link>
      </div>
      {/* Projected to the fingerprint-free descriptor at the server boundary —
          the keyed valueFingerprint must never reach the browser. */}
      <ExceptionDetailClient
        exception={toExceptionDescriptor(exception)}
        // A relative label — and the lifecycle state that decides whether the
        // revoke form renders at all — must be calculated against the exact
        // same instant during SSR and hydration; otherwise crossing a boundary
        // between the two changes the text, or the form itself.
        renderedAt={renderInstant()}
      />
    </div>
  );
}
