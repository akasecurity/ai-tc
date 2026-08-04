'use client';

import { Button, Card, CardContent } from '@akasecurity/ui-kit';
import Link from 'next/link';

import { AlertOctagonIcon } from '../components/icons';

/**
 * Error boundary for every page under (app). It renders below the route-group
 * layout, so the shell stays mounted and the sidebar keeps working.
 *
 * Only the digest is shown, never `error.message`: these pages read a store that
 * holds scanned content, and a message can carry the value that tripped the
 * failure. The digest identifies the same error in the server log without
 * putting anything from the store on screen.
 */
export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="px-8 pb-10 pt-7">
      <Card className="mx-auto max-w-lg">
        <CardContent className="flex flex-col items-center gap-4 py-10 text-center">
          <span className="flex size-11 items-center justify-center rounded-full bg-sev-critical-fill">
            <AlertOctagonIcon
              aria-hidden
              focusable={false}
              className="size-5 text-sev-critical-ink"
            />
          </span>
          <div className="flex flex-col gap-1.5">
            <h1 className="text-lg font-semibold text-text">Something went wrong</h1>
            <p className="text-sm text-text-2">
              This page could not be rendered from the local store.
            </p>
            {error.digest && (
              <p className="pt-1 font-mono text-xs text-text-3">Error digest: {error.digest}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="solid" tone="primary" onClick={reset}>
              Try again
            </Button>
            <Button variant="outline" tone="neutral" asChild>
              <Link href="/security">Go to Security</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
