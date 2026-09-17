import { Card, CardContent } from '@akasecurity/ui-kit';

import type { StoreVersionSkew } from '../lib/db';
import { AlertOctagonIcon } from './icons';

/**
 * Shown in place of a page when the local store was written by a NEWER AKA
 * build than the one serving this dashboard.
 *
 * It is deliberately NOT the error boundary. That boundary is for a page that
 * could not be rendered, and it says so without saying why — a digest, never
 * `error.message`, because these pages read a store holding scanned content.
 * This case is different in both halves: nothing is damaged, and what there is
 * to say carries no captured value (see `StoreVersionSkew`). So it gets its own
 * surface, with the remedy on it.
 *
 * The copy must never suggest repairing, resetting or moving the store. The
 * store is intact, an up-to-date build reads it correctly, and the only thing
 * that is wrong is the version of the binary rendering this page.
 */
export function StoreSkewNotice({ skew }: { skew: StoreVersionSkew }) {
  return (
    <div className="p-6">
      <Card className="mx-auto max-w-xl">
        <CardContent className="flex flex-col items-center gap-4 py-10 text-center">
          <span className="flex size-11 items-center justify-center rounded-full bg-sev-medium-fill">
            <AlertOctagonIcon
              aria-hidden
              focusable={false}
              className="size-5 text-sev-medium-ink"
            />
          </span>
          <div className="flex flex-col gap-1.5">
            <h1 className="text-lg font-semibold text-text">This dashboard is out of date</h1>
            <p className="text-sm text-text-2">
              The local store was written by a newer version of AKA than the one serving this
              dashboard, so its pages cannot read it. Your data is intact and needs no repair —
              update AKA so every surface on this machine is on one version line.
            </p>
            <p className="pt-1 text-sm text-text-2">
              Update with <code className="font-mono text-text">aka update</code>, then restart the
              dashboard.
            </p>
          </div>
          <dl className="flex flex-col gap-1 text-xs text-text-3">
            <div className="flex justify-center gap-2">
              <dt>Store schema</dt>
              <dd className="font-mono text-text-2">{skew.storeVersion}</dd>
            </div>
            <div className="flex justify-center gap-2">
              <dt>This build</dt>
              <dd className="font-mono text-text-2">{skew.buildVersion}</dd>
            </div>
            {skew.unknownTags.length > 0 && (
              <div className="flex flex-col gap-1 pt-1">
                <dt>Migrations this build does not have</dt>
                <dd className="font-mono break-all text-text-2">{skew.unknownTags.join(', ')}</dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
