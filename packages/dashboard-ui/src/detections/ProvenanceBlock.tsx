// The detail-pane provenance block: where a detection came from (publisher +
// version it tracks) and the contextual call-to-action. THREE honest states
// (see provenanceState in meta.ts):
//
//   update-available → amber banner (+ Update button when the app supplies
//                      `onOpenUpdate`; with `updateRefusal` that same button
//                      renders in place, offered-and-disabled, beside its reason)
//   up-to-date       → the store VERIFIED the installed snapshot matches what
//                      the binaries ship (update.available === false)
//   unknown          → nothing has recorded an inventory yet (update == null):
//                      a fresh machine where only the dashboard has run.
//                      Rendered as its own muted row — never as "up to date",
//                      which the store cannot back.
//
// `onRecheck` (optional, OSS web-ui) re-reads the store in place. `unknownHint`
// (optional) is the app-supplied explanation of how an inventory gets recorded:
// this view is shared across apps, so each app supplies its own copy rather
// than the component hardcoding one remediation. Omitted
// → just the neutral status line.
import type { DetectionDetail } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';
import { type ReactNode, useId } from 'react';

import { ArrowUpIcon, CheckCircleIcon, InfoIcon } from '../shared/icons.tsx';
import { RefusalReason, refusedControlProps } from '../shared/Refusal.tsx';
import { OriginBadge, PublisherTag } from './atoms.tsx';
import { provenanceState } from './meta.ts';

export function ProvenanceBlock({
  d,
  onOpenUpdate,
  updateRefusal,
  onRecheck,
  unknownHint,
}: {
  d: DetectionDetail;
  onOpenUpdate?: (() => void) | undefined;
  /**
   * Why this host cannot operate Update. Set (alongside `onOpenUpdate`, the
   * control it stands in for), the same amber button renders in its place,
   * offered-and-disabled — focusable, `aria-disabled`, its reason visible
   * beside it — and never calls `onOpenUpdate`. Without `onOpenUpdate` there is
   * no control to refuse, so nothing renders, exactly as before.
   */
  updateRefusal?: string | undefined;
  onRecheck?: (() => void) | undefined;
  unknownHint?: ReactNode;
}) {
  const state = provenanceState(d);
  const latestVersion = d.update?.latestVersion ?? d.latestVersion ?? '';
  const updateReasonId = useId();
  // null when live. The hover string is the live button's own override — it
  // replaces the default solid/neutral hover (hover:bg-border-strong), so the
  // refused one repeats it.
  const updateRefused =
    updateRefusal === undefined
      ? null
      : refusedControlProps(updateReasonId, updateRefusal, 'hover:bg-sev-high-ink');

  return (
    <div className="overflow-hidden rounded-xl border border-border shrink-0">
      {/* header line: origin + lineage */}
      <div className="flex flex-wrap items-center gap-2.5 bg-surface-2 px-4 py-3 border-b border-border">
        <OriginBadge origin={d.origin} />
        <PublisherTag publisher={d.publisher ?? d.namespace} kind={d.publisherKind ?? 'user'} />
        <span className="flex-1" />
        <span className="font-mono text-label text-text-2">tracking v{d.version}</span>
      </div>

      {state === 'update-available' ? (
        <div className="flex items-center gap-3 bg-sev-high-fill px-4 py-3">
          <ArrowUpIcon
            aria-hidden
            focusable={false}
            className="size-4.5 shrink-0 text-sev-high-ink"
          />
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold text-sev-high-ink">
              Update available · v{latestVersion}
            </div>
            <div className="mt-px text-xs leading-snug text-text-2">
              A newer version is published upstream.
            </div>
          </div>
          {onOpenUpdate &&
            (updateRefused === null ? (
              <Button
                size="sm"
                data-slot="open-update"
                onClick={onOpenUpdate}
                className="shrink-0 bg-sev-high-ink text-on-accent hover:bg-sev-high-ink"
              >
                Update
              </Button>
            ) : (
              <div className="flex max-w-56 shrink-0 flex-col items-end gap-1 text-right">
                <Button
                  size="sm"
                  data-slot="open-update"
                  {...updateRefused}
                  className={cn('shrink-0 bg-sev-high-ink text-on-accent', updateRefused.className)}
                >
                  Update
                </Button>
                <RefusalReason id={updateReasonId} dataSlot="open-update-reason">
                  {updateRefusal}
                </RefusalReason>
              </div>
            ))}
        </div>
      ) : state === 'up-to-date' ? (
        <div className="flex items-center gap-2.5 px-4 py-2.5 text-xs text-text-3">
          <CheckCircleIcon aria-hidden focusable={false} className="size-4 text-ok-ink" />
          Up to date with upstream
        </div>
      ) : (
        <div className="flex items-center gap-2.5 px-4 py-2.5 text-xs text-text-3">
          <InfoIcon aria-hidden focusable={false} className="size-4 shrink-0" />
          <span className="min-w-0 flex-1">
            Update status unknown{unknownHint ? <> — {unknownHint}</> : '.'}
          </span>
          {onRecheck && (
            <Button variant="ghost" tone="neutral" size="sm" onClick={onRecheck}>
              Check again
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
