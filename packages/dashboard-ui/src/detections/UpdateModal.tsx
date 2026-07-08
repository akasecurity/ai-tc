'use client';
// Review & apply an available update for an installed detection. Shared across
// hosts: one pulls the latest published version from the
// registry; another copies the latest snapshot shipped with the
// plugin/CLI (available_packs) into the installed pack. Either way the apply is
// the caller's job (onConfirm) — this modal only presents the delta.
//
// The delta line adapts to what actually changed: a version bump renders
// v-old → v-new; a same-version rule-content update (OSS coverage growth)
// renders the rule-count change instead, so the dialog never shows a
// meaningless "v2.0.0 → v2.0.0".
import type { DetectionDetail } from '@akasecurity/schema';
import { Button, Dialog, DialogContent, DialogTitle } from '@akasecurity/ui-kit';

import {
  ArrowRightIcon,
  ArrowUpIcon,
  CheckCircleIcon,
  DownloadIcon,
  XIcon,
} from '../shared/icons.tsx';
import { PublisherTag } from './atoms.tsx';

export function UpdateModal({
  det,
  isUpdating,
  onClose,
  onConfirm,
}: {
  det: DetectionDetail | null;
  isUpdating: boolean;
  onClose: () => void;
  onConfirm: (id: string) => void;
}) {
  const d = det;
  // Fall back to the CURRENT version last: callers gate this modal on
  // update.available, but if a stale detail slips through, "v2.0.0 → v2.0.0"
  // (rule-count mode below) beats a broken "v2.0.0 → v" render.
  const latestVersion = d ? (d.update?.latestVersion ?? d.latestVersion ?? d.version) : '';
  const latestRuleCount = d?.update?.latestRuleCount;
  const versionChanged = !!d && latestVersion !== d.version;

  return (
    <Dialog
      open={!!d}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <DialogContent className="w-155 max-w-[96vw]" aria-describedby={undefined}>
        {d && (
          <>
            <DialogTitle className="sr-only">Update · {d.name}</DialogTitle>
            {/* header */}
            <div className="flex shrink-0 items-center gap-3 border-b border-border px-5 py-4">
              <span className="grid size-9.5 shrink-0 place-items-center rounded-lg bg-sev-high-fill text-sev-high">
                <ArrowUpIcon aria-hidden focusable={false} className="size-5" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="font-display text-base font-semibold text-text">
                  Update “{d.name}”
                </div>
                <div className="text-xs text-text-3">
                  From the detection library · {d.publisher ?? d.namespace}
                </div>
              </div>
              <Button
                variant="ghost"
                tone="neutral"
                size="icon"
                onClick={onClose}
                aria-label="Close"
                className="size-8 text-text-3"
              >
                <XIcon aria-hidden focusable={false} />
              </Button>
            </div>

            {/* body */}
            <div className="flex flex-col gap-5 overflow-y-auto p-5">
              {/* the delta: version bump, or rule-count change when the version is unchanged */}
              <div className="flex items-center gap-3">
                <span className="rounded-lg border border-border bg-surface-2 px-3 py-1.5 font-mono text-sm font-semibold text-text-2">
                  {versionChanged ? `v${d.version}` : `${String(d.ruleCount)} rules`}
                </span>
                <ArrowRightIcon aria-hidden focusable={false} className="size-4 text-text-3" />
                <span className="rounded-lg border border-sev-high bg-sev-high-fill px-3 py-1.5 font-mono text-sm font-bold text-sev-high">
                  {versionChanged
                    ? `v${latestVersion}`
                    : `${String(latestRuleCount ?? d.ruleCount)} rules`}
                </span>
                <span className="flex-1" />
                <PublisherTag
                  publisher={d.publisher ?? d.namespace}
                  kind={d.publisherKind ?? 'user'}
                />
              </div>

              <div className="flex items-center gap-2.5 rounded-lg border border-ok bg-ok-fill px-3 py-2.5">
                <CheckCircleIcon
                  aria-hidden
                  focusable={false}
                  className="size-4 shrink-0 text-ok"
                />
                <div className="text-sm text-text-2">
                  Updates are never applied automatically — your enabled state and policy assignment
                  are preserved.
                </div>
              </div>
            </div>

            {/* footer */}
            <div className="flex shrink-0 items-center gap-2.5 border-t border-border px-5 py-4">
              <span className="flex-1" />
              <Button variant="outline" tone="neutral" onClick={onClose}>
                Cancel
              </Button>
              <Button
                variant="solid"
                tone="primary"
                disabled={isUpdating}
                onClick={() => {
                  onConfirm(d.id);
                }}
              >
                <DownloadIcon aria-hidden focusable={false} className="size-4" />
                {isUpdating
                  ? 'Updating…'
                  : versionChanged
                    ? `Update to v${latestVersion}`
                    : 'Update rules'}
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
