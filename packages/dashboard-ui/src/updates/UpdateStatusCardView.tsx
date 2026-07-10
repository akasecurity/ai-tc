'use client';
import type { ComponentStatus } from '@akasecurity/schema';
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  cn,
} from '@akasecurity/ui-kit';

import { RefreshIcon } from '../shared/icons.tsx';

// Per-row apply outcome, fed back by the connected layer after an update runs.
export interface UpdateOutcome {
  ok: boolean;
  // Package-manager output (or the reason nothing ran) — surfaced verbatim so
  // a failed npm/claude run stays diagnosable from the browser.
  output: string;
}

export interface UpdateStatusCardViewProps {
  statuses: ComponentStatus[];
  checkedAt: string | null;
  onCheckNow: () => void;
  // Applies the update for one component id. The CLI self-update replaces the
  // very package this server runs from — after a successful 'cli' apply the
  // connected layer should surface the restart banner (see `restartRequired`).
  onApply: (id: string) => void;
  applyingId: string | null;
  outcomes: Record<string, UpdateOutcome>;
  // True once the CLI updated: the running `aka dashboard` still serves the
  // OLD version until restarted.
  restartRequired: boolean;
  busy?: boolean;
}

function statusBadge(s: ComponentStatus) {
  if (s.installed === null || s.latest === null) return <Badge variant="default">unknown</Badge>;
  if (s.updateAvailable) return <Badge variant="high">update available</Badge>;
  return <Badge variant="success">up to date</Badge>;
}

/** Installed-vs-latest register — the web twin of `aka check-updates` / `aka update`. */
export function UpdateStatusCardView({
  statuses,
  checkedAt,
  onCheckNow,
  onApply,
  applyingId,
  outcomes,
  restartRequired,
  busy,
}: UpdateStatusCardViewProps) {
  return (
    <Card className="shadow-sm">
      <CardHeader>
        <CardIcon className="bg-primary-tint text-primary">
          <RefreshIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Installed components</CardTitle>
          <CardDescription>
            {checkedAt ? `Last checked ${checkedAt}` : 'Not checked yet'}
          </CardDescription>
        </CardHeading>
        <Button variant="outline" tone="neutral" size="sm" disabled={busy} onClick={onCheckNow}>
          {busy ? 'Checking…' : 'Check now'}
        </Button>
      </CardHeader>
      <CardContent>
        {restartRequired && (
          <div className="mb-3 rounded-lg border border-ok-fill bg-ok-fill px-3 py-2 text-xs font-medium text-text">
            Update installed — restart <code className="font-mono">aka dashboard</code> to load the
            new version.
          </div>
        )}
        <div className="flex flex-col">
          {statuses.map((s, i) => {
            const outcome = outcomes[s.id];
            return (
              <div key={s.id} className={cn('py-3', i > 0 && 'border-t border-text/6')}>
                <div className="flex items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-text">{s.name}</div>
                    <div className="mt-0.5 font-mono text-xs text-text-3">
                      {s.installed ?? '—'}
                      {s.latest && s.updateAvailable && ` → ${s.latest}`}
                    </div>
                  </div>
                  {statusBadge(s)}
                  {s.updateAvailable && (
                    <Button
                      variant="solid"
                      tone="primary"
                      size="sm"
                      disabled={applyingId !== null}
                      onClick={() => {
                        onApply(s.id);
                      }}
                    >
                      {applyingId === s.id ? 'Updating…' : 'Update'}
                    </Button>
                  )}
                </div>
                {outcome && (
                  <div
                    className={cn(
                      'mt-2 rounded-lg border p-2',
                      outcome.ok
                        ? 'border-ok-fill bg-ok-fill'
                        : 'border-sev-critical-fill bg-sev-critical-fill',
                    )}
                  >
                    <div className="text-xs font-semibold text-text">
                      {outcome.ok ? 'Updated.' : 'Update failed'}
                    </div>
                    {outcome.output && (
                      <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-label text-text-2">
                        {outcome.output}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            );
          })}
          {statuses.length === 0 && (
            <div className="py-6 text-center text-xs text-text-3">
              Nothing installed to report on yet.
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
