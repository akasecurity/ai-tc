'use client';

import type { UpdateOutcome } from '@akasecurity/dashboard-ui';
import { AvailablePluginsCardView, UpdateStatusCardView } from '@akasecurity/dashboard-ui';
import type { AvailablePlugin, ComponentStatus } from '@akasecurity/schema';
import {
  Button,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@akasecurity/ui-kit';
import { useState, useTransition } from 'react';

import { applyUpdate, checkNow, installPlugin } from './actions';

interface PendingBase {
  id: string;
  name: string;
  command: string;
}

/** A pending action the confirm button can actually run. */
type PendingRun = PendingBase & { kind: 'update' | 'install' };

/**
 * A component this dashboard will not update itself. `command` is the line
 * that WOULD do it and `reason` says why nothing here runs it — the two are
 * required together, so a dialog cannot present advice without saying so.
 */
type PendingAdvice = PendingBase & { kind: 'advice'; reason: string };

type PendingApply = PendingRun | PendingAdvice;

/**
 * A component whose update this dashboard cannot apply — the standalone
 * binary, a Homebrew tree, a source checkout. `display` is the command that
 * WOULD do it, which is advice rather than something to offer to run.
 */
export interface UpdateAdvisory {
  display: string;
  reason: string;
}

export function UpdatesClient({
  statuses,
  availablePlugins,
  checkedAt,
  commands,
  advisories,
  installCommands,
}: {
  statuses: ComponentStatus[];
  availablePlugins: AvailablePlugin[];
  checkedAt: string | null;
  commands: Record<string, string>;
  advisories: Record<string, UpdateAdvisory>;
  installCommands: Record<string, string>;
}) {
  const [outcomes, setOutcomes] = useState<Record<string, UpdateOutcome>>({});
  const [installOutcomes, setInstallOutcomes] = useState<Record<string, UpdateOutcome>>({});
  const [applyingId, setApplyingId] = useState<string | null>(null);
  const [installingId, setInstallingId] = useState<string | null>(null);
  const [restartRequired, setRestartRequired] = useState(false);
  const [pending, setPending] = useState<PendingApply | null>(null);
  const [checking, startChecking] = useTransition();
  const [, startApplying] = useTransition();

  // Only a runnable pending can be confirmed — an advisory has no action
  // behind it, and typing that here is what stops the branch below from
  // quietly calling installPlugin() for one.
  const confirmApply = (p: PendingRun) => {
    setPending(null);
    if (p.kind === 'update') setApplyingId(p.id);
    else setInstallingId(p.id);
    startApplying(async () => {
      const result = p.kind === 'update' ? await applyUpdate(p.id) : await installPlugin(p.id);
      const outcome: UpdateOutcome = { ok: result.ok, output: result.output };
      if (p.kind === 'update') {
        setOutcomes((prev) => ({ ...prev, [p.id]: outcome }));
        setApplyingId(null);
        if (result.restartRequired) setRestartRequired(true);
      } else {
        setInstallOutcomes((prev) => ({ ...prev, [p.id]: outcome }));
        setInstallingId(null);
      }
    });
  };

  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <UpdateStatusCardView
        statuses={statuses}
        checkedAt={checkedAt}
        busy={checking}
        onCheckNow={() => {
          startChecking(async () => {
            await checkNow();
          });
        }}
        onApply={(id) => {
          const status = statuses.find((s) => s.id === id);
          if (!status) return;
          // An advisory means the button cannot apply this one. Say so before
          // the confirmation rather than after the run: the dialog below
          // introduces a runnable command with "This runs the following command
          // on this machine", and for the standalone binary the line it would
          // be introducing is the installer's curl-pipe-to-shell one-liner.
          const advisory = advisories[id];
          setPending(
            advisory
              ? {
                  id,
                  kind: 'advice',
                  name: status.name,
                  command: advisory.display,
                  reason: advisory.reason,
                }
              : { id, kind: 'update', name: status.name, command: commands[id] ?? '' },
          );
        }}
        applyingId={applyingId}
        outcomes={outcomes}
        restartRequired={restartRequired}
      />

      <AvailablePluginsCardView
        plugins={availablePlugins}
        onInstall={(id) => {
          const plugin = availablePlugins.find((p) => p.id === id);
          if (!plugin) return;
          setPending({
            id,
            kind: 'install',
            name: plugin.name,
            command: installCommands[id] ?? '',
          });
        }}
        installingId={installingId}
        outcomes={installOutcomes}
      />

      <Dialog
        open={pending !== null}
        onOpenChange={(open) => {
          if (!open) setPending(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pending?.kind === 'advice' ? (
                <>Updating {pending.name}</>
              ) : (
                <>
                  {pending?.kind === 'install' ? 'Install' : 'Update'} {pending?.name}?
                </>
              )}
            </DialogTitle>
            <DialogDescription>
              {pending?.kind === 'advice'
                ? 'This one can’t be applied from the dashboard. Run it yourself:'
                : 'This runs the following on this machine:'}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            {pending?.kind === 'advice' && (
              <p className="mb-2 text-xs text-text-3">{pending.reason}.</p>
            )}
            <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs text-text">
              {pending?.command}
            </pre>
            {pending?.id === 'cli' && pending.kind === 'update' && (
              <p className="text-xs text-text-3">
                This replaces the package the dashboard server itself runs from — you’ll need to
                restart <code className="font-mono">aka dashboard</code> afterwards.
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            {pending?.kind === 'advice' ? (
              <Button
                variant="solid"
                tone="primary"
                size="sm"
                onClick={() => {
                  setPending(null);
                }}
              >
                Close
              </Button>
            ) : (
              <>
                <Button
                  variant="ghost"
                  tone="neutral"
                  size="sm"
                  onClick={() => {
                    setPending(null);
                  }}
                >
                  Cancel
                </Button>
                <Button
                  variant="solid"
                  tone="primary"
                  size="sm"
                  onClick={() => {
                    // Narrowed to PendingRun by the branch above — an
                    // advisory cannot reach this button at all.
                    if (pending) confirmApply(pending);
                  }}
                >
                  Run it
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
