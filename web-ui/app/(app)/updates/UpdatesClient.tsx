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

interface PendingApply {
  id: string;
  kind: 'update' | 'install';
  name: string;
  command: string;
}

export function UpdatesClient({
  statuses,
  availablePlugins,
  checkedAt,
  commands,
  installCommands,
}: {
  statuses: ComponentStatus[];
  availablePlugins: AvailablePlugin[];
  checkedAt: string | null;
  commands: Record<string, string>;
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

  const confirmApply = (p: PendingApply) => {
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
          setPending({
            id,
            kind: 'update',
            name: status.name,
            command: commands[id] ?? '',
          });
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
              {pending?.kind === 'install' ? 'Install' : 'Update'} {pending?.name}?
            </DialogTitle>
            <DialogDescription>This runs the following command on this machine:</DialogDescription>
          </DialogHeader>
          <DialogBody>
            <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs text-text">
              {pending?.command}
            </pre>
            {pending?.id === 'cli' && (
              <p className="text-xs text-text-3">
                This replaces the package the dashboard server itself runs from — you’ll need to
                restart <code className="font-mono">aka dashboard</code> afterwards.
              </p>
            )}
          </DialogBody>
          <DialogFooter>
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
                if (pending) confirmApply(pending);
              }}
            >
              Run it
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
