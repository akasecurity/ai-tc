'use client';
import type { AvailablePlugin } from '@akasecurity/schema';
import {
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

import { SparklesIcon } from '../shared/icons.tsx';
import type { UpdateOutcome } from './UpdateStatusCardView.tsx';

export interface AvailablePluginsCardViewProps {
  plugins: AvailablePlugin[];
  onInstall: (id: string) => void;
  installingId: string | null;
  outcomes: Record<string, UpdateOutcome>;
}

/** Agent plugins not yet installed — the web twin of `aka plugins list/install`. */
export function AvailablePluginsCardView({
  plugins,
  onInstall,
  installingId,
  outcomes,
}: AvailablePluginsCardViewProps) {
  if (plugins.length === 0) return null;
  return (
    <Card className="shadow-sm">
      <CardHeader>
        <CardIcon className="bg-teal-fill text-teal">
          <SparklesIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Available plugins</CardTitle>
          <CardDescription>Agent integrations you haven’t installed yet</CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col">
          {plugins.map((p, i) => {
            const outcome = outcomes[p.id];
            return (
              <div key={p.id} className={cn('py-3', i > 0 && 'border-t border-text/6')}>
                <div className="flex items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-text">{p.name}</div>
                    {p.latest && (
                      <div className="mt-0.5 font-mono text-xs text-text-3">v{p.latest}</div>
                    )}
                  </div>
                  <Button
                    variant="solid"
                    tone="primary"
                    size="sm"
                    disabled={installingId !== null}
                    onClick={() => {
                      onInstall(p.id);
                    }}
                  >
                    {installingId === p.id ? 'Installing…' : 'Install'}
                  </Button>
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
                      {outcome.ok
                        ? 'Installed — restart Claude Code to load it.'
                        : 'Install failed'}
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
        </div>
      </CardContent>
    </Card>
  );
}
