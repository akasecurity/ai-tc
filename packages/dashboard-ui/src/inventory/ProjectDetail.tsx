'use client';

// Right pane for one project: its findings and withheld-file counts, the files
// withheld from models, and the harnesses that have loaded it.
import type { FileSummary, HarnessSummary, ProjectSummary } from '@akasecurity/schema';
import { cn } from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { Provider } from '../shared/Provider.tsx';
import { BackButton, Section, VisBadge } from './chips.tsx';
import { assetTile, fmtDateTime } from './data.ts';
import { Ico } from './Ico.tsx';

export function ProjectDetail({
  project,
  blocked,
  blockedLoading,
  blockedError,
  harnesses,
  onBack,
  backLabel,
  renderedAt,
  locale,
}: {
  project: ProjectSummary;
  /** Files auto-blocked from every model, most recent first. */
  blocked: FileSummary[];
  blockedLoading?: boolean | undefined;
  /** Set when the withheld files could not be loaded. */
  blockedError?: string | null | undefined;
  /** Every harness; those that list this project are shown as loading it. */
  harnesses: HarnessSummary[];
  /** Returns to the table this project was opened from. */
  onBack: () => void;
  /** What the back button returns to, e.g. "Claude Code" or "Projects". */
  backLabel: string;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
  /** The locale dates are formatted in. */
  locale: string;
}) {
  const tile = assetTile('project');
  const withheld = project.accessCounts.blocked;
  const otherWithheld = Math.max(0, withheld - blocked.length);
  const loadedBy = harnesses.filter((h) => h.projects.some((p) => p.id === project.id));
  const updated = relativeTime(project.updatedAt, renderedAt);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-3 border-b border-border px-5 py-3.5">
        <BackButton onBack={onBack} backLabel={backLabel} />
        <span
          className={cn('grid size-10 shrink-0 place-items-center rounded-lg', tile.bg, tile.fg)}
        >
          <Ico name={tile.icon} className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className="truncate font-mono text-base font-semibold text-text"
              title={project.name}
            >
              {project.name}
            </span>
            <VisBadge v={project.visibility} />
          </div>
          <div className="mt-px truncate text-xs text-text-3">
            {[project.repo, project.language, updated && `updated ${updated}`]
              .filter(Boolean)
              .join(' · ')}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 border-b border-border">
        <Stat
          value={project.findingsCount}
          label="Findings"
          tone={project.findingsCount > 0 ? 'text-sev-high-ink' : 'text-ok-ink'}
        />
        <Stat
          value={withheld}
          label="Files withheld from models"
          tone={withheld > 0 ? 'text-sev-critical-ink' : 'text-ok-ink'}
          className="border-l border-border"
        />
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto p-5">
        <Section label="Files withheld from models">
          {blockedError ? (
            <div className="text-xs text-sev-critical-ink">
              {`Couldn't load the withheld files: ${blockedError}`}
            </div>
          ) : blockedLoading && blocked.length === 0 ? (
            <div className="text-xs text-text-3">Loading withheld files…</div>
          ) : blocked.length > 0 ? (
            <ul className="overflow-hidden rounded-lg border border-border">
              {blocked.map((f, i) => (
                <li
                  key={f.path}
                  className={cn(
                    'flex items-center gap-3 px-3.5 py-2.5',
                    i > 0 && 'border-t border-border',
                  )}
                >
                  <Ico name="slash-circle" className="size-4 shrink-0 text-sev-critical-ink" />
                  <span
                    className="min-w-0 flex-1 truncate font-mono text-xs text-text"
                    title={f.path}
                  >
                    {f.path}
                  </span>
                  <span
                    className="min-w-0 flex-1 truncate text-xs text-text-2"
                    title={f.note ?? ''}
                  >
                    {f.note ?? 'Withheld by policy'}
                  </span>
                  <span className="shrink-0 text-xs text-text-3">
                    {f.blockedAt ? fmtDateTime(f.blockedAt, locale) : '—'}
                  </span>
                </li>
              ))}
            </ul>
          ) : withheld === 0 ? (
            <Notice>Every file in this project is available to approved models.</Notice>
          ) : null}
          {!blockedError && !blockedLoading && otherWithheld > 0 && (
            <div className={cn('text-xs text-text-3', blocked.length > 0 && 'mt-2')}>
              {blocked.length > 0
                ? `${String(otherWithheld)} more withheld by the project's policy or a manual setting.`
                : `${String(otherWithheld)} ${otherWithheld === 1 ? 'file is' : 'files are'} withheld by the project's policy or a manual setting.`}
            </div>
          )}
        </Section>

        <Section label="Harnesses loading this project">
          {loadedBy.length > 0 ? (
            <ul className="flex flex-col gap-1">
              {loadedBy.map((h) => (
                <li key={h.id} className="flex items-center gap-3 py-1.5">
                  <Provider id={h.id} size={28} />
                  <span className="text-sm font-semibold text-text">{h.label}</span>
                  {h.version && <span className="text-xs text-text-3">{h.version}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-xs text-text-3">No agent harness has loaded this project yet.</div>
          )}
        </Section>
      </div>
    </div>
  );
}

function Stat({
  value,
  label,
  tone,
  className,
}: {
  value: number;
  label: string;
  tone: string;
  className?: string;
}) {
  return (
    <div className={cn('px-5 py-4', className)}>
      <div className={cn('font-display text-2xl font-semibold tabular-nums', tone)}>{value}</div>
      <div className="mt-0.5 text-xs text-text-3">{label}</div>
    </div>
  );
}

function Notice({ children }: { children: string }) {
  return (
    <div className="flex items-center gap-2.5 rounded-lg border border-border px-3.5 py-3 text-sm text-text-2">
      <Ico name="check-circle" className="size-4 shrink-0 text-ok-ink" />
      {children}
    </div>
  );
}
