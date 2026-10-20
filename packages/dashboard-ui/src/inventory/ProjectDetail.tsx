'use client';

// Right pane for one project: its findings and withheld-file counts, the
// categories of sensitive data its findings fall in, the files withheld from
// models, and the harnesses that have loaded it.
import type {
  FileSummary,
  HarnessSummary,
  ProjectSummary,
  SensitiveDataClass,
} from '@akasecurity/schema';
import { PROJECT_FINDINGS_WINDOW_DAYS } from '@akasecurity/schema';
import { cn, SeverityBadge } from '@akasecurity/ui-kit';

import { CATEGORY_LABEL } from '../detections/meta.ts';
import { relativeTime } from '../lib/relativeTime.ts';
import { Provider } from '../shared/Provider.tsx';
import { BackButton, Section } from './chips.tsx';
import { assetTile, endpointCountText, fmtDateTime, SENSITIVE_CATEGORY } from './data.ts';
import { Ico } from './Ico.tsx';

export function ProjectDetail({
  project,
  blocked,
  blockedLoading,
  blockedError,
  sensitiveData,
  sensitiveDataLoading,
  sensitiveDataError,
  sensitiveDataRefusal,
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
  /** The project's findings in the findings window by category, most severe first. */
  sensitiveData: SensitiveDataClass[];
  sensitiveDataLoading?: boolean | undefined;
  /** Set when the sensitive data could not be loaded. */
  sensitiveDataError?: string | null | undefined;
  /** Shown in place of the sensitive data when the viewer may not read it. */
  sensitiveDataRefusal?: string | undefined;
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
  const stats: StatProps[] = [
    ...(project.machines === undefined
      ? []
      : [
          {
            value: endpointCountText(project.machines, true),
            label: 'Endpoints seen on',
            tone: 'text-text',
          },
        ]),
    ...(project.findingsCount === undefined
      ? []
      : [
          {
            value: project.findingsCount,
            label: `Findings · ${String(PROJECT_FINDINGS_WINDOW_DAYS)}d`,
            tone: project.findingsCount > 0 ? 'text-sev-high-ink' : 'text-ok-ink',
          },
        ]),
    {
      value: withheld,
      label: 'Files withheld from models',
      tone: withheld > 0 ? 'text-sev-critical-ink' : 'text-ok-ink',
    },
  ];
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
          <div
            className="truncate font-mono text-base font-semibold text-text"
            title={project.name}
          >
            {project.name}
          </div>
          <div className="mt-px truncate text-xs text-text-3">
            {[project.repo, project.language, updated && `updated ${updated}`]
              .filter(Boolean)
              .join(' · ')}
          </div>
        </div>
      </div>

      <div className={cn('grid border-b border-border', STAT_COLUMNS[stats.length])}>
        {stats.map((stat, i) => (
          <Stat key={stat.label} {...stat} className={cn(i > 0 && 'border-l border-border')} />
        ))}
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto p-5">
        <Section label="Sensitive data present">
          {sensitiveDataRefusal !== undefined ? (
            <div className="text-xs text-text-3">{sensitiveDataRefusal}</div>
          ) : sensitiveDataError ? (
            <div className="text-xs text-sev-critical-ink">
              {`Couldn't load the sensitive data: ${sensitiveDataError}`}
            </div>
          ) : sensitiveDataLoading && sensitiveData.length === 0 ? (
            <div className="text-xs text-text-3">Loading sensitive data…</div>
          ) : sensitiveData.length > 0 ? (
            <ul className="flex flex-col gap-2">
              {sensitiveData.map((c) => (
                <SensitiveDataRow key={c.category} item={c} renderedAt={renderedAt} />
              ))}
            </ul>
          ) : (
            <Notice>{`No sensitive data found in the last ${String(PROJECT_FINDINGS_WINDOW_DAYS)} days.`}</Notice>
          )}
        </Section>

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

function SensitiveDataRow({ item, renderedAt }: { item: SensitiveDataClass; renderedAt: number }) {
  const tile = SENSITIVE_CATEGORY[item.category];
  return (
    <li className="flex items-center gap-3 rounded-lg border border-border px-3.5 py-2.5">
      <span className={cn('grid size-8 shrink-0 place-items-center rounded-md', tile.bg, tile.fg)}>
        <Ico name={tile.icon} className="size-4" />
      </span>
      <span className="min-w-0 flex-1 truncate text-sm font-semibold text-text">
        {CATEGORY_LABEL[item.category]}
      </span>
      <span className="shrink-0 text-xs text-text-2">
        {item.files === 0
          ? 'In prompts & output'
          : `${String(item.files)} ${item.files === 1 ? 'file' : 'files'}`}
      </span>
      <SeverityBadge severity={item.severity} />
      <span className="min-w-20 shrink-0 text-right text-xs text-text-3">
        {relativeTime(item.lastDetectedAt, renderedAt)}
      </span>
    </li>
  );
}

interface StatProps {
  value: number | string;
  label: string;
  tone: string;
}

/** The grid class for the number of stats the header shows. */
const STAT_COLUMNS: Record<number, string> = {
  1: 'grid-cols-1',
  2: 'grid-cols-2',
  3: 'grid-cols-3',
};

function Stat({ value, label, tone, className }: StatProps & { className?: string | undefined }) {
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
