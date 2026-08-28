'use client';

import type { FindingLocationFile, FindingLocationRepo } from '@akasecurity/schema';
import { Badge, Card, cn, SeverityBadge } from '@akasecurity/ui-kit';
import { Fragment, type ReactNode } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { ChevronRightIcon } from '../shared/icons.tsx';
import { findingStatusMeta } from './meta.ts';

/**
 * Findings folded by location — repository, then file within it.
 *
 * The grouping keys come from each capturing event's recorded repo and file
 * path, which is what the local store relates a finding to. A finding whose
 * event recorded neither folds into an unnamed bucket, rendered but NOT
 * linkable: no filter can name the empty string, since a URL cannot distinguish
 * an absent param from an empty one.
 *
 * Fully presentational — expansion state and the drill-down are the caller's.
 */
export function FindingsLocationsView({
  items,
  expandedRepos,
  onToggleRepo,
  onSelectFile,
  hasMore = false,
  isLoading = false,
  emptyState,
}: {
  items: FindingLocationRepo[];
  expandedRepos: ReadonlySet<string>;
  onToggleRepo: (repo: string) => void;
  /** Drill into one file's findings. Never called for the unnamed bucket. */
  onSelectFile: (repo: string, file: string) => void;
  hasMore?: boolean;
  isLoading?: boolean;
  emptyState?: ReactNode;
}) {
  return (
    <Card className="flex h-full min-h-0 flex-col overflow-hidden shadow-sm">
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {isLoading ? (
          <div className="flex flex-col gap-2 py-2">
            {Array.from({ length: 6 }, (_, i) => (
              <div key={i} className="h-12 animate-pulse rounded-md bg-surface-3" />
            ))}
          </div>
        ) : items.length === 0 ? (
          (emptyState ?? (
            <p className="py-8 text-center text-sm text-text-3">No findings match these filters.</p>
          ))
        ) : (
          <div className="flex flex-col gap-1.5">
            {items.map((repo) => {
              const expanded = expandedRepos.has(repo.repo);
              return (
                <Fragment key={repo.repo || '\0unnamed'}>
                  <button
                    type="button"
                    aria-expanded={expanded}
                    onClick={() => {
                      onToggleRepo(repo.repo);
                    }}
                    className="flex w-full items-center gap-3 rounded-lg border border-border px-3 py-2.5 text-left hover:bg-surface-2"
                  >
                    <ChevronRightIcon
                      aria-hidden
                      focusable={false}
                      className={cn(
                        'size-4 shrink-0 text-text-3 transition-transform',
                        expanded && 'rotate-90',
                      )}
                    />
                    <SeverityBadge severity={repo.maxSeverity} />
                    <span
                      className={cn(
                        'min-w-0 flex-1 truncate text-ui font-semibold',
                        repo.repo ? 'font-mono text-text' : 'italic text-text-3',
                      )}
                    >
                      {repo.repo || 'No repository recorded'}
                    </span>
                    <StatusBadge status={repo.status} />
                    <span className="shrink-0 text-xs text-text-3">
                      {repo.instanceCount} {repo.instanceCount === 1 ? 'finding' : 'findings'} ·{' '}
                      {repo.files.length} {repo.files.length === 1 ? 'file' : 'files'}
                    </span>
                    <span className="shrink-0 text-xs text-text-3">
                      {relativeTime(repo.latestDetectedAt)}
                    </span>
                  </button>

                  {expanded &&
                    repo.files.map((file) => (
                      <FileRow
                        key={`${repo.repo}\0${file.file}`}
                        file={file}
                        // The unnamed bucket has no filter that could name it,
                        // so its rows are informational rather than links.
                        onSelect={
                          file.file
                            ? () => {
                                onSelectFile(repo.repo, file.file);
                              }
                            : undefined
                        }
                      />
                    ))}
                </Fragment>
              );
            })}
          </div>
        )}

        {hasMore && (
          <p className="mt-4 text-center text-xs text-text-3">
            Showing the first {items.length} repositories — refine the filters to narrow results.
          </p>
        )}
      </div>
    </Card>
  );
}

function StatusBadge({ status }: { status: FindingLocationRepo['status'] }) {
  if (status === undefined) return null;
  const meta = findingStatusMeta(status);
  return (
    <Badge variant={meta.badge} className="h-6 shrink-0">
      {meta.label}
    </Badge>
  );
}

function FileRow({
  file,
  onSelect,
}: {
  file: FindingLocationFile;
  // `| undefined` explicitly: the caller passes undefined for the unnamed
  // bucket, which exactOptionalPropertyTypes distinguishes from omitting it.
  onSelect?: (() => void) | undefined;
}) {
  const content = (
    <div className="grid grid-cols-[100px_1fr_1fr_100px_100px] w-full gap-2">
      <div>
        <SeverityBadge severity={file.maxSeverity} />
      </div>
      <span
        className={cn(
          'font-mono text-xs break-words [word-break:break-word]',
          file.file ? 'text-text-2' : 'italic text-text-3',
        )}
      >
        {file.file || 'No file recorded'}
      </span>
      <span className="text-xs text-text-3 break-words [word-break:break-word]">
        {file.ruleIds.join(', ')}
      </span>
      <span className="shrink-0 text-xs text-text-3">{file.instanceCount}</span>
      <span className="shrink-0 text-xs text-text-3">{relativeTime(file.latestDetectedAt)}</span>
    </div>
  );

  const className = 'flex w-full items-center gap-3 rounded-md py-1.5 pl-10 pr-3 text-left';

  if (!onSelect) {
    return <div className={className}>{content}</div>;
  }
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(className, 'cursor-pointer hover:bg-surface-2')}
    >
      {content}
    </button>
  );
}
