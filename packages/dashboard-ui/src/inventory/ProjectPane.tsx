'use client';

// Right pane shown when a project is selected: an API-backed file browser with
// breadcrumb, in-project search and a folder/file table whose rows carry the
// per-file LLM-access toggle. Each directory level is fetched from
// GET /v1/inventory/projects/:id/tree (browse mode → folders+files at a path;
// search mode → a flat, repo-wide match list). Access changes are written back
// through PUT .../files/access.
import type {
  AccessLevel,
  FileSummary,
  FolderSummary,
  ProjectSummary,
  ProjectTreeResponse,
} from '@akasecurity/schema';
import {
  Button,
  Card,
  cn,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import { AccessBar, AccessControl, AccessLabel, OriginTag, VisBadge } from './chips.tsx';
import { ACCESS, ACCESS_ORDER, fmtDateTime, rationale } from './data.ts';
import { Ico } from './Ico.tsx';

export interface ProjectPaneProps {
  proj: ProjectSummary;
  path: string[];
  onPathChange: (p: string[]) => void;
  query: string;
  onQueryChange: (q: string) => void;
  // Current directory level (or flat search results) from useProjectTree.
  tree: ProjectTreeResponse | null;
  isLoading: boolean;
  error: string | null;
  // Fires the setFileAccess mutation for a single file.
  onSetAccess: (path: string, access: AccessLevel) => void;
  onOpenFile: (path: string) => void;
  drawerPath: string | null;
  // Project-wide auto-blocked files (tree `filter=blocked`) for the strip below
  // the header, plus its collapse state. Hidden while searching.
  blocked: FileSummary[];
  showBlocked: boolean;
  onToggleBlocked: () => void;
  // Present only when the project was opened from a harness — closes back to
  // that harness's overview. Omitted in the by-type view, where there's no harness.
  onClose?: (() => void) | undefined;
}

/** Directory portion of a repo-relative file path (empty for a root-level file). */
function dirOf(fullPath: string): string {
  const idx = fullPath.lastIndexOf('/');
  return idx === -1 ? '' : fullPath.slice(0, idx);
}

export function ProjectPane(props: ProjectPaneProps) {
  const { proj, path, onPathChange, query, tree, isLoading, error, onClose } = props;

  const searching = query.trim().length > 0;
  const folders = tree?.folders ?? [];
  const files = tree?.files ?? [];
  const pCounts = proj.accessCounts;

  return (
    <Card className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
      {/* header */}
      <div className="border-b border-border px-5 py-3.5">
        <div className="flex items-center gap-3.5">
          <div className="min-w-0 flex-1">
            <Breadcrumb proj={proj} path={path} onPathChange={onPathChange} />
          </div>
          <SearchBox {...props} />
          {onClose && (
            <Button
              variant="ghost"
              size="icon"
              aria-label="Back to harness"
              title="Back to harness"
              onClick={onClose}
            >
              <Ico name="x" />
            </Button>
          )}
        </div>
        <div className="mt-3 flex items-start gap-2.5">
          <VisBadge v={proj.visibility} />
          <div className="flex min-w-0 flex-1 gap-2.5 flex-wrap justify-between">
            <span className="text-xs text-text-3">{rationale(proj, 'source')}</span>
            <span className="flex items-center gap-3 text-xs text-text-3">
              {ACCESS_ORDER.map((k) => (
                <span key={k} className="inline-flex items-center gap-1.5">
                  <span className={cn('size-2 rounded-sm', ACCESS[k].bar)} />
                  {pCounts[k]} {ACCESS[k].label}
                </span>
              ))}
            </span>
          </div>
        </div>
      </div>

      {!searching && props.blocked.length > 0 && <BlockedStrip {...props} />}

      {/* body */}
      <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-4 pt-2">
        {isLoading && !tree ? (
          <div className="py-12 text-center text-sm text-text-3">Loading files…</div>
        ) : error ? (
          <div className="py-12 text-center text-sm text-sev-critical">{error}</div>
        ) : searching ? (
          files.length > 0 ? (
            <FileTable
              caption={`${String(files.length)} result${files.length === 1 ? '' : 's'}`}
              rows={files}
              showPath
              {...props}
            />
          ) : (
            <div className="py-12 text-center text-text-3">
              <Ico name="search" className="mx-auto mb-2 size-6" />
              <div className="text-sm">No files match “{query}”</div>
            </div>
          )
        ) : folders.length === 0 && files.length === 0 ? (
          <div className="py-12 text-center text-sm text-text-3">This folder is empty</div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Origin</TableHead>
                <TableHead>LLM access</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {folders.map((folder) => (
                <FolderRow
                  key={'d' + folder.name}
                  folder={folder}
                  onOpen={() => {
                    onPathChange([...path, folder.name]);
                  }}
                />
              ))}
              {files.map((file) => (
                <FileRow key={'f' + file.path} file={file} {...props} />
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </Card>
  );
}

function SearchBox({ proj, query, onQueryChange }: ProjectPaneProps) {
  return (
    <div className="relative w-70 shrink-0">
      <Ico name="search" className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-3" />
      <input
        value={query}
        onChange={(e) => {
          onQueryChange(e.target.value);
        }}
        placeholder={`Search files in ${proj.name}…`}
        className="h-9 w-full rounded-lg border border-border bg-surface-2 pl-9 pr-8 text-sm text-text placeholder:text-text-3 focus:border-primary focus:outline-none"
      />
      {query && (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => {
            onQueryChange('');
          }}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-text-3 hover:text-text"
        >
          <Ico name="x" className="size-3.5" />
        </button>
      )}
    </div>
  );
}

function Breadcrumb({
  proj,
  path,
  onPathChange,
}: {
  proj: ProjectSummary;
  path: string[];
  onPathChange: (p: string[]) => void;
}) {
  const crumbs = [proj.name, ...path];
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1.5">
      {path.length > 0 && (
        <Button
          variant="ghost"
          size="icon"
          className="size-7"
          title="Up one level"
          onClick={() => {
            onPathChange(path.slice(0, -1));
          }}
        >
          <Ico name="arrow-up" />
        </Button>
      )}
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return (
          <Fragment key={i}>
            {i > 0 && <Ico name="chevron-right" className="size-3 text-text-3" />}
            <button
              type="button"
              onClick={() => {
                onPathChange(path.slice(0, i));
              }}
              className={cn(
                'rounded px-1 py-0.5 text-sm',
                i === 0 && 'font-mono',
                last
                  ? 'cursor-default font-bold text-text'
                  : 'font-semibold text-text-2 hover:text-text',
              )}
            >
              {c}
            </button>
          </Fragment>
        );
      })}
    </div>
  );
}

function FolderRow({ folder, onOpen }: { folder: FolderSummary; onOpen: () => void }) {
  const counts = folder.accessCounts;
  return (
    <TableRow className="cursor-pointer hover:bg-surface-2" onClick={onOpen}>
      <TableCell>
        <div className="flex items-center gap-2.5">
          <Ico name="folder" className="size-4.5 shrink-0 text-primary" />
          <span className="text-ui font-semibold text-text">{folder.name}</span>
          <span className="text-xs text-text-3">
            {counts.total} file{counts.total === 1 ? '' : 's'}
          </span>
        </div>
      </TableCell>
      <TableCell className="text-xs text-text-3">Folder</TableCell>
      <TableCell>
        <div className="flex items-center gap-3">
          <AccessBar counts={counts} />
          {counts.blocked > 0 ? (
            <span className="text-xs font-semibold text-sev-critical">
              {counts.blocked} blocked
            </span>
          ) : (
            <span className="text-xs text-text-3">{counts.total} allowed</span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <div className="grid size-7 place-items-center" aria-hidden="true">
          <Ico name="chevron-right" className="size-4 text-text-3" />
        </div>
      </TableCell>
    </TableRow>
  );
}

function FileNameCell({ file, showPath }: { file: FileSummary; showPath?: boolean | undefined }) {
  const dir = dirOf(file.path);
  const blocked = file.access === 'blocked';
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <Ico name="file" className="size-4.5 shrink-0 text-text-3" />
      <div className="min-w-0">
        <div className="flex items-baseline gap-1.5 whitespace-nowrap">
          {showPath && dir.length > 0 && (
            <span className="font-mono text-xs text-text-3">{dir}/</span>
          )}
          <span className="font-mono text-xs font-semibold text-text">{file.name}</span>
        </div>
        {file.blockedAt && blocked && (
          <div className="mt-px flex items-center gap-1.5 text-xs text-sev-critical">
            <Ico name="slash-circle" className="size-3" />
            {file.note}
          </div>
        )}
      </div>
    </div>
  );
}

function FileRow({
  file,
  onSetAccess,
  onOpenFile,
  drawerPath,
  showPath,
}: ProjectPaneProps & { file: FileSummary; showPath?: boolean | undefined }) {
  return (
    <TableRow
      className={cn(
        'cursor-pointer hover:bg-surface-2',
        drawerPath === file.path && 'bg-surface-2',
      )}
      onClick={() => {
        onOpenFile(file.path);
      }}
    >
      <TableCell>
        <FileNameCell file={file} showPath={showPath} />
      </TableCell>
      <TableCell>
        <OriginTag origin={file.origin} />
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-3">
          <AccessControl
            value={file.access}
            onChange={(v) => {
              onSetAccess(file.path, v);
            }}
          />
          <AccessLabel value={file.access} />
        </div>
      </TableCell>
      <TableCell>
        <div className="grid size-7 place-items-center" aria-hidden="true">
          <Ico name="chevron-right" className="size-4 text-text-3" />
        </div>
      </TableCell>
    </TableRow>
  );
}

/** Search-results table — flat list with the directory shown inline. */
function FileTable({
  caption,
  rows,
  showPath,
  ...props
}: ProjectPaneProps & { caption: string; rows: FileSummary[]; showPath?: boolean | undefined }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{caption}</TableHead>
          <TableHead>Origin</TableHead>
          <TableHead>LLM access</TableHead>
          <TableHead className="w-10" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((file) => (
          <FileRow key={file.path} file={file} showPath={showPath} {...props} />
        ))}
      </TableBody>
    </Table>
  );
}

/**
 * Collapsible strip above the file table listing every auto-blocked file across
 * the whole project (GET .../tree?filter=blocked). Each row carries the same
 * access toggle as the table, plus a "Review" shortcut into the file drawer.
 */
function BlockedStrip({
  blocked,
  showBlocked,
  onToggleBlocked,
  onSetAccess,
  onOpenFile,
}: ProjectPaneProps) {
  return (
    <div className="border-b border-border bg-surface-2">
      <button
        type="button"
        className="flex w-full items-center gap-2.5 px-4.5 py-3 text-left cursor-pointer"
        onClick={onToggleBlocked}
      >
        <span className="grid size-6 shrink-0 place-items-center rounded-md bg-sev-critical-fill text-sev-critical">
          <Ico name="slash-circle" className="size-3.5" />
        </span>
        <span className="text-ui font-semibold">Recently blocked</span>
        <span className="rounded-full bg-sev-critical px-2 py-px text-xs font-bold text-white">
          {blocked.length}
        </span>
        <span className="text-xs text-text-3">Auto-blocked on detection — review to adjust</span>
        <Ico
          name="chevron-down"
          className={cn(
            'ml-auto size-4.5 text-text-3 transition-transform',
            !showBlocked && '-rotate-90',
          )}
        />
      </button>
      {showBlocked && (
        <div className="flex flex-col gap-2 px-3.5 pb-3">
          {blocked.map((file) => {
            const dir = dirOf(file.path);
            return (
              <div
                key={file.path}
                className="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-1.5 overflow-hidden whitespace-nowrap">
                    {dir.length > 0 && (
                      <span className="font-mono text-xs text-text-3">{dir}/</span>
                    )}
                    <span className="font-mono text-xs font-semibold text-text">{file.name}</span>
                  </div>
                  <div className="mt-0.5 text-xs text-text-3">
                    {file.note}
                    {file.blockedAt ? ` · blocked ${fmtDateTime(file.blockedAt)}` : ''}
                  </div>
                </div>
                <AccessControl
                  value={file.access}
                  onChange={(v) => {
                    onSetAccess(file.path, v);
                  }}
                />
                <AccessLabel value={file.access} />
                <Button
                  variant="ghost"
                  tone="primary"
                  size="sm"
                  onClick={() => {
                    onOpenFile(file.path);
                  }}
                >
                  Review
                </Button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
