'use client';

import { Ico } from '@akasecurity/dashboard-ui';
import { Button, Popover, PopoverContent, PopoverTrigger } from '@akasecurity/ui-kit';
import { Fragment, useState } from 'react';

import type { DirEntry } from './actions';
import { listDirectory } from './actions';

export function DirectoryBrowser({ onSelect }: { onSelect: (path: string) => void }) {
  const [open, setOpen] = useState(false);
  const [consented, setConsented] = useState(false);
  const [current, setCurrent] = useState<string | null>(null);
  const [crumbs, setCrumbs] = useState<DirEntry[]>([]);
  const [parent, setParent] = useState<string | null>(null);
  const [entries, setEntries] = useState<DirEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setConsented(false);
    setCurrent(null);
    setCrumbs([]);
    setParent(null);
    setEntries([]);
    setError(null);
  };

  // Close from a button handler. Unlike Radix's own close paths (Escape,
  // outside click), a direct setOpen(false) does NOT fire onOpenChange, so the
  // reset must run here too — otherwise `consented` sticks and reopening skips
  // the consent step.
  const close = () => {
    setOpen(false);
    reset();
  };

  const load = (path?: string) => {
    setLoading(true);
    setError(null);
    void listDirectory(path)
      .then((result) => {
        if (!result.ok || !result.path || !result.entries || !result.crumbs) {
          setError(result.error ?? 'Could not list directory.');
          return;
        }
        setCurrent(result.path);
        setCrumbs(result.crumbs);
        setParent(result.parent ?? null);
        setEntries(result.entries);
      })
      .catch(() => {
        setError('Could not list directory.');
      })
      .finally(() => {
        setLoading(false);
      });
  };

  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <PopoverTrigger asChild>
        <Button variant="ghost" tone="neutral" size="sm">
          Browse…
        </Button>
      </PopoverTrigger>

      <PopoverContent align="end" className="w-96 p-4">
        <div className="mb-3 flex items-center justify-between">
          <span className="text-label font-semibold uppercase tracking-wider text-text-3">
            {consented ? 'Choose a folder' : 'Browse your filesystem'}
          </span>
          <button
            type="button"
            aria-label="Close"
            onClick={close}
            className="rounded p-1 text-text-3 hover:text-text"
          >
            <Ico name="x" className="size-3.5" />
          </button>
        </div>

        {!consented ? (
          <div className="flex flex-col gap-3">
            <p className="text-xs text-text-3">
              AKA will list folder names on your machine, starting from your home directory. Nothing
              is read or scanned until you click Scan.
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" tone="neutral" size="sm" onClick={close}>
                Cancel
              </Button>
              <Button
                variant="solid"
                tone="primary"
                size="sm"
                onClick={() => {
                  setConsented(true);
                  load(undefined);
                }}
              >
                Allow
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex min-w-0 flex-wrap items-center gap-1 text-xs">
              {parent && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-6"
                  title="Up one level"
                  onClick={() => {
                    load(parent);
                  }}
                >
                  <Ico name="arrow-up" className="size-3.5" />
                </Button>
              )}
              {crumbs.map((crumb, i) => {
                const last = i === crumbs.length - 1;
                return (
                  <Fragment key={crumb.path}>
                    {i > 0 && <Ico name="chevron-right" className="size-3 text-text-3" />}
                    <button
                      type="button"
                      onClick={() => {
                        load(crumb.path);
                      }}
                      className={
                        last
                          ? 'cursor-default font-mono font-bold text-text'
                          : 'font-mono text-text-2 hover:text-text'
                      }
                    >
                      {crumb.name}
                    </button>
                  </Fragment>
                );
              })}
            </div>

            <div className="max-h-64 overflow-y-auto rounded-lg border border-border">
              {loading && <div className="p-3 text-xs text-text-3">Loading…</div>}
              {!loading && error && <div className="p-3 text-xs text-sev-critical">{error}</div>}
              {!loading &&
                !error &&
                entries.map((entry) => (
                  <button
                    key={entry.path}
                    type="button"
                    onClick={() => {
                      load(entry.path);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-2"
                  >
                    <Ico name="folder" className="size-4 shrink-0 text-primary" />
                    <span className="truncate text-text">{entry.name}</span>
                  </button>
                ))}
              {!loading && !error && entries.length === 0 && (
                <div className="p-3 text-xs text-text-3">No subfolders.</div>
              )}
            </div>

            <div className="flex justify-end">
              <Button
                variant="solid"
                tone="primary"
                size="sm"
                disabled={!current}
                onClick={() => {
                  if (current) onSelect(current);
                  close();
                }}
              >
                Select this folder
              </Button>
            </div>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
