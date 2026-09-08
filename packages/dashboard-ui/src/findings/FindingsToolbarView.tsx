'use client';

import type { FindingFacets, FindingProvider } from '@akasecurity/schema';
import { cn, Popover, PopoverContent, PopoverTrigger } from '@akasecurity/ui-kit';

import { CheckIcon, ChevronDownIcon, SearchIcon } from '../shared/icons.tsx';
import { PROVIDERS } from '../shared/Provider.tsx';
import { FINDING_STATUS_META, FINDING_STATUSES, type FindingsFilters, SEVERITIES } from './meta.ts';

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

const providerLabel = (value: string) =>
  value in PROVIDERS ? PROVIDERS[value as FindingProvider].label : value;

interface Option {
  value: string;
  label: string;
  count?: number;
}

/**
 * Merge currently-selected values the facet omitted back into the options (count
 * 0). A facet is computed excluding only its own dimension's filter, so selecting
 * filters in other dimensions can narrow it until an already-selected value drops
 * out of its own list; re-adding it keeps that value individually deselectable.
 */
function withSelected(
  options: Option[],
  selected: string[],
  label: (value: string) => string,
): Option[] {
  const present = new Set(options.map((o) => o.value));
  const missing = selected
    .filter((value) => !present.has(value))
    .map((value) => ({ value, label: label(value), count: 0 }));
  return [...options, ...missing];
}

/**
 * The three FINDING-level filter dimensions: provider, action and status.
 *
 * Its own component because it is rendered in two places that must stay
 * identical — the flat view's toolbar below, and the By-type view's detail
 * panel, where these narrow the findings of the selected type. Severity, type
 * and the search box are deliberately NOT here: they select TYPES, so in the
 * master/detail view they live with the type list instead.
 *
 * The facets it counts against are whatever the caller hands it, which is the
 * point: in the flat view they count the whole list, and in the detail panel
 * they count within the selected type — so "what happens if I pick this?" is
 * answered about the rows the control actually acts on.
 */
export function FindingLevelFilters({
  facets,
  filters,
  onFiltersChange,
}: {
  facets: FindingFacets;
  filters: FindingsFilters;
  onFiltersChange: (next: FindingsFilters) => void;
}) {
  const providerOptions = withSelected(
    facets.provider.map((f) => ({ value: f.value, label: providerLabel(f.value), count: f.count })),
    filters.provider,
    providerLabel,
  );
  const actionOptions = withSelected(
    facets.action.map((f) => ({ value: f.value, label: capitalize(f.value), count: f.count })),
    filters.action,
    capitalize,
  );
  const statusCount = new Map(facets.status.map((f) => [f.value, f.count]));
  const statusOptions = FINDING_STATUSES.map((value) => ({
    value,
    label: FINDING_STATUS_META[value].label,
    count: statusCount.get(value) ?? 0,
  }));

  const set = (key: keyof FindingsFilters, next: string[]) => {
    onFiltersChange({ ...filters, [key]: next });
  };

  return (
    <>
      <MultiSelectFilter
        label="Provider"
        options={providerOptions}
        selected={filters.provider}
        onChange={(next) => {
          set('provider', next);
        }}
      />
      <MultiSelectFilter
        label="Action"
        options={actionOptions}
        selected={filters.action}
        onChange={(next) => {
          set('action', next);
        }}
      />
      <MultiSelectFilter
        label="Status"
        options={statusOptions}
        selected={filters.status}
        onChange={(next) => {
          set('status', next);
        }}
      />
    </>
  );
}

/**
 * The flat view's filter bar: search, severity, type, and the three
 * finding-level dimensions.
 *
 * It carries NO tally. The findings/types counts are page-level and live under
 * the page title, because in the master/detail view they answer a question no
 * single control here acts on — a count sitting beside a filter that cannot
 * move it reads as a filter that stopped working.
 */
export function FindingsToolbarView({
  facets,
  filters,
  onFiltersChange,
  query,
  onQueryChange,
}: {
  facets: FindingFacets;
  filters: FindingsFilters;
  onFiltersChange: (next: FindingsFilters) => void;
  query: string;
  onQueryChange: (next: string) => void;
}) {
  // Severity and type are here because in THIS view one list carries both
  // levels, so every dimension narrows the same rows. The master/detail view
  // renders no toolbar at all: its type-level controls sit with the type list
  // and its finding-level ones with the findings, each beside what it acts on.
  //
  // Severity is a closed enum, so it always renders in display order with counts
  // from the facet (absent ⇒ 0) — no value can drop out of the list. Type is
  // facet-driven and run through withSelected so a selected value the facet
  // omits stays deselectable.
  const severityCount = new Map(facets.severity.map((f) => [f.value, f.count]));
  const severityOptions: Option[] = SEVERITIES.map((s) => ({
    value: s,
    label: capitalize(s),
    count: severityCount.get(s) ?? 0,
  }));
  const typeOptions = withSelected(
    facets.subtype.map((f) => ({ value: f.value, label: f.value, count: f.count })),
    filters.type,
    (value) => value,
  );

  const set = (key: keyof FindingsFilters, next: string[]) => {
    onFiltersChange({ ...filters, [key]: next });
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative w-64">
        <SearchIcon className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-3" />
        <input
          type="text"
          aria-label="Search findings"
          placeholder="Search findings…"
          value={query}
          onChange={(e) => {
            onQueryChange(e.target.value);
          }}
          className="h-9 w-full rounded-lg border border-border-field bg-surface pl-9 pr-3 text-sm text-text placeholder:text-text-3 focus:border-primary focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40"
        />
      </div>
      <MultiSelectFilter
        label="Severity"
        options={severityOptions}
        selected={filters.severity}
        onChange={(next) => {
          set('severity', next);
        }}
      />
      <MultiSelectFilter
        label="Type"
        options={typeOptions}
        selected={filters.type}
        onChange={(next) => {
          set('type', next);
        }}
      />
      <FindingLevelFilters facets={facets} filters={filters} onFiltersChange={onFiltersChange} />
    </div>
  );
}

function MultiSelectFilter({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: Option[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  const active = selected.length > 0;
  const toggle = (value: string) => {
    onChange(selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value]);
  };

  return (
    <Popover>
      <PopoverTrigger
        className={cn(
          'inline-flex h-8 items-center gap-1.5 rounded-lg border px-3 text-sm font-medium transition-colors cursor-pointer',
          active
            ? 'border-primary bg-primary-tint text-primary'
            : 'border-border text-text-2 bg-surface hover:bg-surface-2',
        )}
      >
        {label}
        {active && (
          <span className="flex size-4 items-center justify-center rounded-full bg-primary-solid text-[10px] font-semibold text-text-inv">
            {selected.length}
          </span>
        )}
        <ChevronDownIcon className="size-3.5" />
      </PopoverTrigger>
      <PopoverContent className="min-w-52 max-h-80">
        {options.map((opt) => {
          const checked = selected.includes(opt.value);
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => {
                toggle(opt.value);
              }}
              className="flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-text hover:bg-surface-2"
            >
              <span
                className={cn(
                  'flex size-4 shrink-0 items-center justify-center rounded border',
                  checked ? 'border-primary-solid bg-primary-solid text-text-inv' : 'border-border',
                )}
              >
                {checked && <CheckIcon className="size-3" />}
              </span>
              <span className="flex-1">{opt.label}</span>
              {opt.count !== undefined && (
                <span className="text-xs tabular-nums text-text-3">{opt.count}</span>
              )}
            </button>
          );
        })}
        {active && (
          <button
            type="button"
            onClick={() => {
              onChange([]);
            }}
            className="mt-1 flex w-full cursor-pointer items-center rounded-md border-t border-border px-2 py-1.5 text-left text-sm text-text-2 hover:bg-surface-2"
          >
            Clear
          </button>
        )}
      </PopoverContent>
    </Popover>
  );
}
