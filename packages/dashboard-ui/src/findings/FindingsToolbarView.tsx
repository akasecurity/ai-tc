'use client';

import type { FindingFacets, FindingProvider } from '@akasecurity/schema';
import { Button, cn, Popover, PopoverContent, PopoverTrigger } from '@akasecurity/ui-kit';

import { numberFormat } from '../security/widget-shared.tsx';
import { CheckIcon, ChevronDownIcon, SearchIcon, SlidersIcon } from '../shared/icons.tsx';
import { PROVIDERS } from '../shared/Provider.tsx';
import {
  type ColumnVisibility,
  type FindingColumn,
  type FindingsFilters,
  SEVERITIES,
} from './meta.ts';

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

/** Filter bar shown above the findings table — severity / type / provider / action. */
export function FindingsToolbarView({
  facets,
  filters,
  onFiltersChange,
  query,
  onQueryChange,
  findingCount,
  typeCount,
}: {
  facets: FindingFacets;
  filters: FindingsFilters;
  onFiltersChange: (next: FindingsFilters) => void;
  query: string;
  onQueryChange: (next: string) => void;
  findingCount: number;
  typeCount: number;
}) {
  // Severities always render in display order; counts come from the facet
  // (absent ⇒ 0). Type/provider/action are facet-driven, each run through
  // withSelected so a selected value the facet omits stays deselectable.
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
          className="h-9 w-full rounded-lg border border-border bg-surface-2 pl-9 pr-3 text-sm text-text placeholder:text-text-3 focus:border-primary focus:outline-none"
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
      <span className="h-6 bg-border w-px" />
      <span className="text-sm text-text-3">
        <span className="font-semibold text-text">{numberFormat.format(findingCount)}</span> finding
        {findingCount === 1 ? '' : 's'} ·{' '}
        <span className="font-semibold text-text">{numberFormat.format(typeCount)}</span> type
        {typeCount === 1 ? '' : 's'}
      </span>
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
          <span className="flex size-4 items-center justify-center rounded-full bg-primary text-[10px] font-semibold text-text-inv">
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
                  checked ? 'border-primary bg-primary text-text-inv' : 'border-border',
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

/**
 * Column-visibility menu for the header "Columns" button. Visibility is a plain
 * `{ id: boolean }` map (absent ⇒ visible). Deselecting the last visible column
 * resets to all-visible — "nothing selected" means "everything selected".
 */
export function ColumnsMenu({
  columns,
  visibility,
  onChange,
}: {
  columns: FindingColumn[];
  visibility: ColumnVisibility;
  onChange: (next: ColumnVisibility) => void;
}) {
  const isVisible = (id: FindingColumn['id']) => visibility[id] !== false;
  const visibleCount = columns.filter((c) => isVisible(c.id)).length;

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline">
          <SlidersIcon /> Columns
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="min-w-44 p-1">
        {columns.map((column) => {
          const checked = isVisible(column.id);
          return (
            <button
              key={column.id}
              type="button"
              onClick={() => {
                if (checked && visibleCount === 1) {
                  onChange({}); // reset to all-visible
                } else {
                  onChange({ ...visibility, [column.id]: !checked });
                }
              }}
              className="flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-text hover:bg-surface-2"
            >
              <span
                className={cn(
                  'flex size-4 shrink-0 items-center justify-center rounded border',
                  checked ? 'border-primary bg-primary text-text-inv' : 'border-border',
                )}
              >
                {checked && <CheckIcon className="size-3" />}
              </span>
              {column.header}
            </button>
          );
        })}
      </PopoverContent>
    </Popover>
  );
}
