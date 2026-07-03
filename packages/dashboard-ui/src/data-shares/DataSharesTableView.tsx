// Grouped, expandable Data Shares register. Destinations are sectioned by kind
// (providers / internal domains / raw IPs); each group row expands to reveal its
// endpoint rows. Pure and props-driven — expansion/selection state and all
// handlers come from the app.
import {
  Button,
  cn,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import { AlertIcon, ChevronRightIcon } from '../shared/icons.tsx';
import {
  ClassTag,
  DestMark,
  MethodTag,
  TemplatePill,
  TemplateUrl,
  TransportTag,
  TrustTag,
} from './atoms.tsx';
import { destClasses, destSites, destTransports, hasInsecure, KIND_LABEL } from './meta.ts';
import type {
  DataClass,
  ShareDestination,
  ShareEndpoint,
  ShareGroup,
  ShareSelection,
} from './types.ts';

export interface DataSharesTableViewProps {
  groups: ShareGroup[];
  /** Which group rows are expanded (by destination id). */
  expanded: Record<string, boolean>;
  /** Force every group open (used while a search query is active). */
  forceExpand?: boolean;
  /** Currently open selection in the drawer, or null. */
  selection: ShareSelection | null;
  /** Whether the detail drawer is open (drives row highlight). */
  drawerOpen: boolean;
  onToggle: (id: string) => void;
  onOpenDest: (id: string) => void;
  onOpenEndpoint: (id: string, ei: number) => void;
}

function ClassCell({ classes }: { classes: DataClass[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {classes.slice(0, 3).map((c) => (
        <ClassTag key={c} cls={c} />
      ))}
      {classes.length > 3 && <span className="text-xs text-text-3">+{classes.length - 3}</span>}
    </div>
  );
}

function GroupRow({
  d,
  expanded,
  selected,
  onToggle,
  onOpen,
}: {
  d: ShareDestination;
  expanded: boolean;
  selected: boolean;
  onToggle: () => void;
  onOpen: () => void;
}) {
  const transports = destTransports(d);
  const nSites = destSites(d);
  const insecure = hasInsecure(d);
  return (
    <TableRow
      onClick={onOpen}
      className={cn('cursor-pointer', selected ? 'bg-primary-tint' : 'hover:bg-surface-2')}
    >
      <TableCell className="w-9">
        <Button
          aria-label={expanded ? 'Collapse' : 'Expand'}
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          variant="ghost"
          size="sm"
        >
          <ChevronRightIcon
            aria-hidden
            focusable={false}
            className={cn('size-4 transition-transform', expanded && 'rotate-90')}
          />
        </Button>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-3">
          <DestMark d={d} />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  'whitespace-nowrap font-semibold text-text',
                  d.kind === 'ip' && 'font-mono',
                )}
              >
                {d.name}
              </span>
              {insecure && (
                <span title="Sends over plaintext" className="inline-flex text-sev-critical">
                  <AlertIcon aria-hidden focusable={false} className="size-3.5" />
                </span>
              )}
            </div>
            <div className="whitespace-nowrap text-xs text-text-3">
              {d.category}
              {d.geo ? ' · ' + d.geo : ''}
            </div>
          </div>
        </div>
      </TableCell>
      <TableCell>
        <TrustTag trust={d.trust} />
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap gap-1.5">
          {transports.map((t) => (
            <TransportTag key={t} transport={t} />
          ))}
        </div>
      </TableCell>
      <TableCell>
        <ClassCell classes={destClasses(d)} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        <b className="text-text">{d.endpoints.length}</b> endpoint
        {d.endpoints.length === 1 ? '' : 's'} · <b className="text-text">{nSites}</b> call
        {nSites === 1 ? '' : 's'}
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">{d.lastSeen}</TableCell>
      <TableCell className="w-9"></TableCell>
    </TableRow>
  );
}

function EndpointRow({
  ep,
  selected,
  onClick,
}: {
  ep: ShareEndpoint;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <TableRow
      onClick={onClick}
      className={cn(
        'cursor-pointer',
        selected ? 'bg-primary-tint' : 'bg-surface-2 hover:bg-surface-3',
      )}
    >
      <TableCell className="w-9" />
      <TableCell colSpan={2}>
        <div className="flex min-w-0 items-center gap-2.5 pl-1.5">
          <span className="h-3.5 w-3.5 shrink-0 rounded-bl border-b-[1.5px] border-l-[1.5px] border-border-strong" />
          <MethodTag method={ep.method} />
          <span className="flex min-w-0 items-center gap-2">
            <TemplateUrl url={ep.url} />
            {ep.template && <TemplatePill />}
          </span>
        </div>
      </TableCell>
      <TableCell>
        <TransportTag transport={ep.transport} />
      </TableCell>
      <TableCell>
        <ClassTag cls={ep.cls} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        <b className="text-text">{ep.sites.length}</b> call{ep.sites.length === 1 ? '' : 's'}
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">{ep.lastSeen}</TableCell>
      <TableCell className="w-9">
        <div className="size-7 grid place-items-center">
          <ChevronRightIcon aria-hidden focusable={false} className="size-4 text-text-3" />
        </div>
      </TableCell>
    </TableRow>
  );
}

/** Full-width kind-section header row rendered between destination groups. */
function SectionRow({ group }: { group: ShareGroup }) {
  return (
    <TableRow className="border-0 hover:bg-transparent">
      <TableCell colSpan={8} className="pb-2 pt-4">
        <div className="flex items-center gap-2">
          <span className="text-label font-semibold uppercase tracking-wider text-text-3">
            {KIND_LABEL[group.kind]}
          </span>
          <span className="rounded-full border border-border bg-surface-2 px-1.5 text-label py-0.5 font-semibold text-text-2">
            {group.items.length}
          </span>
          {group.kind === 'ip' && (
            <span className="inline-flex items-center gap-1 text-xs text-sev-critical">
              <AlertIcon aria-hidden focusable={false} className="size-3" />
              review recommended
            </span>
          )}
        </div>
      </TableCell>
    </TableRow>
  );
}

export function DataSharesTableView({
  groups,
  expanded,
  forceExpand,
  selection,
  drawerOpen,
  onToggle,
  onOpenDest,
  onOpenEndpoint,
}: DataSharesTableViewProps) {
  // One table for every group (not a table per kind) so columns stay aligned
  // across the Providers / Internal / Raw-IP sections — a single auto-layout
  // table shares one set of column widths. Section headers are full-width rows
  // between groups.
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-9" />
          <TableHead>Destination</TableHead>
          <TableHead>Trust</TableHead>
          <TableHead>Transport</TableHead>
          <TableHead>Data sent</TableHead>
          <TableHead>Footprint</TableHead>
          <TableHead>Last seen</TableHead>
          <TableHead className="w-9" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {groups.map((g) => (
          <Fragment key={g.kind}>
            <SectionRow group={g} />
            {g.items.map((d) => {
              const isExp = (forceExpand ?? false) || !!expanded[d.id];
              const groupSel = drawerOpen && selection?.id === d.id && selection.ei == null;
              return (
                <Fragment key={d.id}>
                  <GroupRow
                    d={d}
                    expanded={isExp}
                    selected={groupSel}
                    onToggle={() => {
                      onToggle(d.id);
                    }}
                    onOpen={() => {
                      onOpenDest(d.id);
                    }}
                  />
                  {isExp &&
                    d.endpoints.map((ep, ei) => (
                      <EndpointRow
                        key={ei}
                        ep={ep}
                        selected={drawerOpen && selection?.id === d.id && selection.ei === ei}
                        onClick={() => {
                          onOpenEndpoint(d.id, ei);
                        }}
                      />
                    ))}
                </Fragment>
              );
            })}
          </Fragment>
        ))}
      </TableBody>
    </Table>
  );
}
