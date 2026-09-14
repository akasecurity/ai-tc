'use client';
// Expandable Data Shares register for one destination kind — the app picks
// which group's rows this renders (see DataSharesKindTabsView, the sibling
// tab strip that drives the choice); each destination row expands to reveal
// its endpoint rows. Pure and props-driven — expansion/selection state and
// all handlers come from the app; all shapes are @akasecurity/schema types.
import type {
  DataClass,
  EgressStatus,
  EndpointSummary,
  ShareDestinationGroup,
  ShareDestinationSummary,
  ShareTrustLevel,
} from '@akasecurity/schema';
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

import { relativeTime } from '../lib/relativeTime.ts';
import { AlertIcon, ChevronRightIcon } from '../shared/icons.tsx';
import {
  ClassTag,
  DestMark,
  MethodTag,
  StatusTag,
  TemplatePill,
  TemplateUrl,
  TransportTag,
  TrustTag,
} from './atoms.tsx';
import { bindId, bindTwoIds } from './bindings.ts';
import {
  groupByProvider as foldByProvider,
  type ProviderGroup,
  type RegisterRow,
} from './grouping.ts';
import { hasInsecureTransport } from './meta.ts';
import type { ShareSelection } from './types.ts';

export interface DataSharesTableViewProps {
  group: ShareDestinationGroup;
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
  onOpenEndpoint: (id: string, endpointId: string) => void;
  /**
   * The instant this render is measured against, in epoch milliseconds. The host
   * captures one and every relative label below reads it. Required: a view that
   * picks its own instant renders one string while the server renders it and
   * another when the browser hydrates it. See ../lib/relativeTime.ts.
   */
  renderedAt: number;
  /**
   * Fold destinations sharing a provider into one expandable provider row
   * (see grouping.ts). Defaults to false, so an app that doesn't pass this
   * keeps rendering one row per destination.
   */
  groupByProvider?: boolean;
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
  renderedAt,
  expanded,
  selected,
  onToggle,
  onOpen,
  showHost,
}: {
  d: ShareDestinationSummary;
  renderedAt: number;
  expanded: boolean;
  selected: boolean;
  onToggle: () => void;
  onOpen: () => void;
  /**
   * Renders this row as a provider's host, nested under its ProviderRow: the
   * primary label becomes the host rather than the name, with the name
   * demoted to the sub-line, and a left-indent marker (matching EndpointRow's)
   * shows it belongs to the provider row above it.
   */
  showHost?: boolean;
}) {
  const insecure = hasInsecureTransport(d.transports);
  return (
    <TableRow
      onClick={onOpen}
      aria-label={`View details for destination ${d.name}`}
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
          {showHost && (
            <span className="h-3.5 w-3.5 shrink-0 rounded-bl border-b-[1.5px] border-l-[1.5px] border-border-strong" />
          )}
          <DestMark kind={d.kind} trust={d.trust} name={d.name} providerId={d.providerId} />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  'whitespace-nowrap font-semibold text-text',
                  !showHost && d.kind === 'ip' && 'font-mono',
                )}
              >
                {showHost ? d.host : d.name}
              </span>
              {insecure && (
                <span title="Sends over plaintext" className="inline-flex text-sev-critical-ink">
                  <AlertIcon aria-hidden focusable={false} className="size-3.5" />
                </span>
              )}
            </div>
            <div className="whitespace-nowrap text-xs text-text-3">
              {showHost ? (
                <>
                  {d.name} · {d.category}
                </>
              ) : (
                <>
                  {d.host !== d.name ? `${d.host} · ` : ''}
                  {d.category}
                  {d.network?.geo ? ' · ' + d.network.geo : ''}
                </>
              )}
            </div>
          </div>
        </div>
      </TableCell>
      <TableCell>
        <TrustTag trust={d.trust} />
      </TableCell>
      <TableCell>
        <StatusTag status={d.status} isCustom={d.isCustom} />
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap gap-1.5">
          {d.transports.map((t) => (
            <TransportTag key={t} transport={t} />
          ))}
        </div>
      </TableCell>
      <TableCell>
        <ClassCell classes={d.dataClasses} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        <b className="text-text">{d.endpointCount}</b> endpoint
        {d.endpointCount === 1 ? '' : 's'} · <b className="text-text">{d.callSiteCount}</b> call
        {d.callSiteCount === 1 ? '' : 's'}
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        {relativeTime(d.lastSeen, renderedAt)}
      </TableCell>
    </TableRow>
  );
}

/** The host with the latest `lastSeen` — non-empty by construction. */
function mostRecentHost(hosts: ShareDestinationSummary[]): ShareDestinationSummary {
  return hosts.reduce((a, b) => (b.lastSeen > a.lastSeen ? b : a));
}

/** The value every host shares, or null once any host disagrees. */
function sharedValue<T>(
  hosts: ShareDestinationSummary[],
  read: (d: ShareDestinationSummary) => T,
): T | null {
  const [firstHost, ...restHosts] = hosts;
  if (firstHost === undefined) return null;
  const value = read(firstHost);
  return restHosts.every((h) => read(h) === value) ? value : null;
}

function ProviderRow({
  g,
  renderedAt,
  expanded,
  pinnedOpen,
  onToggle,
}: {
  g: ProviderGroup;
  renderedAt: number;
  expanded: boolean;
  /**
   * The row is held open because one of its hosts is showing in the drawer;
   * the toggle is disabled rather than flipping a state nothing renders.
   */
  pinnedOpen: boolean;
  onToggle: () => void;
}) {
  const trust: ShareTrustLevel | null = sharedValue(g.hosts, (d) => d.trust);
  const status: EgressStatus | null = sharedValue(g.hosts, (d) => d.status);
  const isCustom = g.hosts.some((d) => d.isCustom);
  const verb = expanded ? 'Collapse' : 'Expand';
  return (
    <TableRow
      onClick={pinnedOpen ? undefined : onToggle}
      aria-label={`${verb} provider ${g.name}`}
      className={cn(!pinnedOpen && 'cursor-pointer hover:bg-surface-2')}
    >
      <TableCell className="w-9">
        <Button
          aria-label={pinnedOpen ? 'Kept open while a host is selected' : verb}
          disabled={pinnedOpen}
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
          <DestMark
            kind="provider"
            trust={mostRecentHost(g.hosts).trust}
            name={g.name}
            providerId={g.providerId}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="whitespace-nowrap font-semibold text-text">{g.name}</span>
              {g.insecure && (
                <span title="Sends over plaintext" className="inline-flex text-sev-critical-ink">
                  <AlertIcon aria-hidden focusable={false} className="size-3.5" />
                </span>
              )}
            </div>
            <div className="whitespace-nowrap text-xs text-text-3">
              {g.category} · {g.hosts.length} hosts
            </div>
          </div>
        </div>
      </TableCell>
      <TableCell>
        {trust ? <TrustTag trust={trust} /> : <span className="text-xs text-text-3">Mixed</span>}
      </TableCell>
      <TableCell>
        {status ? (
          <StatusTag status={status} isCustom={isCustom} />
        ) : (
          <span className="text-xs text-text-3">Mixed</span>
        )}
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap gap-1.5">
          {g.transports.map((t) => (
            <TransportTag key={t} transport={t} />
          ))}
        </div>
      </TableCell>
      <TableCell>
        <ClassCell classes={g.dataClasses} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        <b className="text-text">{g.endpointCount}</b> endpoint
        {g.endpointCount === 1 ? '' : 's'} · <b className="text-text">{g.callSiteCount}</b> call
        {g.callSiteCount === 1 ? '' : 's'}
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        {relativeTime(g.lastSeen, renderedAt)}
      </TableCell>
    </TableRow>
  );
}

function EndpointRow({
  ep,
  renderedAt,
  selected,
  onClick,
}: {
  ep: EndpointSummary;
  renderedAt: number;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <TableRow
      onClick={onClick}
      aria-label={`View details for endpoint ${ep.method} ${ep.url}`}
      className={cn(
        'cursor-pointer',
        selected ? 'bg-primary-tint' : 'bg-surface-2 hover:bg-surface-3',
      )}
    >
      <TableCell className="w-9" />
      {/* Destination + Trust + Status: all three are destination-level, so the
          endpoint's own cell spans them rather than rendering blanks. */}
      <TableCell colSpan={3}>
        <div className="flex min-w-0 items-center gap-2.5 pl-1.5 py-1">
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
        <ClassTag cls={ep.dataClass} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        <b className="text-text">{ep.callSiteCount}</b> call{ep.callSiteCount === 1 ? '' : 's'}
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-text-3">
        {relativeTime(ep.lastSeen, renderedAt)}
      </TableCell>
    </TableRow>
  );
}

/** A destination row plus its (conditionally rendered) endpoint rows. */
function DestinationRows({
  d,
  renderedAt,
  expanded,
  selection,
  drawerOpen,
  onToggle,
  onOpenDest,
  onOpenEndpoint,
  showHost,
}: {
  d: ShareDestinationSummary;
  renderedAt: number;
  expanded: boolean;
  selection: ShareSelection | null;
  drawerOpen: boolean;
  onToggle: (id: string) => void;
  onOpenDest: (id: string) => void;
  onOpenEndpoint: (id: string, endpointId: string) => void;
  showHost?: boolean;
}) {
  const groupSel = drawerOpen && selection?.id === d.id && selection.endpointId == null;
  return (
    <>
      <GroupRow
        d={d}
        renderedAt={renderedAt}
        expanded={expanded}
        selected={groupSel}
        onToggle={bindId(onToggle, d.id)}
        onOpen={bindId(onOpenDest, d.id)}
        {...(showHost ? { showHost: true } : {})}
      />
      {expanded &&
        d.endpoints.map((ep) => (
          <EndpointRow
            key={ep.id}
            ep={ep}
            renderedAt={renderedAt}
            selected={drawerOpen && selection?.id === d.id && selection.endpointId === ep.id}
            onClick={bindTwoIds(onOpenEndpoint, d.id, ep.id)}
          />
        ))}
    </>
  );
}

export function DataSharesTableView({
  group,
  expanded,
  forceExpand,
  selection,
  drawerOpen,
  onToggle,
  onOpenDest,
  onOpenEndpoint,
  renderedAt,
  groupByProvider,
}: DataSharesTableViewProps) {
  // Folding is opt-in (defaults to false), so an app that omits the prop gets
  // exactly the one-row-per-destination list it always has.
  const rows: RegisterRow[] = groupByProvider
    ? foldByProvider(group.items)
    : group.items.map((item): RegisterRow => ({ type: 'destination', item }));
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-9" />
          <TableHead>Destination</TableHead>
          <TableHead>Trust</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Transport</TableHead>
          <TableHead>Data sent</TableHead>
          <TableHead>Footprint</TableHead>
          <TableHead>Last seen</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => {
          if (row.type === 'destination') {
            const d = row.item;
            const isExp = (forceExpand ?? false) || !!expanded[d.id];
            return (
              <Fragment key={d.id}>
                <DestinationRows
                  d={d}
                  renderedAt={renderedAt}
                  expanded={isExp}
                  selection={selection}
                  drawerOpen={drawerOpen}
                  onToggle={onToggle}
                  onOpenDest={onOpenDest}
                  onOpenEndpoint={onOpenEndpoint}
                />
              </Fragment>
            );
          }
          const g = row.group;
          // A host selected in the drawer must stay visible, so the provider row
          // it sits under opens on its own while that selection is showing.
          const holdsSelection = drawerOpen && g.hosts.some((h) => h.id === selection?.id);
          const isExp = (forceExpand ?? false) || !!expanded[g.id] || holdsSelection;
          return (
            <Fragment key={g.id}>
              <ProviderRow
                g={g}
                renderedAt={renderedAt}
                expanded={isExp}
                pinnedOpen={holdsSelection}
                onToggle={bindId(onToggle, g.id)}
              />
              {isExp &&
                g.hosts.map((d) => {
                  const hostExp = (forceExpand ?? false) || !!expanded[d.id];
                  return (
                    <Fragment key={d.id}>
                      <DestinationRows
                        d={d}
                        renderedAt={renderedAt}
                        expanded={hostExp}
                        selection={selection}
                        drawerOpen={drawerOpen}
                        onToggle={onToggle}
                        onOpenDest={onOpenDest}
                        onOpenEndpoint={onOpenEndpoint}
                        showHost
                      />
                    </Fragment>
                  );
                })}
            </Fragment>
          );
        })}
      </TableBody>
    </Table>
  );
}
