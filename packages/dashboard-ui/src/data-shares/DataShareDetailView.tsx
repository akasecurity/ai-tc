'use client';
// Data Shares detail drawer body: a destination overview that drills into a
// single endpoint (URL, classification, and the call sites in code that invoke
// it). Rendered inside a ui-kit Sheet by the app. Pure/props-driven; selection
// navigation and the egress-decision footer are handled by the app. All shapes
// are @akasecurity/schema types.
import type {
  CallSite,
  EgressDecision,
  EndpointWithSites,
  ShareDestinationDetail,
} from '@akasecurity/schema';
import { Badge, Button, cn } from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { MetaItem, SectionLabel } from '../shared/DetailFields.tsx';
import {
  BracesIcon,
  CheckIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ExternalShareIcon,
  PolicyIcon,
  RepoIcon,
  SlashCircleIcon,
} from '../shared/icons.tsx';
import { ClassTag, DestMark, MethodTag, TemplateUrl, TransportTag, TrustTag } from './atoms.tsx';
import { TRUST_META } from './meta.ts';

function CallSiteCard({ st }: { st: CallSite }) {
  return (
    <div className="rounded-lg border border-border bg-surface p-3">
      <div className="mb-1.5 flex items-center gap-2">
        <RepoIcon aria-hidden focusable={false} className="size-3.5 shrink-0 text-primary" />
        <span className="text-xs font-semibold text-text">{st.project}</span>
        {st.vendored ? (
          <span className="ml-auto">
            <Badge variant="high">Vendored</Badge>
          </span>
        ) : (
          st.dynamic && (
            <span className="ml-auto">
              <Badge variant="default">
                <BracesIcon aria-hidden focusable={false} className="size-2.5" />
                Dynamic
              </Badge>
            </span>
          )
        )}
      </div>
      <span className="font-mono text-xs text-text-3">
        {st.file}:<b className="text-text-2">{st.line}</b>
      </span>
      <div className="overflow-x-auto whitespace-pre rounded-md bg-ink px-2.5 py-2 font-mono text-xs leading-relaxed text-white mt-0.5">
        <span className="text-code-muted">
          {st.file.split('/').pop()}:{st.line}
          {'  '}
        </span>
        {st.snippet}
      </div>
    </div>
  );
}

function DestDetail({
  d,
  onPick,
}: {
  d: ShareDestinationDetail;
  onPick: (endpointId: string) => void;
}) {
  const tm = TRUST_META[d.trust];
  const TrustIcon = tm.icon;
  const callSites = d.endpoints.reduce((n, ep) => n + ep.callSiteCount, 0);
  return (
    <>
      <div className="flex items-start gap-3">
        <DestMark kind={d.kind} trust={d.trust} name={d.name} host={d.host} size={44} />
        <div className="min-w-0">
          <div
            className={cn(
              'text-lg font-semibold text-text',
              d.kind === 'ip' ? 'font-mono' : 'font-display',
            )}
          >
            {d.name}
          </div>
          <div className="mt-0.5 text-xs text-text-3">
            {d.category} · {d.endpoints.length} endpoints · {callSites} call sites
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <TrustTag trust={d.trust} />
        {d.transports.map((t) => (
          <TransportTag key={t} transport={t} />
        ))}
      </div>

      {(d.note !== null || d.network?.geo != null) && (
        <div className="flex gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
          <TrustIcon aria-hidden focusable={false} className="mt-0.5 size-4 shrink-0 text-text-2" />
          <div className="text-xs leading-normal text-text-2">
            {d.network?.geo != null && (
              <div>
                <b className="text-text">Resolves to </b>
                {d.network.geo}
                {d.network.ptr != null ? ' · ' + d.network.ptr : ''}
              </div>
            )}
            {d.note != null && <div className={d.network?.geo != null ? 'mt-1' : ''}>{d.note}</div>}
          </div>
        </div>
      )}

      <div>
        <SectionLabel>Endpoints</SectionLabel>
        <div className="flex flex-col gap-2">
          {d.endpoints.map((ep) => (
            <button
              key={ep.id}
              type="button"
              onClick={() => {
                onPick(ep.id);
              }}
              className="flex w-full cursor-pointer items-center gap-2.5 rounded-lg border border-border bg-surface px-3 py-2.5 text-left hover:bg-surface-2"
            >
              <MethodTag method={ep.method} />
              <div className="min-w-0 flex-1">
                <TemplateUrl url={ep.url} />
                <div className="mt-1 flex items-center gap-2">
                  <TransportTag transport={ep.transport} plain />
                  <span className="text-xs text-text-3">
                    · {ep.callSiteCount} call{ep.callSiteCount === 1 ? '' : 's'}
                  </span>
                </div>
              </div>
              <ChevronRightIcon
                aria-hidden
                focusable={false}
                className="size-4 shrink-0 text-text-3"
              />
            </button>
          ))}
        </div>
      </div>
    </>
  );
}

function EndpointDetail({
  d,
  ep,
  onBack,
}: {
  d: ShareDestinationDetail;
  ep: EndpointWithSites;
  onBack: () => void;
}) {
  return (
    <>
      <div>
        <Button onClick={onBack} size="sm" variant="link" tone="primary">
          <ChevronLeftIcon aria-hidden focusable={false} className="size-3.5" />
          Back to destination
        </Button>
      </div>

      <div>
        <div className="mb-2 flex items-center gap-2.5">
          <MethodTag method={ep.method} />
          <DestMark kind={d.kind} trust={d.trust} name={d.name} host={d.host} size={22} />
          <span className="text-xs font-semibold text-text-3">{d.name}</span>
        </div>
        <div className="rounded-lg border border-border bg-surface-2 px-3 py-2.5">
          <TemplateUrl url={ep.url} big />
        </div>
      </div>

      {ep.template && (
        <div className="flex gap-2.5 rounded-lg border border-border bg-primary-tint px-3 py-2.5">
          <BracesIcon
            aria-hidden
            focusable={false}
            className="mt-0.5 size-4 shrink-0 text-primary"
          />
          <div>
            <div className="mb-0.5 text-xs font-semibold text-text">Templated URL</div>
            <div className="text-xs leading-normal text-text-2">
              Built at runtime — the{' '}
              <span className="rounded bg-primary-tint px-1 font-mono font-semibold text-primary">
                ${'{…}'}
              </span>{' '}
              segments vary per request, so individual generated URLs aren’t itemized.
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-x-3 gap-y-3.5">
        <MetaItem label="Method">{ep.method}</MetaItem>
        <MetaItem label="Transport">
          <TransportTag transport={ep.transport} plain />
        </MetaItem>
        <MetaItem label="Data classification">
          <span className="inline-flex">
            <ClassTag cls={ep.dataClass} />
          </span>
        </MetaItem>
        <MetaItem label="Last seen">{relativeTime(ep.lastSeen)}</MetaItem>
      </div>

      <div>
        <SectionLabel>Call sites</SectionLabel>
        <div className="flex flex-col gap-2">
          {ep.sites.map((st) => (
            <CallSiteCard key={st.id} st={st} />
          ))}
        </div>
      </div>
    </>
  );
}

export interface DataShareDetailViewProps {
  destination: ShareDestinationDetail;
  /** The endpoint being viewed, or null for the destination overview. */
  endpoint: EndpointWithSites | null;
  onPick: (endpointId: string) => void;
  onBack: () => void;
  /** Write the per-destination egress decision (`null` clears the override). */
  onSetDecision: (decision: EgressDecision | null) => void;
  isSettingDecision: boolean;
}

export function DataShareDetailView({
  destination: d,
  endpoint,
  onPick,
  onBack,
  onSetDecision,
  isSettingDecision,
}: DataShareDetailViewProps) {
  // `status` (effective egress state) and `isCustom` (override differs from the
  // trust default) already ride on the destination — read them from there.
  const blocked = d.status === 'blocked';
  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex items-center gap-2.5 border-b border-border px-4.5 py-4 pr-12">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-text-3">
          <ExternalShareIcon aria-hidden focusable={false} className="size-4" />
          {endpoint ? 'Endpoint' : 'Destination'}
        </span>
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4.5">
        {endpoint ? (
          <EndpointDetail d={d} ep={endpoint} onBack={onBack} />
        ) : (
          <DestDetail d={d} onPick={onPick} />
        )}
      </div>

      <footer className="flex flex-col gap-2 border-t border-border p-3.5">
        <div className="flex gap-2">
          <Button variant="outline" className="flex-1">
            <PolicyIcon aria-hidden focusable={false} />
            Add policy
          </Button>
          {blocked ? (
            <Button
              variant="outline"
              className="flex-1 border-ok-fill text-ok hover:bg-ok-fill"
              disabled={isSettingDecision}
              onClick={() => {
                onSetDecision('allow');
              }}
            >
              <CheckIcon aria-hidden focusable={false} />
              Allow egress
            </Button>
          ) : (
            <Button
              variant="solid"
              tone="danger"
              className="flex-1"
              disabled={isSettingDecision}
              onClick={() => {
                onSetDecision('block');
              }}
            >
              <SlashCircleIcon aria-hidden focusable={false} />
              Block egress
            </Button>
          )}
        </div>
        {d.isCustom && (
          <Button
            variant="ghost"
            size="sm"
            tone="neutral"
            className="self-center text-xs text-text-3"
            disabled={isSettingDecision}
            onClick={() => {
              onSetDecision(null);
            }}
          >
            Reset to default ({TRUST_META[d.trust].label})
          </Button>
        )}
      </footer>
    </div>
  );
}
