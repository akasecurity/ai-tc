// Small shared presentational atoms for the Data Shares views: destination
// marks, method/transport/class/trust chips and template-URL rendering. Pure
// (no state/events) so they render in any host app.
import type {
  DataClass,
  DestinationKind,
  EgressStatus,
  HttpMethod,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';
import { Badge, cn, type Tone, TONE_SOFT } from '@akasecurity/ui-kit';

import { BracesIcon, BuildingIcon, PinIcon, ServerIcon } from '../shared/icons.tsx';
import {
  CLASS_META,
  destMarkStyle,
  EGRESS_STATUS_META,
  providerMark,
  TRANSPORT_META,
  TRUST_META,
} from './meta.ts';

/**
 * Colored method tag (mono, method-colored). 'SDK' and 'REF' are evidence tags
 * rather than verbs — see HttpMethod in @akasecurity/schema.
 */
const METHOD_TONE: Record<HttpMethod, Tone> = {
  GET: 'low',
  POST: 'ok',
  PUT: 'high',
  DELETE: 'critical',
  SDK: 'ok',
  REF: 'medium',
};
export function MethodTag({ method }: { method: HttpMethod }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 items-center rounded px-1.5 font-mono text-label leading-none font-bold py-0.5',
        TONE_SOFT[METHOD_TONE[method]],
      )}
    >
      {method}
    </span>
  );
}

/**
 * Transport chip. `plain` renders an inline icon+label (insecure transports go
 * red with a "· plaintext" suffix); otherwise a Badge.
 */
export function TransportTag({ transport, plain }: { transport: Transport; plain?: boolean }) {
  const m = TRANSPORT_META[transport];
  const Icon = m.icon;
  if (plain) {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 text-xs font-semibold',
          m.secure ? 'text-text-2' : 'text-sev-critical-ink',
        )}
      >
        <Icon aria-hidden focusable={false} className="size-3" />
        {m.label}
        {!m.secure && ' · plaintext'}
      </span>
    );
  }
  return (
    <Badge variant={m.secure ? 'default' : 'critical'}>
      <Icon aria-hidden focusable={false} className="size-3" />
      {m.label}
    </Badge>
  );
}

/** Data-classification chip. */
export function ClassTag({ cls }: { cls: DataClass }) {
  const m = CLASS_META[cls];
  const Icon = m.icon;
  return (
    <Badge variant={m.tone}>
      <Icon aria-hidden focusable={false} className="size-3" />
      {m.label}
    </Badge>
  );
}

/** Trust-posture chip. */
export function TrustTag({ trust }: { trust: ShareTrustLevel }) {
  const m = TRUST_META[trust];
  const Icon = m.icon;
  return (
    <Badge variant={m.tone}>
      <Icon aria-hidden focusable={false} className="size-3" />
      {m.label}
    </Badge>
  );
}

/**
 * Effective egress state chip. `isCustom` — an override that resolves to a
 * different state than the trust default would — is what separates a decision
 * somebody MADE from a state the destination merely inherited, and that is the
 * question a register full of rows is asked first, so it drives the badge:
 * tinted for an explicit decision, neutral for the default.
 *
 * That distinction is carried by colour alone, so the label also states it in
 * `sr-only` text: "Blocked" read aloud is the same word either way, and the
 * whole value of the column is knowing which rows have been dealt with.
 */
export function StatusTag({ status, isCustom }: { status: EgressStatus; isCustom: boolean }) {
  const m = EGRESS_STATUS_META[status];
  const Icon = m.icon;
  return (
    <Badge variant={isCustom ? m.tone : 'default'}>
      <Icon aria-hidden focusable={false} className="size-3" />
      {m.label}
      <span className="sr-only">{isCustom ? ' — set by an operator' : ' — trust default'}</span>
    </Badge>
  );
}

/**
 * Destination mark: a colored lettermark for known providers (derived from
 * name/host, since the API sends neither), or a tinted icon tile (server /
 * building / pin) for internal domains, external domains and raw IPs. External
 * destinations take the unverified treatment, never internal's.
 */
export function DestMark({
  kind,
  trust,
  name,
  host,
  size = 34,
}: {
  kind: DestinationKind;
  trust: ShareTrustLevel;
  name: string;
  host?: string;
  size?: number;
}) {
  if (kind === 'provider') {
    const { short, color } = providerMark(name, host);
    // Same construction as Provider in shared/Provider.tsx — white lettermark on a
    // fixed hex — so it carries the same per-theme inset ring. This palette has no
    // value sitting on a surface color today; the ring is here so the two tiles
    // cannot drift the next time either list gains a color.
    return (
      <span
        className="inline-flex shrink-0 items-center justify-center rounded-lg font-display font-semibold text-white ring-1 ring-inset ring-mark-edge"
        style={{ width: size, height: size, background: color, fontSize: size * 0.34 }}
      >
        {short}
      </span>
    );
  }
  const iconStyle = { width: size * 0.5, height: size * 0.5 };
  // 'external' is matched on the kind, not only on its 'unverified' trust, so a
  // later trust reclassification cannot silently drop it to the internal mark.
  const mark =
    kind === 'ip' ? (
      <PinIcon aria-hidden focusable={false} style={iconStyle} />
    ) : kind === 'external' || trust === 'unverified' ? (
      <BuildingIcon aria-hidden focusable={false} style={iconStyle} />
    ) : (
      <ServerIcon aria-hidden focusable={false} style={iconStyle} />
    );
  return (
    <span
      className={cn('grid shrink-0 place-items-center rounded-lg', destMarkStyle({ kind, trust }))}
      style={{ width: size, height: size }}
    >
      {mark}
    </span>
  );
}

/** Renders a URL, highlighting `${…}` template segments. */
export function TemplateUrl({ url, big }: { url: string; big?: boolean }) {
  const parts = url.split(/(\$\{[^}]+\})/g);
  return (
    <span className={cn('break-all font-mono', big ? 'text-ui' : 'text-xs')}>
      {parts.map((p, i) =>
        p.startsWith('${') ? (
          <span key={i} className="rounded bg-primary-tint px-1 font-semibold text-primary">
            {p}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </span>
  );
}

/** Small `{ }` "Template" pill shown next to templated endpoint URLs. */
export function TemplatePill() {
  return (
    <Badge variant="default">
      <BracesIcon aria-hidden focusable={false} className="size-2.5" />
      Template
    </Badge>
  );
}
