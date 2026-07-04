// Small shared presentational atoms for the Data Shares views: destination
// marks, method/transport/class/trust chips and template-URL rendering. Pure
// (no state/events) so they render in any host app.
import type {
  DataClass,
  DestinationKind,
  HttpMethod,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';
import { Badge, cn } from '@akasecurity/ui-kit';

import { BracesIcon, BuildingIcon, PinIcon, ServerIcon } from '../shared/icons.tsx';
import { CLASS_META, destMarkStyle, providerMark, TRANSPORT_META, TRUST_META } from './meta.ts';

/** Colored HTTP-method tag (mono, method-colored). */
const METHOD_TONE: Record<HttpMethod, string> = {
  GET: 'bg-sev-low-fill text-sev-low',
  POST: 'bg-ok-fill text-ok',
  PUT: 'bg-sev-high-fill text-sev-high',
  DELETE: 'bg-sev-critical-fill text-sev-critical',
};
export function MethodTag({ method }: { method: HttpMethod }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 items-center rounded px-1.5 font-mono text-label leading-none font-bold py-0.5',
        METHOD_TONE[method],
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
          m.secure ? 'text-text-2' : 'text-sev-critical',
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
 * Destination mark: a colored lettermark for known providers (derived from
 * name/host, since the API sends neither), or a tinted icon tile (server /
 * building / pin) for internal domains and raw IPs.
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
    return (
      <span
        className="inline-flex shrink-0 items-center justify-center rounded-lg font-display font-semibold text-white"
        style={{ width: size, height: size, background: color, fontSize: size * 0.34 }}
      >
        {short}
      </span>
    );
  }
  const iconStyle = { width: size * 0.5, height: size * 0.5 };
  const mark =
    kind === 'ip' ? (
      <PinIcon aria-hidden focusable={false} style={iconStyle} />
    ) : trust === 'unverified' ? (
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
