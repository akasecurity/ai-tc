'use client';

// Right pane for one skill / MCP server / hook / config file: status, description,
// the type's own detail fields, the MCP trust classifier and exposed tools, and
// per-type actions. The per-type action buttons are visual affordances only.
import type {
  AssetDetail as AssetDetailShape,
  AssetType,
  AssetVariant,
  McpTool,
  TrustLevel,
} from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';
import { type ReactNode, useId, useState } from 'react';

import { BackButton, FlagChips, RadioCardList, Section, TrustPill } from './chips.tsx';
import {
  assetTile,
  endpointsText,
  FLAG,
  fmtDateTime,
  inlineLabel,
  metaText,
  TRUST,
  TRUST_ORDER,
  typeMeta,
} from './data.ts';
import { Ico } from './Ico.tsx';
import { type IconName } from './icons.ts';

type AssetKind = Exclude<AssetType, 'project'>;

/** The labelled `meta` fields each type shows, in order. */
const DETAIL_FIELDS: Record<AssetKind, [key: string, label: string][]> = {
  skill: [
    ['source', 'Source'],
    ['scope', 'Scope'],
    ['installedVersion', 'Installed'],
    ['latestVersion', 'Latest'],
    ['updatedAt', 'Updated'],
    ['pluginName', 'Plugin'],
  ],
  mcp: [
    ['transport', 'Transport'],
    ['url', 'URL'],
    ['command', 'Command'],
    ['scope', 'Scope'],
    ['envKeys', 'Environment keys'],
    ['pluginName', 'Plugin'],
    ['marketplace', 'Marketplace'],
    ['project', 'Project'],
  ],
  hook: [
    ['event', 'Event'],
    ['matcher', 'Matcher'],
    ['scope', 'Scope'],
    ['status', 'State'],
    ['pluginName', 'Plugin'],
  ],
  config: [
    ['kind', 'Kind'],
    ['scope', 'Scope'],
    ['path', 'Path'],
    ['entryCount', 'Entries'],
    ['updatedAt', 'Changed'],
  ],
};

/** `meta` keys a type renders outside the details grid (code block, description). */
const SHOWN_ELSEWHERE: Record<AssetKind, string[]> = {
  skill: [],
  mcp: [],
  hook: ['command', 'warnings'],
  config: ['detail'],
};

const DATE_KEYS = new Set(['updatedAt']);

/** "entryCount" → "Entry count". */
function humanize(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function detailFields(
  asset: AssetDetailShape,
  locale: string,
): [key: string, label: string, value: string][] {
  const known = asset.type === 'project' ? [] : DETAIL_FIELDS[asset.type];
  const elsewhere = asset.type === 'project' ? [] : SHOWN_ELSEWHERE[asset.type];
  const skip = new Set([...known.map(([k]) => k), ...elsewhere]);
  const format = (key: string): string | null => {
    const text = metaText(asset.meta, key);
    if (text === null || !DATE_KEYS.has(key) || Number.isNaN(Date.parse(text))) return text;
    return fmtDateTime(text, locale);
  };
  const out: [string, string, string][] = [];
  for (const [key, label] of known) {
    const value = format(key);
    if (value !== null) out.push([key, label, value]);
  }
  for (const key of Object.keys(asset.meta)) {
    if (skip.has(key)) continue;
    const value = format(key);
    if (value !== null) out.push([key, humanize(key), value]);
  }
  return out;
}

export function AssetDetail({
  asset,
  onTrust,
  onBack,
  backLabel,
  locale,
  trustRefusal,
}: {
  asset: AssetDetailShape;
  onTrust: (v: TrustLevel) => void;
  /** Returns to the table this asset was opened from. */
  onBack: () => void;
  /** What the back button returns to, e.g. "Claude Code" or "Skills". */
  backLabel: string;
  /** The locale dates are formatted in. */
  locale: string;
  /**
   * Set when the MCP trust control cannot be operated by the host: the picker
   * renders offered-and-disabled with this text as the reason, and `onTrust` is
   * never called. Only an MCP asset has a trust picker.
   */
  trustRefusal?: string | undefined;
}) {
  const isMcp = asset.type === 'mcp';
  const trust = asset.trust; // null for non-MCP assets
  const tile = assetTile(asset.type);
  const trustReasonId = useId();
  const command = asset.type === 'hook' ? metaText(asset.meta, 'command') : null;
  const fields = detailFields(asset, locale);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-3 border-b border-border px-5 py-3.5">
        <BackButton onBack={onBack} backLabel={backLabel} />
        <span
          className={cn('grid size-10 shrink-0 place-items-center rounded-lg', tile.bg, tile.fg)}
        >
          <Ico name={tile.icon} className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-base font-semibold text-text" title={asset.name}>
            {asset.name}
          </div>
          <div className="mt-px text-xs text-text-3">{typeMeta(asset.type).one}</div>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto p-5">
        <div className="flex flex-wrap items-center gap-2">
          {isMcp && trust && <TrustPill value={trust} />}
          {(asset.flags.length > 0 || !isMcp) && <FlagChips flags={asset.flags} />}
          {asset.machines !== undefined && (
            <span className="text-xs text-text-2">{`Seen on ${endpointsText(asset.machines, false)}`}</span>
          )}
        </div>

        {asset.description && (
          <div className="max-w-prose text-sm leading-relaxed text-text-2">{asset.description}</div>
        )}

        {command && (
          <pre className="whitespace-pre-wrap break-all rounded-lg border border-border bg-surface-2 px-3.5 py-3 font-mono text-xs leading-relaxed text-text">
            {command}
          </pre>
        )}

        {fields.length > 0 && (
          <Section label="Details">
            <dl className="grid grid-cols-[repeat(auto-fit,minmax(14rem,1fr))] gap-x-6 gap-y-4">
              {fields.map(([key, label, value]) => (
                <div key={key}>
                  <dt className="mb-1 text-label font-semibold uppercase tracking-wider text-text-3">
                    {label}
                  </dt>
                  <dd className="wrap-break-word font-mono text-xs font-medium text-text">
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
          </Section>
        )}

        {asset.seenOn !== undefined && asset.seenOn.length > 1 && (
          <VersionsSection asset={asset} variants={asset.seenOn} />
        )}

        {isMcp && trust && (
          <Section label="Trust classification">
            <RadioCardList
              order={TRUST_ORDER}
              meta={TRUST}
              value={trust}
              onChange={onTrust}
              accentOf={(t) => t.iconBg}
              refusal={
                trustRefusal === undefined ? undefined : { id: trustReasonId, reason: trustRefusal }
              }
            />
          </Section>
        )}

        {asset.finding && (
          <Section label="Related finding">
            <div className="flex w-full items-center gap-2.5 rounded-lg border border-border bg-sev-critical-fill px-3 py-2.5">
              <Ico name="alert" className="size-4 shrink-0 text-sev-critical-ink" />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-text">{asset.finding.title}</div>
                {asset.finding.note && (
                  <div className="mt-0.5 font-mono text-xs text-text-3">{asset.finding.note}</div>
                )}
              </div>
            </div>
          </Section>
        )}

        {isMcp && asset.tools && (
          <ToolsSection tools={asset.tools} blocked={trust === 'unapproved'} />
        )}

        <div className="flex flex-wrap gap-2">{actionsFor(asset, trust)}</div>
      </div>
    </div>
  );
}

/**
 * The fields whose value differs between the variants, each with the value
 * every variant holds. A field every variant agrees on says nothing about how
 * they differ, and a date is when one endpoint last changed its copy.
 */
function distinguishingFields(
  type: AssetKind,
  variants: AssetVariant[],
): { key: string; label: string; values: (string | null)[] }[] {
  const labels = new Map(DETAIL_FIELDS[type]);
  const metaKeys = [...new Set(variants.flatMap((v) => Object.keys(v.meta)))].filter(
    (key) => !DATE_KEYS.has(key),
  );
  const candidates: [key: string, label: string, read: (v: AssetVariant) => string | null][] = [
    ['sub', 'Summary', (v) => v.sub || null],
    ['description', 'Description', (v) => v.description],
    ['flags', 'Flags', (v) => v.flags.map((f) => FLAG[f].label).join(', ') || null],
    ...metaKeys.map((key): [string, string, (v: AssetVariant) => string | null] => [
      `meta:${key}`,
      labels.get(key) ?? humanize(key),
      (v) => metaText(v.meta, key),
    ]),
  ];
  return candidates.flatMap(([key, label, read]) => {
    const values = variants.map(read);
    return new Set(values.map((v) => v ?? '')).size > 1 ? [{ key, label, values }] : [];
  });
}

function hostsText(variant: AssetVariant): string | null {
  const hosts = variant.hosts ?? [];
  if (hosts.length === 0) return null;
  const more = variant.machines - hosts.length;
  return more > 0 ? `${hosts.join(', ')} and ${String(more)} more` : hosts.join(', ');
}

function VersionsSection({
  asset,
  variants,
}: {
  asset: AssetDetailShape;
  variants: AssetVariant[];
}) {
  const kind = asset.type === 'project' ? null : asset.type;
  const fields = kind === null ? [] : distinguishingFields(kind, variants);
  return (
    <Section label="Versions reported">
      <div className="mb-2 text-xs text-text-3">
        {`Endpoints report this ${inlineLabel(typeMeta(asset.type).one)} in ${String(variants.length)} different versions.`}
      </div>
      <ul className="flex flex-col gap-2">
        {variants.map((variant, i) => {
          const hosts = hostsText(variant);
          return (
            <li
              key={JSON.stringify([variant.sub, variant.description, variant.flags, variant.meta])}
              className="rounded-lg border border-border px-3.5 py-3"
            >
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="text-sm font-semibold text-text">
                  {endpointsText(variant.machines, false)}
                </span>
                {hosts !== null && <span className="text-xs text-text-3">{hosts}</span>}
              </div>
              {fields.length > 0 && (
                <dl className="mt-2 grid grid-cols-[repeat(auto-fit,minmax(14rem,1fr))] gap-x-6 gap-y-2">
                  {fields.map((f) => (
                    <div key={f.key}>
                      <dt className="mb-0.5 text-label font-semibold uppercase tracking-wider text-text-3">
                        {f.label}
                      </dt>
                      <dd className="wrap-break-word font-mono text-xs text-text">
                        {f.values[i] ?? '—'}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
            </li>
          );
        })}
      </ul>
    </Section>
  );
}

function ToolsSection({ tools, blocked }: { tools: McpTool[]; blocked: boolean }) {
  const [open, setOpen] = useState(false);
  const shown = open ? tools : tools.slice(0, 4);
  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-label font-semibold uppercase tracking-wider text-text-3">
          Exposed tools
        </span>
        <span className="text-xs font-semibold text-text-3">{tools.length}</span>
        {blocked && (
          <span className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-sev-critical-ink">
            <Ico name="slash-circle" className="size-3" /> Calls blocked
          </span>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        {shown.map((t) => (
          <div
            key={t.name}
            className={cn(
              'flex items-start gap-2.5 rounded-lg border px-3 py-2.5',
              t.risk ? 'border-sev-high-fill bg-sev-high-fill' : 'border-border bg-surface',
              blocked && 'opacity-70',
            )}
          >
            <span
              className={cn(
                'mt-px grid size-5.5 shrink-0 place-items-center rounded-md',
                t.risk
                  ? 'bg-sev-high-ink text-on-accent'
                  : t.write
                    ? 'bg-surface-2 text-text-2'
                    : 'bg-teal-fill text-teal-ink',
              )}
            >
              <Ico name={t.risk ? 'alert' : t.write ? 'edit' : 'eye'} className="size-3" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-1.5">
                <span className="font-mono text-xs font-semibold text-text">{t.name}</span>
                <span className="font-mono text-xs text-text-3">{t.signature}</span>
                {t.write && !t.risk && (
                  <span className="rounded-full bg-surface-2 px-2 py-px text-xs font-semibold text-text-2">
                    write
                  </span>
                )}
              </div>
              <div className="mt-0.5 text-xs leading-relaxed text-text-2">{t.description}</div>
              {t.risk && (
                <div className="mt-1 flex items-center gap-1.5 text-xs font-semibold text-sev-high-ink">
                  <Ico name="alert" className="size-3" /> {t.risk}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
      {tools.length > 4 && (
        <Button
          variant="ghost"
          tone="primary"
          size="sm"
          className="mt-2 px-0"
          onClick={() => {
            setOpen(!open);
          }}
        >
          <Ico
            name="chevron-down"
            className={cn('size-3.5 transition-transform', open && 'rotate-180')}
          />
          {open ? 'Show fewer' : `Show all ${String(tools.length)} tools`}
        </Button>
      )}
    </div>
  );
}

interface Action {
  key: string;
  primary?: boolean;
  icon: IconName;
  label: string;
}
function actionsFor(asset: AssetDetailShape, trust: TrustLevel | null): ReactNode {
  let actions: Action[];
  if (asset.type === 'skill') {
    const latest = metaText(asset.meta, 'latestVersion') ?? '';
    actions = asset.flags.includes('update')
      ? [
          { key: 'u', primary: true, icon: 'arrow-up', label: `Update to ${latest}`.trim() },
          { key: 'c', icon: 'book', label: 'Changelog' },
        ]
      : [{ key: 'r', icon: 'refresh', label: 'Check for updates' }];
  } else if (asset.type === 'mcp') {
    actions =
      trust === 'unapproved'
        ? [
            { key: 'a', primary: true, icon: 'shield-check', label: 'Approve & allow-list' },
            { key: 'b', icon: 'slash-circle', label: 'Block server' },
          ]
        : [
            { key: 'v', icon: 'eye', label: 'View tools' },
            { key: 'r', icon: 'refresh', label: 'Re-verify' },
          ];
  } else if (asset.type === 'hook') {
    if (asset.flags.includes('conflict'))
      actions = [
        { key: 'r', primary: true, icon: 'branch', label: 'Resolve run order' },
        { key: 'd', icon: 'eye-off', label: 'Disable hook' },
      ];
    else if (asset.flags.includes('unknown'))
      actions = [
        { key: 'v', primary: true, icon: 'shield-check', label: 'Review & verify' },
        { key: 'b', icon: 'slash-circle', label: 'Block' },
      ];
    else actions = [{ key: 'v', icon: 'eye', label: 'View script' }];
  } else {
    if (asset.flags.includes('risk'))
      actions = [
        { key: 'r', primary: true, icon: 'shield-check', label: 'Review change' },
        { key: 'd', icon: 'swap', label: 'View diff' },
      ];
    else if (asset.flags.length)
      actions = [
        { key: 'd', icon: 'swap', label: 'View diff' },
        { key: 'm', icon: 'check', label: 'Mark reviewed' },
      ];
    else actions = [{ key: 'o', icon: 'eye', label: 'Open file' }];
  }
  return actions.map((a) => (
    <Button
      key={a.key}
      variant={a.primary ? 'solid' : 'outline'}
      tone={a.primary ? 'primary' : 'neutral'}
      size="sm"
    >
      <Ico name={a.icon} className="size-3.5" />
      {a.label}
    </Button>
  ));
}
