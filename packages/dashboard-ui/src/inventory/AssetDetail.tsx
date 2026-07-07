'use client';

// Right pane shown when a non-project asset (skill / MCP server / hook / config)
// is selected: status chips, description, MCP trust classifier + exposed tools,
// related finding, metadata grid and context-specific actions. Backed by
// GET /v1/inventory/assets/:assetId; the trust classifier writes back through
// PUT .../trust. The per-type action buttons are visual affordances only —
// no update/approve/disable operations exist.
import type {
  AssetDetail as AssetDetailShape,
  AssetType,
  McpTool,
  TrustLevel,
} from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';
import { type ReactNode, useState } from 'react';

import { FlagChips, RadioCardList, Section, TrustPill } from './chips.tsx';
import { assetTile, TRUST, TRUST_ORDER } from './data.ts';
import { Ico } from './Ico.tsx';
import { type IconName } from './icons.ts';

const TYPE_LABEL: Record<Exclude<AssetType, 'project'>, string> = {
  skill: 'Skill',
  mcp: 'MCP server',
  hook: 'Hook',
  config: 'Configuration file',
};

export function AssetDetail({
  asset,
  onTrust,
  onClose,
}: {
  asset: AssetDetailShape;
  onTrust: (v: TrustLevel) => void;
  // Present only when the asset was opened from a harness — closes back to that
  // harness's overview. Omitted in the by-type view, where there's no harness.
  onClose?: (() => void) | undefined;
}) {
  const isMcp = asset.type === 'mcp';
  const trust = asset.trust; // null for non-MCP assets
  const tile = assetTile(asset.type);
  const typeLabel = TYPE_LABEL[asset.type as Exclude<AssetType, 'project'>];

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* header */}
      <div className="flex items-center gap-3 border-b border-border px-5 py-3.5">
        <span
          className={cn('grid size-8.5 shrink-0 place-items-center rounded-lg', tile.bg, tile.fg)}
        >
          <Ico name={tile.icon} className="size-4.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-sm font-semibold text-text">{asset.name}</div>
          <div className="mt-px text-xs text-text-3">{typeLabel}</div>
        </div>
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

      {/* body */}
      <div className="flex min-h-0 flex-1 flex-col gap-4.5 overflow-y-auto p-5">
        <div className="flex flex-wrap items-center gap-2">
          {isMcp && trust && <TrustPill value={trust} />}
          <FlagChips flags={asset.flags} />
        </div>

        {asset.description && (
          <div className="text-sm leading-relaxed text-text-2">{asset.description}</div>
        )}

        {isMcp && trust && (
          <Section label="Trust classification">
            <RadioCardList
              order={TRUST_ORDER}
              meta={TRUST}
              value={trust}
              onChange={onTrust}
              accentOf={(t) => t.iconBg}
            />
          </Section>
        )}

        {asset.finding && (
          <Section label="Related finding">
            <button
              type="button"
              className="flex w-full items-center gap-2.5 rounded-lg border border-border bg-sev-critical-fill px-3 py-2.5 text-left"
            >
              <Ico name="alert" className="size-4 shrink-0 text-sev-critical" />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-text">{asset.finding.title}</div>
                {asset.finding.note && (
                  <div className="mt-0.5 font-mono text-xs text-text-3">{asset.finding.note}</div>
                )}
              </div>
              <Ico name="chevron-right" className="size-4 shrink-0 text-text-3" />
            </button>
          </Section>
        )}

        <Section label="Details">
          <div className="grid grid-cols-2 gap-x-4 gap-y-3.5">
            {Object.entries(asset.meta).map(([k, v]) => (
              <div key={k}>
                <div className="mb-1 text-label font-semibold uppercase tracking-wider text-text-3">
                  {k}
                </div>
                <div className="wrap-break-word font-mono text-xs font-medium">{String(v)}</div>
              </div>
            ))}
          </div>
        </Section>

        {isMcp && asset.tools && (
          <ToolsSection tools={asset.tools} blocked={trust === 'unapproved'} />
        )}

        <div className="flex flex-wrap gap-2">{actionsFor(asset, trust)}</div>
      </div>
    </div>
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
          <span className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-sev-critical">
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
                  ? 'bg-sev-high text-white'
                  : t.write
                    ? 'bg-surface-2 text-text-2'
                    : 'bg-teal-fill text-teal',
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
                <div className="mt-1 flex items-center gap-1.5 text-xs font-semibold text-sev-high">
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
    const latest = typeof asset.meta.Latest === 'string' ? asset.meta.Latest : '';
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
