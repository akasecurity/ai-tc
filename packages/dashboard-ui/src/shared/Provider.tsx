// AI tool/provider lettermarks for dashboard widgets. App domain data (not a
// design-system primitive), so it lives in the dashboard rather than @akasecurity/ui-kit.
import type { Harness } from '@akasecurity/schema';

export interface ProviderMeta {
  label: string;
  short: string;
  color: string;
}

// Keyed off the canonical @akasecurity/schema `Harness` vocabulary — `satisfies
// Record<Harness, …>` makes a harness added there (or dropped) a compile error
// here, rather than a silently stale lettermark.
export const PROVIDERS = {
  claudecode: { label: 'Claude Code', short: 'CC', color: '#C96442' },
  claudedesktop: { label: 'Claude Desktop', short: 'CD', color: '#A8553A' },
  cursor: { label: 'Cursor', short: 'Cu', color: '#252F3D' },
  windsurf: { label: 'Windsurf', short: 'Wf', color: '#0B8F7B' },
  codex: { label: 'Codex CLI', short: 'Cx', color: '#10A37F' },
  antigravity: { label: 'Antigravity', short: 'Ag', color: '#4285F4' },
  copilot: { label: 'GitHub Copilot', short: 'Co', color: '#0581D4' },
  chatgpt: { label: 'ChatGPT', short: 'GP', color: '#0d8f6f' },
  claudeai: { label: 'Claude.ai', short: 'Ca', color: '#D97757' },
  api: { label: 'Anthropic API', short: 'AP', color: '#6058E9' },
} satisfies Record<Harness, ProviderMeta>;

export type ProviderId = Harness;

/** Lettermark font size as a fraction of the tile size. */
const FONT_SIZE_RATIO = 0.36;

/** A colored square lettermark for an AI provider. */
export function Provider({ id, size = 24 }: { id: ProviderId; size?: number }) {
  const p = PROVIDERS[id];
  // Vendor brand colors are fixed, so some land close to the surface they sit on
  // (Cursor's IS the dark theme's card color). --color-mark-edge is a per-theme inset
  // ring that keeps the tile's edge visible either way without altering the brand
  // fill. DestMark in data-shares/atoms.tsx is the same tile and carries the same ring.
  return (
    <span
      className="flex shrink-0 items-center justify-center rounded-lg font-display font-bold text-white ring-1 ring-inset ring-mark-edge"
      style={{ width: size, height: size, background: p.color, fontSize: size * FONT_SIZE_RATIO }}
    >
      {p.short}
    </span>
  );
}
