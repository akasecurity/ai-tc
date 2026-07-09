// AI tool/provider lettermarks for dashboard widgets. App domain data (not a
// design-system primitive), so it lives in the dashboard rather than @akasecurity/ui-kit.
export interface ProviderMeta {
  label: string;
  short: string;
  color: string;
}

export const PROVIDERS = {
  claudecode: { label: 'Claude Code', short: 'CC', color: '#C96442' },
  claudedesktop: { label: 'Claude Desktop', short: 'CD', color: '#A8553A' },
  cursor: { label: 'Cursor', short: 'Cu', color: '#252F3D' },
  windsurf: { label: 'Windsurf', short: 'Wf', color: '#0B8F7B' },
  codex: { label: 'Codex CLI', short: 'Cx', color: '#10A37F' },
  copilot: { label: 'GitHub Copilot', short: 'Co', color: '#0581D4' },
  chatgpt: { label: 'ChatGPT', short: 'GP', color: '#0d8f6f' },
  api: { label: 'Anthropic API', short: 'AP', color: '#6058E9' },
} satisfies Record<string, ProviderMeta>;

export type ProviderId = keyof typeof PROVIDERS;

/** Lettermark font size as a fraction of the tile size. */
const FONT_SIZE_RATIO = 0.36;

/** A colored square lettermark for an AI provider. */
export function Provider({ id, size = 24 }: { id: ProviderId; size?: number }) {
  const p = PROVIDERS[id];
  return (
    <span
      className="flex shrink-0 items-center justify-center rounded-lg font-display font-bold text-white"
      style={{ width: size, height: size, background: p.color, fontSize: size * FONT_SIZE_RATIO }}
    >
      {p.short}
    </span>
  );
}
