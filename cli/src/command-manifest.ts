// The single source of truth for the CLI's command surface. `cli.ts` (dispatch +
// USAGE), `commands/completion.ts` (the tab-completion scripts) and the tests all
// derive from this list, so a new command auto-appears in the help text AND in
// completion — no more hand-synced copies drifting apart (which is how the
// `completion` command itself first shipped missing from its own completion).

export interface CommandSpec {
  name: string;
  // Shown in the USAGE help and as the zsh `_describe` description.
  summary: string;
  // A positional hint rendered after the name in USAGE, e.g. '[path]', '<url>'.
  argHint?: string;
  // Fixed second-level values to complete (subcommands / verbs / views).
  args?: readonly string[];
  // Completes a filesystem path at the first argument (only `scan` today).
  completesFiles?: boolean;
}

export const COMMAND_SPECS: readonly CommandSpec[] = [
  { name: 'init', summary: 'Scaffold ~/.aka (settings + local database)' },
  {
    name: 'scan',
    argHint: '[path]',
    summary: 'Scan a file or directory and record findings (default: .)',
    completesFiles: true,
  },
  { name: 'stats', summary: 'Print findings / enforcement / detections from the local store' },
  {
    name: 'detections',
    argHint: '[update]',
    summary: 'List installed detection packs + available updates (updates are manual)',
    args: ['update'],
  },
  {
    name: 'plugins',
    summary: 'List / install agent plugins (the CLI is an optional hub)',
    args: ['list', 'install'],
  },
  { name: 'dashboard', summary: 'Launch the local web dashboard and open it in the browser' },
  {
    name: 'exception',
    summary: 'Manage detection exceptions (approve, add, list, show, revoke, rotate-key)',
    args: ['approve', 'add', 'list', 'show', 'revoke', 'rotate-key'],
  },
  {
    name: 'tui',
    argHint: '[view]',
    summary: 'Interactive colour dashboard — health|findings|recommend|audit (needs a TTY)',
    args: ['health', 'findings', 'recommend', 'audit'],
  },
  {
    name: 'check-updates',
    summary: 'Show which components (CLI + plugins) have updates available',
  },
  {
    name: 'update',
    argHint: '[what]',
    summary: 'Update the CLI and/or plugins (what: cli | <plugin-id> | all)',
    args: ['cli', 'all'],
  },
  {
    name: 'completion',
    argHint: '<sh>',
    summary: 'Emit a shell completion script (sh: zsh | bash)',
    args: ['zsh', 'bash'],
  },
];

// Global flags honoured for every command.
export const GLOBAL_FLAGS = ['--home', '--no-update-check', '--version', '--help'] as const;

// The `Commands:` block of the help text, generated from the specs so it can never
// drift from them. Name + hint left-padded to a shared column, then the summary —
// preserving the existing two-space indent + aligned layout.
export function commandsHelp(): string {
  const label = (s: CommandSpec): string => (s.argHint ? `${s.name} ${s.argHint}` : s.name);
  const width = Math.max(...COMMAND_SPECS.map((s) => label(s).length)) + 1;
  return COMMAND_SPECS.map((s) => `  ${label(s).padEnd(width)}${s.summary}`).join('\n');
}
