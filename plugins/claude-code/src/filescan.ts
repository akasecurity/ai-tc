/**
 * Working-tree scan entry — invoked by the /aka:scan slash command:
 *
 *   node scripts/filescan.js [--dir <path>]
 *   node scripts/filescan.js --discover [--root <path>] [--depth <n>]
 *
 * Without flags: scans the current directory (or --dir path).
 * With --discover: scans all git repos found under --root (default: the
 * CURRENT directory — never the home directory implicitly; a machine-wide
 * sweep requires an explicit `--root ~`, and commands/scan.md requires user
 * confirmation first).
 *
 * Rendering lives in @akasecurity/scanner (host-neutral); this entry
 * owns only what is Claude-Code-specific: flag parsing, the /findings hint,
 * and the Markdown code fence.
 * Fail-open: any error prints a friendly note and exits 0 so the command
 * never surfaces a stack trace.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';
import {
  renderMultiRepoSummary,
  renderWorktreeSummary,
  scanAllRepos,
  scanWorktree,
} from '@akasecurity/scanner';

import { fenced } from './present.ts';

interface Flags {
  dir: string | undefined;
  discover: boolean;
  root: string | undefined;
  depth: number | undefined;
}

function valueFlag(argv: string[], flag: string): string | undefined {
  const idx = argv.indexOf(flag);
  let value: string | undefined;
  if (idx !== -1 && argv[idx + 1]) value = argv[idx + 1];
  const prefixed = argv.find((a) => a.startsWith(`${flag}=`));
  if (prefixed) value = prefixed.slice(flag.length + 1);
  return value;
}

function parseFlags(argv: string[]): Flags {
  const dir = valueFlag(argv, '--dir');
  const root = valueFlag(argv, '--root');
  const depthRaw = valueFlag(argv, '--depth');
  const depth = depthRaw !== undefined ? Number.parseInt(depthRaw, 10) : undefined;
  const discover = argv.includes('--discover');
  return {
    dir,
    discover,
    root,
    depth: depth !== undefined && Number.isFinite(depth) && depth > 0 ? depth : undefined,
  };
}

// The follow-up hint is host-specific (a Claude Code slash command), so it is
// injected here rather than baked into the shared renderer.
const FOLLOW_UP = 'Run /findings to review details.';

try {
  const { dir, discover, root, depth } = parseFlags(process.argv.slice(2));
  const cfg = loadConfig();

  if (discover) {
    // Never the home directory implicitly: --discover without --root sweeps
    // the current directory. `--root ~` is the explicit machine-wide opt-in.
    const summary = await scanAllRepos(cfg, {
      sourceTool: 'claude-code',
      searchRoots: [root ?? process.cwd()],
      ...(depth !== undefined ? { maxDepth: depth } : {}),
    });
    process.stdout.write(`${fenced(renderMultiRepoSummary(summary, { followUp: FOLLOW_UP }))}\n`);
  } else {
    const summary = await scanWorktree(cfg, {
      sourceTool: 'claude-code',
      ...(dir !== undefined ? { rootDir: dir } : {}),
    });
    process.stdout.write(`${fenced(renderWorktreeSummary(summary, { followUp: FOLLOW_UP }))}\n`);
  }
} catch {
  process.stdout.write(
    'AKA could not complete the worktree scan. The live hooks will still protect your session.\n',
  );
}

process.exit(0);
