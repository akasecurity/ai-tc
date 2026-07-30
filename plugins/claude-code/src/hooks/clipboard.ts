/**
 * Best-effort clipboard write for the prompt-block resubmit flow. The text
 * handed here is already pointerized — never a raw secret — and the return
 * value only flips a sentence in the resubmit message, so every failure mode
 * (no platform utility, spawn error, non-zero exit) is a plain `false`, never
 * a throw.
 *
 * The text travels on the child's stdin with every stdio stream piped —
 * nothing is ever inherited, so the written text cannot land in the hook's own
 * output streams or argv (argv is visible in the process table).
 */
import { spawnSync } from 'node:child_process';

// One clipboard utility invocation: the command, its argv, and the text to
// deliver on stdin. Injectable so tests observe exactly what would be spawned
// (and with what text) without touching a real clipboard.
export type ClipboardSpawner = (cmd: string, args: string[], input: string) => { ok: boolean };

const defaultSpawner: ClipboardSpawner = (cmd, args, input) => {
  try {
    const result = spawnSync(cmd, args, {
      input,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 3_000,
    });
    return { ok: result.error === undefined && result.status === 0 };
  } catch {
    return { ok: false };
  }
};

interface ClipboardCommand {
  readonly cmd: string;
  readonly args: readonly string[];
}

// Wayland first, then the two X11 utilities. A missing utility surfaces as a
// failed spawn, which simply moves on to the next candidate.
const LINUX_COMMANDS: readonly ClipboardCommand[] = [
  { cmd: 'wl-copy', args: [] },
  { cmd: 'xclip', args: ['-selection', 'clipboard'] },
  { cmd: 'xsel', args: ['--clipboard', '--input'] },
];

function commandsFor(platform: NodeJS.Platform): readonly ClipboardCommand[] {
  if (platform === 'darwin') return [{ cmd: 'pbcopy', args: [] }];
  if (platform === 'win32') return [{ cmd: 'clip', args: [] }];
  if (platform === 'linux') return LINUX_COMMANDS;
  return [];
}

/**
 * Write `text` to the system clipboard. Returns whether a clipboard utility
 * accepted the write; on an unrecognized platform, a missing utility, or any
 * spawn failure it returns `false` without throwing.
 */
export function writeClipboard(
  text: string,
  opts?: { platform?: NodeJS.Platform; spawn?: ClipboardSpawner },
): boolean {
  try {
    const platform = opts?.platform ?? process.platform;
    const spawn = opts?.spawn ?? defaultSpawner;
    for (const command of commandsFor(platform)) {
      if (spawn(command.cmd, [...command.args], text).ok) return true;
    }
    return false;
  } catch {
    return false;
  }
}
