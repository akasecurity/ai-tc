import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { runCapture } from './exec.ts';
import { reinvokeArgv } from './self-exec.ts';

// `triggerHistorySync` (@akasecurity/plugin-runtime) drains the outbox from
// SessionStart, throttled to once per five minutes — but only a HOST opening
// a session ever calls it. A machine that stays attached without one, or
// whose sessions are all short, never drains. This installs a per-user
// scheduler that periodically re-invokes `aka sync-history --run` on its own,
// so delivery does not depend on a session ever reopening.
//
// MACOS ONLY, today. The credential `aka attach` writes is per-user-home-scoped
// (~/.aka/settings/control-plane-credential.json, 0600 — see
// @akasecurity/persistence's control-plane-credential.ts), so the right
// primitive on every platform is a PER-USER one: a LaunchAgent here, a
// per-user Scheduled Task on Windows, a `systemd --user` timer on Linux. Only
// the first exists so far; the other two stay a deliberate no-op rather than
// guess at a shape nobody has built and tested.

export const BACKGROUND_SYNC_LABEL = 'com.akasecurity.aka.background-sync';

// Coarser than plugin-runtime's HISTORY_SYNC_THROTTLE_MS (5 min) on purpose:
// this path exists for when nothing else is running the drain, not to compete
// with a session that already is.
export const BACKGROUND_SYNC_INTERVAL_SECONDS = 30 * 60;

export interface BackgroundScheduleDeps {
  platform?: NodeJS.Platform;
  homeDir?: () => string;
  reinvoke?: (
    subcommand: string,
    extraArgs?: string[],
  ) => { command: string; args: string[] } | null;
  readFile?: (path: string) => string | null;
  writeFile?: (path: string, data: string) => void;
  mkdir?: (dir: string) => void;
  removeFile?: (path: string) => void;
  runLaunchctl?: (args: string[]) => boolean;
}

function launchAgentsDir(deps: BackgroundScheduleDeps): string {
  return join((deps.homeDir ?? homedir)(), 'Library', 'LaunchAgents');
}

function plistPath(deps: BackgroundScheduleDeps): string {
  return join(launchAgentsDir(deps), `${BACKGROUND_SYNC_LABEL}.plist`);
}

function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

// Exported so the test that pins the plist SHAPE and the code that writes it
// read the same string, rather than a second hand-typed copy drifting from it.
export function renderPlist(programArguments: readonly string[]): string {
  const args = programArguments.map((a) => `    <string>${escapeXml(a)}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${BACKGROUND_SYNC_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>
  <key>StartInterval</key>
  <integer>${String(BACKGROUND_SYNC_INTERVAL_SECONDS)}</integer>
  <key>RunAtLoad</key>
  <false/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
`;
}

function defaultReadFile(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

function defaultRunLaunchctl(args: string[]): boolean {
  return runCapture('launchctl', args).ok;
}

// `process.getuid` is POSIX-only and typed as optional on a Windows-inclusive
// lib target. Both callers are already gated to darwin before this runs, so
// the fallback below is unreachable in practice — kept rather than asserted
// away, since this whole module is best-effort and a launchctl call built
// from a wrong-but-well-formed domain fails no worse than one never made.
function guiDomain(): string {
  const getuid = (process as { getuid?: () => number }).getuid;
  return `gui/${String(typeof getuid === 'function' ? getuid() : 0)}`;
}

/**
 * Install (or refresh) the LaunchAgent, best-effort. Called from `aka attach`
 * once the attachment itself has been written successfully — this never
 * blocks or fails the attach, and a machine it cannot reach still has
 * SessionStart's own drain.
 *
 * IDEMPOTENT: a plist byte-identical to what would be written is left alone
 * and launchctl is not re-invoked, so a routine re-attach to the same
 * deployment (rotating a key) costs nothing extra. A plist that differs — the
 * binary moved, `--home` changed — is rewritten and the running job is
 * bounced so it picks up the new ProgramArguments; launchctl does not reload
 * a loaded job's argv from a plist it was never told changed.
 */
export function installBackgroundSync(base: string, deps: BackgroundScheduleDeps = {}): void {
  try {
    if ((deps.platform ?? process.platform) !== 'darwin') return;
    const reinvoke = (deps.reinvoke ?? reinvokeArgv)('sync-history', ['--run', '--home', base]);
    // Plain-node with no resolvable entry script (see self-exec.ts) — nothing
    // to schedule a re-invocation of.
    if (reinvoke === null) return;

    const content = renderPlist([reinvoke.command, ...reinvoke.args]);
    const path = plistPath(deps);
    if ((deps.readFile ?? defaultReadFile)(path) === content) return;

    (
      deps.mkdir ??
      ((dir: string) => {
        mkdirSync(dir, { recursive: true });
      })
    )(launchAgentsDir(deps));
    (
      deps.writeFile ??
      ((p: string, data: string) => {
        writeFileSync(p, data);
      })
    )(path, content);

    const domain = guiDomain();
    const launchctl = deps.runLaunchctl ?? defaultRunLaunchctl;
    // Unconditional bootout before bootstrap, ignoring its result: the first
    // install has nothing loaded (a harmless no-op refusal), and a refresh
    // must replace an already-loaded job rather than leave it running under
    // its old argv.
    launchctl(['bootout', `${domain}/${BACKGROUND_SYNC_LABEL}`]);
    launchctl(['bootstrap', domain, path]);
  } catch {
    // Best-effort — see the doc comment above.
  }
}

/**
 * Remove the LaunchAgent, best-effort. Called from `aka detach` alongside
 * every other piece of attachment-derived state (see
 * `clearAttachmentDerivedState`) — this is not one of the files it removes,
 * since a LaunchAgent plist does not live under the AKA data dir it sweeps.
 */
export function uninstallBackgroundSync(deps: BackgroundScheduleDeps = {}): void {
  try {
    if ((deps.platform ?? process.platform) !== 'darwin') return;
    (deps.runLaunchctl ?? defaultRunLaunchctl)([
      'bootout',
      `${guiDomain()}/${BACKGROUND_SYNC_LABEL}`,
    ]);
    (
      deps.removeFile ??
      ((p: string) => {
        rmSync(p, { force: true });
      })
    )(plistPath(deps));
  } catch {
    // Best-effort — see installBackgroundSync.
  }
}
