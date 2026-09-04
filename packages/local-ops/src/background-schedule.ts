import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { posix } from 'node:path';

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
  // POSIX always, not the host's native separator: every caller here is
  // already gated to a real macOS host by the darwin check in the two
  // exported functions, so the path this builds is a POSIX path regardless
  // of which OS the TEST SUITE happens to run on.
  return posix.join((deps.homeDir ?? homedir)(), 'Library', 'LaunchAgents');
}

/**
 * The launchd label for a given AKA home — and therefore the plist's
 * filename, and the target of every `bootout`/`bootstrap` call against it.
 *
 * `launchAgentsDir` cannot vary by `base`: launchd loads a LaunchAgent only
 * from the REAL user's `~/Library/LaunchAgents`, which every `--home` shares.
 * So the path alone cannot give a non-default home its own slot the way it
 * does for every other AKA artifact — a machine attached against the real
 * `~/.aka` and then again against `--home /tmp/scratch` would otherwise write
 * both plists to the same file, bouncing the first job and, on detach,
 * booting out and deleting the LaunchAgent for whichever home did not ask.
 * The label carries that distinction instead, suffixed with a short hash of
 * `base` so two homes never collide.
 */
export function backgroundSyncLabel(base: string): string {
  return `${BACKGROUND_SYNC_LABEL}.${createHash('sha256').update(base).digest('hex').slice(0, 12)}`;
}

function plistPath(base: string, deps: BackgroundScheduleDeps): string {
  return posix.join(launchAgentsDir(deps), `${backgroundSyncLabel(base)}.plist`);
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
export function renderPlist(label: string, programArguments: readonly string[]): string {
  const args = programArguments.map((a) => `    <string>${escapeXml(a)}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${escapeXml(label)}</string>
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

    const label = backgroundSyncLabel(base);
    const content = renderPlist(label, [reinvoke.command, ...reinvoke.args]);
    const path = plistPath(base, deps);
    // Content-based idempotency: a plist byte-identical to what would be
    // written is left alone and launchctl is not re-invoked. This can only
    // see the FILE, not whether launchd still has the job loaded — a job
    // unloaded out from under an unchanged plist (`launchctl bootout` run by
    // hand, or any future path that unloads without removing the file) is not
    // re-bootstrapped by a later re-attach until something else changes the
    // plist. Self-healing at next login, when launchd re-reads the directory.
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
    launchctl(['bootout', `${domain}/${label}`]);
    // bootstrap's result IS reported, unlike bootout's: by this point the
    // previously-working job has already been booted out, so a bootstrap
    // failure (a malformed plist, launchd's own "Bootstrap failed: 5:
    // Input/output error") leaves the machine with no scheduler and this is
    // the only signal available to say so.
    if (!launchctl(['bootstrap', domain, path])) {
      process.stderr.write(`[aka] background-sync: launchctl bootstrap failed for ${label}\n`);
    }
  } catch {
    // Best-effort — see the doc comment above.
  }
}

/**
 * Remove the LaunchAgent, best-effort. Called from both surfaces that detach
 * a machine — `aka detach`, alongside every other piece of
 * attachment-derived state (see `clearAttachmentDerivedState`), and the
 * dashboard's own detach action — this is not one of the files
 * `clearAttachmentDerivedState` removes, since a LaunchAgent plist does not
 * live under the AKA data dir it sweeps. `base` must be the SAME home that
 * was passed to `installBackgroundSync`, since it is what the label (and so
 * the plist filename and bootout target) is keyed on.
 */
export function uninstallBackgroundSync(base: string, deps: BackgroundScheduleDeps = {}): void {
  try {
    if ((deps.platform ?? process.platform) !== 'darwin') return;
    (deps.runLaunchctl ?? defaultRunLaunchctl)([
      'bootout',
      `${guiDomain()}/${backgroundSyncLabel(base)}`,
    ]);
    (
      deps.removeFile ??
      ((p: string) => {
        rmSync(p, { force: true });
      })
    )(plistPath(base, deps));
  } catch {
    // Best-effort — see installBackgroundSync.
  }
}
