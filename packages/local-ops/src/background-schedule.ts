import { spawn, spawnSync } from 'node:child_process';
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

// Not exported: it is a prefix `backgroundSyncLabel` builds on, not a label
// any caller should use on its own — a consumer that read the name and
// bootout'd `gui/<uid>/com.akasecurity.aka.background-sync` would target
// nothing, since every real job's label carries the per-base hash suffix.
const BACKGROUND_SYNC_LABEL = 'com.akasecurity.aka.background-sync';

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
  /**
   * Starting the detached child. Injectable for the same reason every other
   * boundary here is: without it a test of the argv actually spawns a process,
   * and the only thing it could then assert is that spawning did not throw.
   */
  startDetached?: (command: string, args: readonly string[]) => void;
  /** Whether the `aka` command can be found at all. Injectable, like the spawn. */
  probeCli?: (command: string) => boolean;
  /** The command that drives the CLI. Injectable so a test need not have one. */
  akaCommand?: string;
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
/**
 * What starting a drain pass by hand could not do.
 *
 * `spawn-failed` is the process refusing to start at all; `no-cli-entry` is the
 * plain-node case where there is no entry script to re-invoke (see self-exec).
 * Both are REPORTED rather than swallowed, unlike the passive callers of the
 * same argv — a scheduler that cannot install and a cache that cannot refresh
 * are best-effort background work, while a control somebody pressed owes them an
 * answer.
 */
function defaultStartDetached(command: string, args: readonly string[]): void {
  // Detached with its output discarded, so the pass outlives whatever started
  // it — a dashboard request, or a command that has already printed.
  const child = spawn(command, [...args], { detached: true, stdio: 'ignore' });
  // A spawn failure arrives on this event, not as a throw, and a `ChildProcess`
  // with no `error` listener re-raises it as an uncaught exception — which in a
  // dashboard request would take down the server over a pass that did not
  // start. There is nothing to tell: the child is detached and unwatched by
  // design, and the probe above has already answered the case a user can act on.
  child.on('error', () => undefined);
  child.unref();
}

/** The command that drives the CLI, as a user's shell resolves it. */
const AKA_COMMAND = 'aka';

/**
 * How long the presence probe may take before it is treated as present.
 *
 * A missing command comes back at once — `spawnSync` reports ENOENT without
 * running anything — so this bounds only the case where something called `aka`
 * exists and is slow to answer. That resolves to "present", which is the
 * fail-open direction: the worst case is a pass that starts and does nothing,
 * against the alternative of refusing a machine that is fine.
 */
const CLI_PROBE_TIMEOUT_MS = 5_000;

function defaultProbeCli(command: string): boolean {
  const probe = spawnSync(command, ['--version'], {
    stdio: 'ignore',
    timeout: CLI_PROBE_TIMEOUT_MS,
  });
  // ONLY absence counts as absent. A non-zero exit, a timeout, a version this
  // build does not recognise — all of them mean something by that name is
  // installed, and none of them is a thing to tell a user about the button they
  // just pressed.
  return (probe.error as NodeJS.ErrnoException | undefined)?.code !== 'ENOENT';
}

export type SyncRunStart =
  { started: true } | { started: false; reason: 'no-cli-entry' | 'spawn-failed' };

/**
 * Start one drain pass now, in a child that outlives this process.
 *
 * NAMES THE `aka` COMMAND, and does NOT re-invoke this executable the way the
 * scheduler above does. That difference is the whole of this function's
 * correctness, and it was found by pressing the button rather than by any test:
 *
 * `reinvokeArgv` re-runs THIS process's entry script, which is right for the
 * CLI installing its own scheduler and wrong for the only caller this has — a
 * dashboard Server Action. On the shipped path the dashboard server does run
 * inside the CLI process, so re-invocation happens to work; in a development
 * workspace Next is spawned directly, `process.argv[1]` is Next's own bin, and
 * re-invoking "this executable" spawns Next with a subcommand it has never
 * heard of. That spawn SUCCEEDS. The action reported that a pass had started,
 * nothing ran, and the panel sat there — the exact failure this whole surface
 * exists to make impossible.
 *
 * Naming the command is correct on both paths, because a machine that has the
 * CLI has it on PATH — that is how the pass gets run by hand, and how the
 * scheduler's own argv was built in the first place.
 *
 * NO PLATFORM GATE, unlike its neighbour. That one is gated because a LaunchAgent
 * is a macOS object and there is nothing to install elsewhere; this spawns a
 * child, which every platform has. Copying the gate would make the control a
 * silent no-op on Linux and Windows.
 *
 * `started: true` means the CHILD WAS SPAWNED, and deliberately claims nothing
 * beyond that. The child is detached with its output discarded, so nothing here
 * can see whether the pass ran, was refused by a closed breaker, or found the
 * lease already held. A surface that needs to know watches the store instead —
 * a real pass takes the lease, and one that never appears is one that never
 * started, whatever the reason.
 */
export function triggerHistorySyncRun(
  base: string,
  deps: BackgroundScheduleDeps = {},
): SyncRunStart {
  const command = deps.akaCommand ?? AKA_COMMAND;
  // BEFORE the spawn, because a spawn that cannot find its command fails
  // asynchronously — long after this has returned — and a control that reported
  // success for it would be the bug this function was rewritten to remove.
  if (!(deps.probeCli ?? defaultProbeCli)(command)) {
    return { started: false, reason: 'no-cli-entry' };
  }
  try {
    (deps.startDetached ?? defaultStartDetached)(command, [
      'sync-history',
      '--run',
      '--home',
      base,
    ]);
    return { started: true };
  } catch {
    return { started: false, reason: 'spawn-failed' };
  }
}

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
