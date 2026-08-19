import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A throwaway macOS keychain for tests that drive the REAL `/usr/bin/security`
 * binary rather than an injected fake.
 *
 * Two properties are load-bearing and easy to lose:
 *
 * - **Nothing reaches the login keychain.** `exec` appends this keychain's path
 *   to every argv, and `security` treats a trailing path as the keychain to
 *   operate on. A caller cannot opt out, because the alternative — targeting the
 *   default keychain — writes vault key material into the developer's own
 *   keychain and leaves it there.
 * - **A prompt becomes a skip, never a hang.** Every call carries a deadline far
 *   below the package's 20s `testTimeout`. A keychain dialog blocks `security`
 *   until someone clicks it, and CI has nobody to click: without a deadline the
 *   suite would wedge until vitest killed it and report a timeout that names
 *   nothing. On a deadline it reports `usable: false` with a reason instead.
 */
export interface DisposableKeychain {
  /** Absolute path of the throwaway keychain, as passed to `security`. */
  readonly path: string;
  /**
   * False when this environment cannot host one — a non-darwin platform, an
   * absent `security`, or a create/unlock that failed or prompted. Callers gate
   * on it: `if (!kc.usable) ctx.skip(kc.reason ?? '…')`. An early `return`
   * reports as a pass, which is the failure mode this shape exists to remove.
   */
  readonly usable: boolean;
  /** Why it is unusable. Always set when `usable` is false. */
  readonly reason?: string;
  /** Runs `security` against THIS keychain. Returns stdout. */
  exec(args: readonly string[]): string;
  /** Deletes the keychain and its temp dir. Idempotent; safe in a `finally`. */
  cleanup(): void;
}

const SECURITY_BIN = '/usr/bin/security';

/**
 * Per-call ceiling. A local `security` invocation answers in well under 100ms,
 * so this is ~30x headroom for an honest call while staying far enough under
 * `testTimeout` (20s) that vitest never wins the race — if vitest wins, the
 * refusal this deadline exists to produce is replaced by a bare timeout.
 */
const CALL_TIMEOUT_MS = 3_000;

/** A `security` call that exceeded {@link CALL_TIMEOUT_MS}, i.e. probably prompted. */
function timedOut(err: unknown): boolean {
  const e = err as { code?: string; signal?: string | null };
  return e.code === 'ETIMEDOUT' || e.signal === 'SIGTERM';
}

/** Exit status of a failed `security` call, or null when it did not run at all. */
function exitStatus(err: unknown): number | null {
  const status = (err as { status?: unknown }).status;
  return typeof status === 'number' ? status : null;
}

/**
 * Creates a fresh keychain in its own temp dir, unlocked with a password this
 * process generated, with auto-lock disabled.
 *
 * The password rides in argv, which `security help` calls insecure — correctly,
 * for a real keychain. This one holds nothing but test fixtures and is deleted
 * in `cleanup()`, so what argv exposes is a random string guarding nothing.
 */
export function createDisposableKeychain(
  platform: NodeJS.Platform = process.platform,
): DisposableKeychain {
  const unusable = (reason: string): DisposableKeychain => ({
    path: '',
    usable: false,
    reason,
    exec: () => {
      throw new Error(`disposable keychain is unusable: ${reason}`);
    },
    // Nothing was created, so there is nothing to tear down. Still safe to call
    // from a `finally`, which is why it is present rather than optional.
    cleanup: () => undefined,
  });

  if (platform !== 'darwin') {
    return unusable(`keychain custody is macOS-only (platform: ${platform})`);
  }

  const dir = mkdtempSync(join(tmpdir(), 'aka-kc-'));
  const path = join(dir, `aka-test-${randomBytes(6).toString('hex')}.keychain`);
  const password = randomBytes(18).toString('base64url');

  // Best-effort teardown: `delete-keychain` unregisters it, and removing the
  // dir catches the `-db` suffixed file newer macOS actually writes. Both are
  // swallowed — a cleanup that throws would replace whatever the test is
  // reporting, and a leftover temp dir is not worth losing a real failure over.
  const cleanup = (): void => {
    try {
      execFileSync(SECURITY_BIN, ['delete-keychain', path], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: CALL_TIMEOUT_MS,
      });
    } catch {
      // already gone, never created, or refused — the rmSync below still runs
    }
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // a Windows-style sharing violation cannot occur here (darwin-only), and
      // a stranded temp dir is not a test failure
    }
  };

  // Setup runs on the same deadline as everything else, and bails on the FIRST
  // timeout: a dialog on `create-keychain` means every later call prompts too,
  // so continuing would spend the whole hook budget re-learning that.
  const setup: readonly (readonly string[])[] = [
    ['create-keychain', '-p', password, path],
    // No -t and no -l/-u: no timeout lock, no lock on sleep. A keychain that
    // re-locks mid-suite starts prompting again halfway through.
    ['set-keychain-settings', path],
    ['unlock-keychain', '-p', password, path],
  ];

  for (const args of setup) {
    try {
      execFileSync(SECURITY_BIN, [...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: CALL_TIMEOUT_MS,
      });
    } catch (err) {
      cleanup();
      const verb = args[0] ?? 'security';
      if (timedOut(err)) {
        return unusable(
          `security ${verb} exceeded ${String(CALL_TIMEOUT_MS)}ms — a keychain dialog is probably open, which CI cannot answer`,
        );
      }
      if ((err as { code?: string }).code === 'ENOENT') {
        return unusable(`${SECURITY_BIN} is not present on this machine`);
      }
      const status = exitStatus(err);
      return unusable(
        `security ${verb} failed${status === null ? '' : ` (exit ${String(status)})`}`,
      );
    }
  }

  return {
    path,
    usable: true,
    exec(args: readonly string[]): string {
      // The keychain path goes LAST, which is where every subcommand this
      // harness is used with takes it (`add-generic-password [keychain]`,
      // `find-generic-password [keychain...]`).
      return execFileSync(SECURITY_BIN, [...args, path], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: CALL_TIMEOUT_MS,
      });
    },
    cleanup,
  };
}
