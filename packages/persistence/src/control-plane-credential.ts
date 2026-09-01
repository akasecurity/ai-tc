import { chmodSync, lstatSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type {
  AttachedCredential,
  ControlPlaneConnection,
  CredentialState,
  CredentialUnusableReason,
} from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_FILENAME,
  AttachedCredential as CredentialSchema,
} from '@akasecurity/schema';

import { DATA_FILE_MODE, ensureDataDirSync, writeOwnerOnlyFileSync } from './paths.ts';

// The credential half of an attachment: `<settingsDir>/control-plane-credential.json`,
// owner-only.
//
// An attachment has two halves in two files, and this module owns the second.
// `settings.json` holds the PUBLIC half — `runMode: 'attached'` plus the
// `ControlPlaneConnection` descriptor — and deliberately carries no credential,
// so a bearer token does not sit in a file the dashboard renders, an
// administrator pins, and `applyOnboarding` rewrites. This file holds the
// secret half and nothing else.
//
// `settingsDir`, not `dataDir`: a credential must outlive a wipe of the data
// directory whose contents it governs.
//
// Everything here is SYNCHRONOUS. The read runs inside hook processes that
// resolve their gateway and exit, so there is nowhere to await.

/** Absolute path of the credential file for a settings dir. */
export function controlPlaneCredentialPath(settingsDir: string): string {
  return join(settingsDir, ATTACHED_CREDENTIAL_FILENAME);
}

/**
 * The endpoints a credential may be presented to.
 *
 * The credential rides on every request, so a plaintext hop lets anyone on the
 * network path read it. `https:` is always fine. `http:` is tolerated only for
 * loopback, which is how a deployment is exercised locally — anything else is
 * refused, and the caller stays standalone rather than send a bearer token in
 * the clear over a real network.
 *
 * The bracketed `'[::1]'` spelling is listed because `URL.hostname` preserves
 * the brackets for an IPv6 literal, so both forms occur.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

export function isSafeEndpoint(endpoint: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return false;
  }
  if (parsed.protocol === 'https:') return true;
  return parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname);
}

// `CredentialUnusableReason` and `CredentialState` now live in
// @akasecurity/schema, beside the `AttachedCredential` they describe, and are
// re-exported here so this module's public surface is unchanged.
//
// They moved because a PRESENTATIONAL surface has to name these states without
// depending on the module that reads the disk: @akasecurity/dashboard-ui may
// reach @akasecurity/schema and must not reach this package, so while the union
// lived here the local dashboard could not be handed one. Every consumer that
// imports them from @akasecurity/persistence keeps working.
export type { CredentialState, CredentialUnusableReason };

/**
 * The same answer as `CredentialState`, WITH the credential.
 *
 * A separate type, and one that never leaves this package's server-side
 * consumers, because the two questions are different: "can this machine talk to
 * its control plane, and if not why" is a question a surface asks, and "give me
 * the key" is one only a transport or a rollback asks. Fusing them made every
 * holder of a state a holder of a bearer credential, which is how one reached a
 * client component and got serialised to the browser.
 *
 * Reachable only by asking for it by name. That is the whole mechanism: the
 * narrow state is what a caller gets by default, and the wide read is a visible
 * act at the call site.
 */
export type CredentialFileRead =
  { usable: true; credential: AttachedCredential } | Extract<CredentialState, { usable: false }>;

/**
 * Repair a too-permissive mode, or refuse the file.
 *
 * Repair-and-continue rather than refuse-on-sight: a group-readable credential
 * file is most often the work of an editor or a `cp`, and refusing would strand
 * a machine that is legitimately attached. Tightening it is strictly better
 * than both alternatives — leaving it readable, or dropping the attachment.
 *
 * The case that is NOT repairable is a file owned by someone else: the chmod
 * would fail anyway, and a foreign-owned file at this path is a planted
 * credential. Symlinks are refused for the same reason — the target is
 * anywhere at all, and following one would read a credential out of a location
 * this module never chose.
 *
 * THAT SYMLINK REFUSAL IS POINT-IN-TIME, and the docblock used to imply
 * otherwise. Two syscalls after it follow links — the `chmodSync` below and the
 * `readFileSync` at the call site — so a symlink swapped in after this returns
 * is followed by both. Closing it properly needs an `openSync(O_NOFOLLOW)` whose
 * fd carries every later operation, which POSIX supports and Windows does not,
 * so the module would hold two shapes for one file. It is not closed because the
 * precondition is already stronger than the race: the credential sits in a 0700
 * settings dir, so an attacker who can win this window can also just replace the
 * file outright and skip the symlink. `paths.ts` states the same limit about the
 * same shape; keep the two sayings in step.
 *
 * ABSENCE IS ONE OF THE ANSWERS, not a refusal. The caller used to `lstat` the
 * path itself and then call this, which decided existence TWICE — and a
 * concurrent `aka detach` landing between the two made this return "refuse",
 * reported to the user as `untrusted-file`: a planted-credential accusation for
 * an ordinary, legitimate detach. One stat, three answers.
 *
 * ON WINDOWS NEITHER HALF RUNS, and the docblock used to claim the ownership
 * check still did. It does not: `process.getuid` is undefined there, so the uid
 * comparison is skipped along with the mode repair, and the only refusal left
 * is the symlink test. What actually protects the credential on that platform
 * is the ACL on the user profile directory, which this module does not read —
 * a real check would need an owner-SID lookup rather than a uid, and is not
 * something a POSIX comparison can stand in for.
 */
type CredentialGate = 'ok' | 'absent' | 'untrusted';

function repairOrRefuseMode(file: string): CredentialGate {
  const link = lstatSync(file, { throwIfNoEntry: false });
  if (link === undefined) return 'absent';
  if (link.isSymbolicLink()) return 'untrusted';

  const stat = statSync(file, { throwIfNoEntry: false });
  // Gone between the two stats — a detach landing mid-read, not a refusal.
  if (stat === undefined) return 'absent';

  // `process.getuid` is absent on Windows; there is nothing to compare there.
  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) return 'untrusted';

  if (process.platform !== 'win32' && (stat.mode & 0o777) !== DATA_FILE_MODE) {
    try {
      chmodSync(file, DATA_FILE_MODE);
    } catch {
      // Could not tighten a file this user owns — refuse rather than read a
      // world-readable credential and treat it as private.
      return 'untrusted';
    }
  }
  return 'ok';
}

/**
 * The credential's state, described rather than reduced.
 *
 * Pass the `ControlPlaneConnection` from settings to have the endpoints
 * compared. A credential is bound to the endpoint it was minted against, and a
 * mismatch is REPORTED rather than folded into "not attached", because it is a
 * state a machine can enter without anyone touching this file:
 *
 *   - a hand edit of `settings.json` repoints the descriptor, which must detach
 *     the machine rather than redirect an existing credential to a host it was
 *     never minted for;
 *   - an administrator repoints `controlPlane` through a managed overlay
 *     (`readEffectiveSettings`), which can move a whole fleet at once and
 *     cannot write this file.
 *
 * The second is an ordinary migration, not a fault, and every affected machine
 * needs a status surface that can say "attached to X, holding a credential for
 * Y — re-attach" rather than reporting a bare "not attached" that reads as a
 * lost file.
 *
 * Never throws. Every failure is a `usable: false` state.
 */
export function readControlPlaneCredentialState(
  settingsDir: string,
  connection?: ControlPlaneConnection,
): CredentialState {
  const read = readControlPlaneCredentialFile(settingsDir, connection);
  // THE PROJECTION, and the one line that keeps the credential off every
  // surface. `usable` is rebuilt rather than spread, so a field added to the
  // wide read never arrives here by accident — a spread would carry the next
  // one out the same way `credential` went.
  return read.usable ? { usable: true } : read;
}

/**
 * The full read, credential included.
 *
 * SERVER-SIDE CALLERS ONLY. Everything this returns on the usable branch is a
 * bearer credential, so a value from here must never be handed to a component
 * that renders in a browser — in a React Server Components tree, anything
 * passed to a `'use client'` boundary is serialised into the payload the
 * browser receives. Surfaces take `readControlPlaneCredentialState`.
 *
 * Never throws. Every failure is a `usable: false` state.
 */
export function readControlPlaneCredentialFile(
  settingsDir: string,
  connection?: ControlPlaneConnection,
): CredentialFileRead {
  const file = controlPlaneCredentialPath(settingsDir);

  let raw: string;
  const gate = repairOrRefuseMode(file);
  if (gate === 'absent') return { usable: false, reason: 'absent' };
  if (gate === 'untrusted') return { usable: false, reason: 'untrusted-file' };
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    // ENOENT is the same detach race one syscall later: the file passed the gate
    // and was gone by the read. "Unreadable" would put the machine in a state
    // that reads as damaged rather than unattached.
    const code = (err as NodeJS.ErrnoException).code;
    return { usable: false, reason: code === 'ENOENT' ? 'absent' : 'unreadable' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { usable: false, reason: 'malformed' };
  }

  const result = CredentialSchema.safeParse(parsed);
  if (!result.success) return { usable: false, reason: 'malformed' };

  if (!isSafeEndpoint(result.data.endpoint)) {
    return { usable: false, reason: 'unsafe-endpoint' };
  }

  if (connection !== undefined && connection.endpoint !== result.data.endpoint) {
    return {
      usable: false,
      reason: 'endpoint-mismatch',
      credentialEndpoint: result.data.endpoint,
      settingsEndpoint: connection.endpoint,
    };
  }

  return { usable: true, credential: result.data };
}

/**
 * The credential to present to `connection`, or null.
 *
 * The transport's door: one value, no reasons, nothing to branch on. A caller
 * that has to EXPLAIN the absence reads the state instead.
 *
 * The connection is REQUIRED here, unlike on the state reader. A transport with
 * no descriptor to check against would be presenting a credential to whatever
 * endpoint the credential itself names — which is exactly the redirect the
 * endpoint binding exists to prevent, since this file and `settings.json` have
 * different writers and different protections.
 */
export function readControlPlaneCredential(
  settingsDir: string,
  connection: ControlPlaneConnection,
): AttachedCredential | null {
  const read = readControlPlaneCredentialFile(settingsDir, connection);
  return read.usable ? read.credential : null;
}

/**
 * Write (or overwrite) the credential, owner-only.
 *
 * Overwrites silently: re-attaching an attached machine is how a credential is
 * rotated, so it is idempotent by design rather than an error.
 *
 * `writeOwnerOnlyFileSync` rather than a hand-rolled tmp+rename — it creates
 * the tmp with `wx` (O_EXCL), so it refuses to follow a symlink planted at the
 * tmp path, removes a stale same-pid tmp first, cleans up on failure, and
 * re-asserts the mode after the rename. This file holds a bearer credential;
 * none of that is optional for it.
 *
 * THROWS, unlike every read path here, because a failed attach must be visible
 * to whoever ran it. Only the read side is fail-open.
 */
export function writeControlPlaneCredential(
  settingsDir: string,
  credential: AttachedCredential,
): void {
  if (!isSafeEndpoint(credential.endpoint)) {
    throw new Error(
      `refusing to store a control-plane credential for a non-HTTPS endpoint: ${credential.endpoint}`,
    );
  }
  ensureDataDirSync(settingsDir);
  writeOwnerOnlyFileSync(
    controlPlaneCredentialPath(settingsDir),
    `${JSON.stringify(credential, null, 2)}\n`,
  );
}

/**
 * Remove the credential. Returns false when there was nothing to remove.
 *
 * THE CREDENTIAL IS ALL THIS REMOVES, AND A DETACH IS MORE THAN THAT. Two other
 * things outlive it and belong to whoever owns the detach:
 *
 *   - the settings descriptor (`runMode` + `controlPlane`), which is what
 *     `isAttached` reads — a machine whose credential is gone but whose
 *     descriptor remains is attached-and-broken rather than standalone;
 *   - any cached policy the deployment supplied. A tenant bundle merges over
 *     the local one RAISE-ONLY, so one left behind goes on escalating
 *     enforcement on a machine nothing manages any more, and nothing would ever
 *     refresh or clear it — the sync that wrote it runs only while attached.
 *
 * This module owns neither, so it removes neither; it is named here because a
 * detach that stops at the credential is the failure to avoid.
 */
export function removeControlPlaneCredential(settingsDir: string): boolean {
  const file = controlPlaneCredentialPath(settingsDir);
  const existed = lstatSync(file, { throwIfNoEntry: false }) !== undefined;
  // `force` swallows ENOENT and still throws on a real failure (EACCES, EPERM,
  // a directory in the way) — a detach that silently left the credential in
  // place would be the worst outcome available here.
  rmSync(file, { force: true });
  return existed;
}
