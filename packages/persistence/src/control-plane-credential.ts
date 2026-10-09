import { chmodSync, lstatSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type {
  AttachedCredentialAny,
  AttachmentMode,
  ControlPlaneConnection,
  CredentialState,
  CredentialUnusableReason,
  UnsafeEndpointReason,
} from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_FILENAME,
  AttachedCredentialAny as CredentialSchema,
  attachmentModeOf,
  isSafeEndpoint,
  originOnly,
  unsafeEndpointReason,
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

// `isSafeEndpoint` now lives in @akasecurity/schema, beside `AttachedCredential`,
// so a second consumer that cannot depend on this package (the control-plane
// transport) can enforce the same rule. Re-exported here so every existing
// importer of this module keeps working.
export { isSafeEndpoint };

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
 *
 * The usable branch carries EITHER credential version, and the version is the
 * attachment's mode: v1 is a machine-wide attachment and v2 a scoped one. A
 * caller that FORWARDS reads the mode before it sends; a caller that only
 * presents the key — the policy pull, an attach rollback — treats the two
 * alike, and a rollback that rewrites what it read keeps the mode it found.
 */
export type CredentialFileRead =
  { usable: true; credential: AttachedCredentialAny } | Extract<CredentialState, { usable: false }>;

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
 * Every failure of the credential file itself is a `usable: false` state: absent,
 * unreadable, malformed, untrusted, an unsafe endpoint, or a credential for
 * another deployment. A settings directory path that is not a directory is not
 * one of them: the stat raises ENOTDIR and this does not catch it. A caller that
 * cannot afford a throw guards the call; `readControlPlaneAttachmentMode` is the
 * variant that answers `undefined` instead of throwing.
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
 * `value` as a credential, when this module's reader would read it back as one,
 * else null. The ONE rule both halves of this module apply: the reader refuses
 * a file by it, and the writer refuses an object by it, so the writer cannot
 * emit a file its own reader calls malformed.
 *
 * BOTH versions, keyed on `specVersion`: v1, a machine-wide attachment read
 * exactly as it always has been, and v2, a scoped attachment carrying
 * `mode: 'scoped'`. Accepting v2 is what switches scoped forwarding on, and it
 * is safe only because every path that forwards what this machine recorded
 * (captured activity, history, the Data Shares register, a device command's
 * scan) consults the scope verdict before it sends. The policy pull, the posture
 * report and the command poll and ack send without a verdict, by design. A build
 * that predates scoped attachments parses `specVersion` as the literal 1, reads
 * v2 as malformed, and forwards nothing. So a version is accepted here only once
 * every forwarder knows what it means.
 *
 * VERSION 1 NAMES NO MODE, and a value that says otherwise is refused. The v1
 * shape is not strict, so the parse DROPS a `mode` key it does not declare:
 * `{ specVersion: 1, mode: 'scoped', … }` would come out as a plain machine-wide
 * credential and send everything. The check is on the raw value because the
 * parsed one no longer carries the key. No writer emits one, and the writer now
 * refuses to.
 */
function asReadableCredential(value: unknown): AttachedCredentialAny | null {
  const result = CredentialSchema.safeParse(value);
  if (!result.success) return null;
  if (
    attachmentModeOf(result.data) === 'machine' &&
    typeof value === 'object' &&
    value !== null &&
    Object.hasOwn(value, 'mode')
  ) {
    return null;
  }
  return result.data;
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
 * Every failure of the credential file itself is a `usable: false` state: absent,
 * unreadable, malformed, untrusted, an unsafe endpoint, or a credential for
 * another deployment. A settings directory path that is not a directory is not
 * one of them: the stat raises ENOTDIR and this does not catch it. A caller that
 * cannot afford a throw guards the call; `readControlPlaneAttachmentMode` is the
 * variant that answers `undefined` instead of throwing.
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

  // Either version, by asReadableCredential's rule — which also refuses a
  // version-1 file that names a mode. Every reader in this module goes through
  // this function, so none of them can return such a file as usable.
  const credential = asReadableCredential(parsed);
  if (credential === null) return { usable: false, reason: 'malformed' };

  if (!isSafeEndpoint(credential.endpoint)) {
    return { usable: false, reason: 'unsafe-endpoint' };
  }

  if (connection !== undefined && connection.endpoint !== credential.endpoint) {
    return {
      usable: false,
      reason: 'endpoint-mismatch',
      credentialEndpoint: credential.endpoint,
      settingsEndpoint: connection.endpoint,
    };
  }

  return { usable: true, credential };
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
 *
 * Null stands for every `usable: false` state of the credential file. A settings
 * directory path that is not a directory is not one of them: the stat raises
 * ENOTDIR from `readControlPlaneCredentialFile` and this does not catch it.
 */
export function readControlPlaneCredential(
  settingsDir: string,
  connection: ControlPlaneConnection,
): AttachedCredentialAny | null {
  const read = readControlPlaneCredentialFile(settingsDir, connection);
  return read.usable ? read.credential : null;
}

/**
 * The attachment mode of the credential this machine holds for `connection`'s
 * deployment, or `undefined`: no connection, no usable credential, or a
 * credential bound to another endpoint.
 *
 * The mode is not secret; the key is. This takes the wide read and returns the
 * mode alone, so a caller that needs only "machine" or "scoped" is handed a
 * word, never the credential, and `CredentialState` keeps carrying no payload. A
 * credential bound to another endpoint answers `undefined` rather than its own
 * mode, because it is not the attachment `connection` describes. Never throws:
 * every read failure is `undefined`.
 *
 * THE TRY/CATCH IS LOAD-BEARING. The wide read describes every failure it
 * expects as a state, but its file checks can still throw: looking inside a path
 * whose settings directory is really a regular file raises ENOTDIR from the
 * stat. Without the catch that error would reach every caller as a throw rather
 * than as an attachment with no known mode.
 */
export function readControlPlaneAttachmentMode(
  settingsDir: string,
  connection: ControlPlaneConnection | undefined,
): AttachmentMode | undefined {
  if (connection === undefined) return undefined;
  try {
    const read = readControlPlaneCredentialFile(settingsDir, connection);
    return read.usable ? attachmentModeOf(read.credential) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether this machine is attached as a personal device: it holds a scoped
 * credential for `connection`'s deployment.
 *
 * The answer `aka sync-history` words its help by. It reads only the credential
 * and not whether the settings say attached, so a half attachment that still
 * holds a scoped credential counts. False for no connection, no usable
 * credential, a credential bound to another endpoint, and a settings directory
 * that cannot be read. Never throws.
 *
 * Not what decides whether a web chat is recorded: false is the wrong answer
 * there for a credential that cannot be read, so the native host, `aka
 * extension status` and the dashboard ask `webChatWithholding`, which fails
 * closed.
 */
export function isScopedAttachment(
  settingsDir: string,
  connection: ControlPlaneConnection | undefined,
): boolean {
  return readControlPlaneAttachmentMode(settingsDir, connection) === 'scoped';
}

/**
 * The plain-language reason `writeControlPlaneCredential` refused an endpoint,
 * beneath `refusing to store a control-plane credential for <origin>:` — never
 * the raw endpoint, since the `userinfo` case exists to keep a password
 * carried on the URL out of this message.
 */
function unsafeEndpointRefusal(reason: UnsafeEndpointReason): string {
  switch (reason) {
    case 'unparseable':
      return 'that does not look like a web address.';
    case 'userinfo':
      return 'the address carries a username or password, which must not be stored alongside the credential.';
    case 'query-or-fragment':
      return 'the address must be an origin, optionally with a path, not a query string or fragment.';
    case 'insecure':
      return 'an access key must not be stored for a non-HTTPS endpoint (http is accepted only for a loopback deployment).';
  }
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
 *
 * Either version, serialised exactly as handed over and with nothing added: a
 * machine-wide attach writes v1 byte for byte as it always has, and a scoped
 * one writes v2. The version on disk is the caller's choice, and it is what a
 * reader that predates scoped attachments keys its refusal on.
 *
 * REFUSED BEFORE ANYTHING IS WRITTEN: an endpoint a key must not be stored for,
 * and any object this module's reader would read back as malformed
 * (asReadableCredential) — a member the schema rejects, a version no build
 * writes, a v2 without `mode: 'scoped'`, a v1 that names a mode. A credential
 * the reader refuses forwards nothing, so writing one would turn a mistake in a
 * caller into a machine that silently stops reporting. The check validates and
 * the write serialises what it was handed, never the parse's output, so a valid
 * credential's bytes do not depend on the schema's key order. Neither refusal
 * names the key.
 */
export function writeControlPlaneCredential(
  settingsDir: string,
  credential: AttachedCredentialAny,
): void {
  const reason = unsafeEndpointReason(credential.endpoint);
  if (reason !== null) {
    throw new Error(
      `refusing to store a control-plane credential for ${originOnly(credential.endpoint)}: ` +
        unsafeEndpointRefusal(reason),
    );
  }
  if (asReadableCredential(credential) === null) {
    throw new Error(
      `refusing to store a control-plane credential for ${originOnly(credential.endpoint)}: ` +
        'it is not a credential this build would read back.',
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
