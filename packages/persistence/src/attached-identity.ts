import { createHash, createHmac } from 'node:crypto';
import { lstatSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import type {
  AttachedCredentialAny,
  AttachedIdentity,
  AttachedIdentityBinding,
  AttachmentScopeEntry,
  WebAccountProvider,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  AGENT_ACCOUNT_PROVIDER_OF,
  agentKey,
  ATTACHED_IDENTITY_SPEC_VERSION,
  ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX,
  attachedIdentityHolds,
  attachmentModeOf,
  normalizeAccountEmail,
  parseAttachedIdentity,
  parseAttachmentScope,
  parseWebAccountKey,
  WEB_ACCOUNT_PROVIDER,
  workSubscriptionsOn,
} from '@akasecurity/schema';

import { ATTACHED_IDENTITY_FILENAME } from './attached-derived.ts';
import { readControlPlaneCredentialFile } from './control-plane-credential.ts';
import { withFileLock } from './file-lock.ts';
import { ensureDataDirSync, writeOwnerOnlyFileSync } from './paths.ts';
import { clearSessionAccountState } from './session-accounts.ts';

// Who attached this machine, kept beside the credential it belongs to:
// <dataDir>/attached-identity.json, owner-only, written under its own lock.
//
// Digests only. The credential's is an HMAC-SHA256 keyed by the key, over a fixed
// prefix, so it cannot equal the server's hash of the key; the others are sha256
// over a fixed prefix and their value, so none of them can equal a digest made
// for another purpose. The email, the organization's name and the key never reach
// the file.
//
// The record counts only beside the credential it was written for
// (attachedIdentityHolds): a record left beside another key, another endpoint or
// a machine-wide credential counts for nothing, whichever build left it.

/** How long a hook waits for the record's lock before it gives up on a write. */
export const WORK_ACCOUNT_LOCK_TIMEOUT_MS = 200;

/**
 * What recordValidatedWorkAccount did: `'written'` it added the key, `'present'`
 * the record already held it, `'refused'` it will not hold it (the record does
 * not count, the key is not a coding agent's account, or the record is full),
 * `'timeout'` the lock was not taken and nothing was written.
 */
export type WorkAccountWrite = 'written' | 'present' | 'refused' | 'timeout';

// The label a learned work account is stored with.
const WORK_ACCOUNT_LABEL: Record<WebAccountProvider, string> = {
  [WEB_ACCOUNT_PROVIDER.Claude]: 'Claude work account',
};

// The providers a coding agent signs in with.
const CODING_AGENT_PROVIDERS: ReadonlySet<WebAccountProvider> = new Set(
  Object.values(AGENT_ACCOUNT_PROVIDER_OF).filter(
    (provider): provider is WebAccountProvider => provider !== undefined,
  ),
);

const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

/**
 * The digest of the user who attached this machine: sha256 hex of a fixed prefix
 * and the normalized email (normalizeAccountEmail), or `undefined` for an email
 * that does not normalize.
 */
export function attachedUserDigestOf(email: unknown): string | undefined {
  const normalized = normalizeAccountEmail(email);
  return normalized === undefined ? undefined : sha256Hex(`aka-attached-user:v1\n${normalized}`);
}

/**
 * The digest of a credential's key: an HMAC-SHA256, in hex, keyed by the key over
 * a fixed prefix. It is deterministic and one way, and it cannot equal the
 * server's hash of the key.
 */
export function credentialDigestOf(apiKey: string): string {
  return createHmac('sha256', apiKey).update('aka-credential-binding:v1\n').digest('hex');
}

/**
 * The tag an attachment's agent keys carry: the first sixteen hex digits of a
 * sha256 over a fixed prefix, the endpoint, the organization's name and the
 * attached user's digest. The same user rotating a key keeps it; another user,
 * organization or endpoint gets another.
 */
export function scopeTagOf(
  endpoint: string,
  tenantName: string,
  attachedUserDigest: string,
): string {
  return sha256Hex(`aka-agent-scope:v1\n${endpoint}\n${tenantName}\n${attachedUserDigest}`).slice(
    0,
    16,
  );
}

/**
 * The binding hash every piece of per-session account state carries: the first
 * sixteen hex digits of a sha256 over a fixed prefix, the endpoint, the
 * credential's digest and the attached user's digest. A new key, user or
 * endpoint changes it.
 */
export function bindingHashOf(
  endpoint: string,
  credentialDigest: string,
  attachedUserDigest: string,
): string {
  return sha256Hex(
    `aka-session-binding:v1\n${endpoint}\n${credentialDigest}\n${attachedUserDigest}`,
  ).slice(0, 16);
}

function recordFile(dataDir: string): string {
  return join(dataDir, ATTACHED_IDENTITY_FILENAME);
}

// The stored value, or undefined when there is no file or it is not JSON.
function readStored(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as unknown;
  } catch {
    return undefined;
  }
}

// The stored work accounts as found, an entry this build cannot read included.
function storedWorkAccounts(raw: unknown): unknown[] {
  if (typeof raw !== 'object' || raw === null || !('workAccounts' in raw)) return [];
  const entries: unknown = raw.workAccounts;
  return Array.isArray(entries) ? [...(entries as unknown[])] : [];
}

function writeRecord(file: string, record: Record<string, unknown>): void {
  writeOwnerOnlyFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
}

// What a record has to match to count beside `credential`, for `endpoint`.
function bindingOf(
  endpoint: string | undefined,
  credential: Readonly<AttachedCredentialAny> | undefined,
): AttachedIdentityBinding {
  if (credential === undefined) return { endpoint, credentialDigest: undefined, mode: undefined };
  return {
    endpoint,
    credentialDigest: credentialDigestOf(credential.apiKey),
    mode: attachmentModeOf(credential),
  };
}

/** The stored record, validated (parseAttachedIdentity), whether or not it counts. Never throws. */
export function readAttachedIdentity(dataDir: string): AttachedIdentity | undefined {
  return parseAttachedIdentity(readStored(recordFile(dataDir)));
}

/**
 * The stored record when it counts for `endpoint` beside `credential`
 * (attachedIdentityHolds), else `undefined`. Never throws.
 */
export function readBoundAttachedIdentity(
  dataDir: string,
  endpoint: string | undefined,
  credential: Readonly<AttachedCredentialAny> | undefined,
): AttachedIdentity | undefined {
  try {
    const raw = readStored(recordFile(dataDir));
    return attachedIdentityHolds(raw, bindingOf(endpoint, credential))
      ? parseAttachedIdentity(raw)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Who a scoped attach verified its key as, once its writes have landed. */
export interface AttachedIdentityInput {
  readonly endpoint: string;
  readonly apiKey: string;
  readonly tenantName: string;
  readonly userEmail: string;
  /** Where the answer came from; `'attach'` unless said otherwise. */
  readonly source?: AttachedIdentity['source'] | undefined;
  /**
   * Run inside the record's lock before anything is written; `false` writes no
   * record and clears no session state. A refresh passes it to re-check that the
   * settings and the credential still match what it asked about.
   */
  readonly stillCurrent?: (() => boolean) | undefined;
}

/**
 * Write the record for a scoped attach whose writes have landed, and clear every
 * session's account state (clearSessionAccountState).
 *
 * The work accounts already learned are kept, as found, when the stored record
 * names the same endpoint, attached user and scope tag: a key rotation by the
 * same user. Any other stored record starts the new one with none. An email that
 * does not normalize gets no record, and a stored one is removed unless the
 * caller passed `stillCurrent`. With `stillCurrent`, nothing is written or
 * cleared unless it answers true inside the lock. Returns whether the record was
 * written. Never throws: a write that fails leaves no record for this key, and
 * the attach as it was.
 */
export function writeAttachedIdentity(
  dataDir: string,
  input: AttachedIdentityInput,
  now: Date = new Date(),
): boolean {
  try {
    const attachedUserDigest = attachedUserDigestOf(input.userEmail);
    if (attachedUserDigest === undefined) {
      if (input.stillCurrent === undefined) removeAttachedIdentity(dataDir);
      return false;
    }
    ensureDataDirSync(dataDir);
    const file = recordFile(dataDir);
    const scopeTag = scopeTagOf(input.endpoint, input.tenantName, attachedUserDigest);
    return withFileLock(file, () => {
      if (input.stillCurrent !== undefined && !input.stillCurrent()) return false;
      clearSessionAccountState(dataDir);
      const stored = readStored(file);
      const previous = parseAttachedIdentity(stored);
      const sameUser =
        previous?.endpoint === input.endpoint &&
        previous.attachedUserDigest === attachedUserDigest &&
        previous.scopeTag === scopeTag;
      writeRecord(file, {
        specVersion: ATTACHED_IDENTITY_SPEC_VERSION,
        endpoint: input.endpoint,
        credentialDigest: credentialDigestOf(input.apiKey),
        attachedUserDigest,
        scopeTag,
        source: input.source ?? 'attach',
        checkedAt: now.toISOString(),
        workAccounts: sameUser
          ? storedWorkAccounts(stored).slice(0, ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX)
          : [],
      });
      return true;
    });
  } catch {
    return false;
  }
}

/**
 * Delete the record and every session's account state, as a machine-wide attach
 * does. Returns whether neither remains. Never throws.
 */
export function removeAttachedIdentity(dataDir: string): boolean {
  const cleared = clearSessionAccountState(dataDir);
  try {
    const file = recordFile(dataDir);
    if (lstatSync(file, { throwIfNoEntry: false }) === undefined) return cleared;
    withFileLock(file, () => {
      rmSync(file, { force: true });
    });
    return cleared;
  } catch {
    return false;
  }
}

/**
 * Add a work account a hook has just validated, `key`, to the record, once.
 *
 * Inside the record's lock it re-checks that the record counts for `endpoint`
 * beside `credential`, and it never changes who the record says attached this
 * machine. A key that already reads as a learned work account is not added
 * again, and a record already holding ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX entries,
 * readable or not, takes no more. The lock is waited on for
 * WORK_ACCOUNT_LOCK_TIMEOUT_MS at most; when it is not taken nothing is written
 * and the answer is `'timeout'`. Every other key and entry is kept as found.
 * Never throws.
 */
export function recordValidatedWorkAccount(
  dataDir: string,
  input: {
    readonly endpoint: string;
    readonly credential: Readonly<AttachedCredentialAny>;
    readonly key: string;
  },
  now: Date = new Date(),
): WorkAccountWrite {
  // Whether the lock was taken: a throw before it was is a timeout.
  const lock = { taken: false };
  try {
    const provider = parseWebAccountKey(input.key)?.provider;
    if (provider === undefined || !CODING_AGENT_PROVIDERS.has(provider)) return 'refused';
    const file = recordFile(dataDir);
    return withFileLock(
      file,
      (): WorkAccountWrite => {
        lock.taken = true;
        const raw = readStored(file);
        if (!attachedIdentityHolds(raw, bindingOf(input.endpoint, input.credential))) {
          return 'refused';
        }
        const learned = parseAttachedIdentity(raw)?.workAccounts ?? [];
        if (learned.some((entry) => entry.identity === input.key)) return 'present';
        const stored = storedWorkAccounts(raw);
        if (stored.length >= ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX) return 'refused';
        const entry: AttachmentScopeEntry = {
          kind: 'account',
          identity: input.key,
          label: WORK_ACCOUNT_LABEL[provider],
          enrolledAt: now.toISOString(),
        };
        writeRecord(file, {
          ...(raw as Record<string, unknown>),
          workAccounts: [...stored, entry],
        });
        return 'written';
      },
      { timeoutMs: WORK_ACCOUNT_LOCK_TIMEOUT_MS },
    );
  } catch {
    return lock.taken ? 'refused' : 'timeout';
  }
}

/**
 * Empty the record's learned work accounts, under its lock, only while it counts
 * for `endpoint` beside `credential`. Who the record says attached this machine
 * is kept, and so is every other key. Returns whether the record holds none
 * afterwards. Never throws.
 */
export function forgetWorkAccounts(
  dataDir: string,
  input: { readonly endpoint: string; readonly credential: Readonly<AttachedCredentialAny> },
): boolean {
  try {
    const file = recordFile(dataDir);
    return withFileLock(file, () => {
      const raw = readStored(file);
      if (!attachedIdentityHolds(raw, bindingOf(input.endpoint, input.credential))) return false;
      if (storedWorkAccounts(raw).length === 0) return true;
      writeRecord(file, { ...(raw as Record<string, unknown>), workAccounts: [] });
      return true;
    });
  } catch {
    return false;
  }
}

/**
 * The agent keys a coding agent's rows may forward under on this machine, as
 * extra scope entries for resolveScope. None unless the stored record counts for
 * the endpoint in force beside `credential` (readBoundAttachedIdentity). Then,
 * each under the record's scope tag (agentKey):
 *   - each learned work account, while workSubscriptionsOn(settings.attachmentScope);
 *   - each account entry the scope record for this endpoint stores with
 *     `codingAgents: true`, whose provider a coding agent signs in with, whether
 *     or not recognition is on.
 * Each once. Never a bare account key, which would select web chat rows. Never
 * throws: a throw gives none.
 */
export function codingScopeExtras(
  dataDir: string,
  settings: Pick<WorkspaceSettings, 'controlPlane' | 'attachmentScope'>,
  credential: Readonly<AttachedCredentialAny> | undefined,
): AttachmentScopeEntry[] {
  try {
    const record = readBoundAttachedIdentity(dataDir, settings.controlPlane?.endpoint, credential);
    if (record === undefined) return [];
    const extras = new Map<string, AttachmentScopeEntry>();
    const add = (entry: AttachmentScopeEntry): void => {
      const identity = agentKey(record.scopeTag, entry.identity);
      if (identity === undefined || extras.has(identity)) return;
      extras.set(identity, {
        kind: 'account',
        identity,
        ...(entry.label === undefined ? {} : { label: entry.label }),
        enrolledAt: entry.enrolledAt,
      });
    };
    if (workSubscriptionsOn(settings.attachmentScope)) {
      for (const entry of record.workAccounts) add(entry);
    }
    const stored = parseAttachmentScope(settings.attachmentScope);
    if (stored?.endpoint === record.endpoint) {
      for (const entry of stored.entries) {
        if (entry.kind !== 'account' || entry.codingAgents !== true) continue;
        const provider = parseWebAccountKey(entry.identity)?.provider;
        if (provider !== undefined && CODING_AGENT_PROVIDERS.has(provider)) add(entry);
      }
    }
    return [...extras.values()];
  } catch {
    return [];
  }
}

/**
 * codingScopeExtras, with the credential read here from `settingsDir` for the
 * connection the settings name, so the caller never holds the key. None when
 * no usable credential is there. Never throws.
 */
export function codingScopeExtrasAt(
  settingsDir: string,
  dataDir: string,
  settings: Pick<WorkspaceSettings, 'controlPlane' | 'attachmentScope'>,
): AttachmentScopeEntry[] {
  try {
    const read = readControlPlaneCredentialFile(settingsDir, settings.controlPlane);
    return read.usable ? codingScopeExtras(dataDir, settings, read.credential) : [];
  } catch {
    return [];
  }
}
