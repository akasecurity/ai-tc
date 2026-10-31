// Sending the credential sightings a file scan found to the deployment this
// machine is attached to. A scan computes each sighting token in memory, from
// the value it just matched; everything here works on tokens and never sees a
// value. The transport is a parameter: this package opens no socket.
import { createHash, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { isAbsolute, relative, sep } from 'node:path';

import type {
  CredentialSighting,
  CredentialSightingsOutcome,
  CredentialSightingsRequest,
  ManagedSettings,
  RemoteFailureKind,
  ResolvedAttachmentScope,
  SightingLocationClass,
} from '@akasecurity/schema';
import {
  attachmentModeOf,
  CREDENTIAL_SIGHTINGS_BATCH_MAX,
  isAttached,
  parseAttachmentScope,
  resolveScope,
  scopeVerdict,
} from '@akasecurity/schema';

import { readControlPlaneCredential } from './control-plane-credential.ts';
import { hashProjectKey, scopeKeyOfProjectKey, supersededProjectKeys } from './egress-wire.ts';
import { createTrackedFileLookup } from './git-index.ts';
import { settingsDir } from './local-layout.ts';
import { readWorkspaceSettings } from './settings.ts';
import { readSightingSharing } from './sighting-sharing.ts';
import type { SightingKeys } from './vault/sighting-keys.ts';
import { readSightingKeys, sightingKeyEndpointFingerprint } from './vault/sighting-keys.ts';

/** One secret a scan found, already reduced to its token. */
export interface ScanSighting {
  token: string;
  /** The value's tokens under each previous key version still accepted. */
  aliases?: string[] | undefined;
  ruleId: string;
  variableName?: string | undefined;
  /** The absolute path the scan read; used to class the file and never sent. */
  file: string;
  /** The scope key of the repository holding the file, when it has one. */
  scopeKey?: string | undefined;
}

/** The project a scan's sightings belong to. */
export interface SightingScanProject {
  /** The local project key: `git:<remote or path>` or `path:<dir>`. */
  projectKey: string;
  /** The display name the Data Shares forward sends. */
  name: string;
  /** The absolute project root. Never sent. */
  root: string;
}

/** The connection a sender is handed. */
export interface CredentialSightingsConnection {
  endpoint: string;
  apiKey: string;
}

/** One request; a failure is named, never thrown. */
export type CredentialSightingsSend = (
  connection: CredentialSightingsConnection,
  request: CredentialSightingsRequest,
) => Promise<{ ok: true; accepted: number } | { ok: false; kind: RemoteFailureKind }>;

export interface SightingShareOptions {
  /** Replaces the managed settings file; `null` reads a machine with no administrator. */
  managedSettings?: ManagedSettings | null | undefined;
  /** False skips sharing for this run. */
  enabled?: boolean | undefined;
}

export type SightingSharePlan =
  | {
      ok: true;
      keys: SightingKeys;
      /** The sha256 hex of the endpoint that issued the key. */
      endpointFingerprint: string;
      /**
       * The sha256 hex of the attachment mode and the identities enrolled for
       * that endpoint; changes when one is enrolled or removed, or the mode does.
       */
      scopeFingerprint: string;
    }
  | { ok: false; outcome: CredentialSightingsOutcome };

/**
 * Whether a scan about to run should compute sighting tokens, and the keys to
 * compute them with: only when sharing is on (which requires an attachment),
 * the run has not opted out, and the machine holds a sighting key. A run that
 * opted out on a machine that does not share reports that sharing is off.
 * Never throws.
 */
export function planSightingShare(
  base: string,
  opts: SightingShareOptions = {},
): SightingSharePlan {
  try {
    const sharing = readSightingSharing(base, opts.managedSettings);
    if (!sharing.sharing) {
      return { ok: false, outcome: { status: 'not-shared', reason: 'sharing-off', sharing } };
    }
    if (opts.enabled === false) {
      return { ok: false, outcome: { status: 'not-shared', reason: 'opt-out' } };
    }
    const keys = readSightingKeys(base);
    const settings = readWorkspaceSettings(base);
    const endpoint = settings.controlPlane?.endpoint;
    if (keys === undefined || endpoint === undefined) {
      return { ok: false, outcome: { status: 'not-shared', reason: 'no-key' } };
    }
    const credential =
      settings.controlPlane === undefined
        ? null
        : readControlPlaneCredential(settingsDir(base), settings.controlPlane);
    const mode = credential === null ? 'none' : attachmentModeOf(credential);
    const scope = parseAttachmentScope(settings.attachmentScope);
    const enrolled =
      scope?.endpoint === endpoint
        ? scope.entries.map((entry) => `${entry.kind}\u0000${entry.identity}`).sort()
        : [];
    return {
      ok: true,
      keys,
      endpointFingerprint: sightingKeyEndpointFingerprint(endpoint),
      scopeFingerprint: createHash('sha256')
        .update([mode, ...enrolled].join('\n'))
        .digest('hex'),
    };
  } catch {
    return { ok: false, outcome: { status: 'not-shared', reason: 'local-error' } };
  }
}

/** `child` as a posix path relative to `parent`, or undefined when it lies outside. */
function within(parent: string, child: string): string | undefined {
  const rel = relative(parent, child);
  if (rel === '') return '';
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return undefined;
  return rel.split(sep).join('/');
}

/**
 * The location class of `file`, or undefined for a file outside both the
 * project and the home directory's dotfiles.
 *
 * A path under a dot-entry of `home` is a home dotfile unless the project is a
 * directory below `home` that holds it, so a project kept in `~/.config/tool`
 * classes its own files as project files.
 */
export function sightingLocationClass(
  file: string,
  projectRoot: string,
  home: string,
): SightingLocationClass | undefined {
  const inProject = within(projectRoot, file);
  const fromHome = within(home, file);
  const projectHoldsHome = within(projectRoot, home) !== undefined;
  const homeEntry = fromHome?.split('/')[0];
  if (
    homeEntry !== undefined &&
    homeEntry.startsWith('.') &&
    (inProject === undefined || projectHoldsHome)
  ) {
    return 'home-dotfile';
  }
  if (inProject === undefined || inProject === '') return undefined;
  const directories = inProject.split('/').slice(0, -1);
  return directories.some((name) => name.startsWith('.'))
    ? 'project-dot-directory'
    : 'project-file';
}

export interface ForwardCredentialSightingsInput {
  project: SightingScanProject;
  sightings: readonly ScanSighting[];
}

export interface ForwardCredentialSightingsDeps extends SightingShareOptions {
  send: CredentialSightingsSend;
  /** The OS home directory; defaults to `homedir()`. */
  home?: string | undefined;
  now?: (() => Date) | undefined;
}

/** Whether a scoped attachment lets this sighting leave the machine. */
function inScope(
  resolved: ResolvedAttachmentScope,
  projectKey: string,
  sighting: ScanSighting,
): boolean {
  if (resolved.mode === 'machine') return true;
  return (
    scopeVerdict(resolved, scopeKeyOfProjectKey(projectKey)) === 'forward' &&
    scopeVerdict(resolved, sighting.scopeKey) === 'forward'
  );
}

// A sender that throws is read as a failed send, so the outer catch is left
// with faults on this machine.
async function sendBatch(
  send: CredentialSightingsSend,
  target: CredentialSightingsConnection,
  request: CredentialSightingsRequest,
): ReturnType<CredentialSightingsSend> {
  try {
    return await send(target, request);
  } catch {
    return { ok: false, kind: 'unreachable' };
  }
}

/**
 * Send a scan's sightings for one project. Sharing is read again here,
 * immediately before sending, and nothing is sent unless it is on. A scoped
 * attachment sends a sighting only when the project and the repository holding
 * the file are both enrolled. A value is sent once per location class.
 *
 * Batches go one after another; the first failure stops the rest, which the
 * next scan sends again. Never throws.
 */
export async function forwardCredentialSightings(
  base: string,
  input: ForwardCredentialSightingsInput,
  deps: ForwardCredentialSightingsDeps,
): Promise<CredentialSightingsOutcome> {
  let shared = 0;
  let keptLocal = 0;
  let pending = input.sightings.length;
  try {
    const sharing = readSightingSharing(base, deps.managedSettings);
    if (!sharing.sharing) return { status: 'not-shared', reason: 'sharing-off', sharing };
    if (deps.enabled === false) return { status: 'not-shared', reason: 'opt-out' };

    const settings = readWorkspaceSettings(base);
    const connection = settings.controlPlane;
    if (!isAttached(settings) || connection === undefined) {
      return { status: 'not-shared', reason: 'no-credential' };
    }
    const credential = readControlPlaneCredential(settingsDir(base), connection);
    if (credential === null) return { status: 'not-shared', reason: 'no-credential' };

    const resolved = resolveScope({
      mode: attachmentModeOf(credential),
      scope: settings.attachmentScope,
      endpoint: connection.endpoint,
    });
    const { project } = input;
    const wireProject = { projectKey: hashProjectKey(project.projectKey), name: project.name };
    const superseded = supersededProjectKeys(project.projectKey);
    const home = deps.home ?? homedir();
    const seenAt = (deps.now ?? (() => new Date()))().toISOString();
    const isTracked = createTrackedFileLookup();

    const byKey = new Map<string, CredentialSighting>();
    const keptKeys = new Set<string>();
    for (const sighting of input.sightings) {
      const locationClass = sightingLocationClass(sighting.file, project.root, home);
      if (locationClass === undefined || !inScope(resolved, project.projectKey, sighting)) {
        keptKeys.add(`${sighting.token}\u0000${locationClass ?? ''}`);
        keptLocal = keptKeys.size;
        continue;
      }
      const gitTracked = isTracked(sighting.file);
      const key = `${sighting.token}\u0000${locationClass}`;
      const seen = byKey.get(key);
      if (seen !== undefined) {
        seen.gitTracked ||= gitTracked;
        if (seen.variableName === undefined && sighting.variableName) {
          seen.variableName = sighting.variableName;
        }
        continue;
      }
      byKey.set(key, {
        token: sighting.token,
        ...(sighting.aliases?.length ? { aliases: sighting.aliases } : {}),
        ruleId: sighting.ruleId,
        category: 'secret',
        ...(sighting.variableName ? { variableName: sighting.variableName } : {}),
        locationClass,
        project: wireProject,
        gitTracked,
        seenAt,
      });
    }

    const wire = [...byKey.values()];
    pending = wire.length;
    const scanId = randomUUID();
    const target = { endpoint: connection.endpoint, apiKey: credential.apiKey };
    for (let start = 0; start < wire.length; start += CREDENTIAL_SIGHTINGS_BATCH_MAX) {
      const batch = wire.slice(start, start + CREDENTIAL_SIGHTINGS_BATCH_MAX);
      const result = await sendBatch(deps.send, target, {
        sightings: batch,
        scanId,
        supersededProjectKeys: superseded,
      });
      if (!result.ok) {
        return { status: 'sent', shared, keptLocal, unsent: pending, failure: result.kind };
      }
      shared += batch.length;
      pending -= batch.length;
    }
    return { status: 'sent', shared, keptLocal, unsent: 0 };
  } catch {
    return shared === 0
      ? { status: 'not-shared', reason: 'local-error' }
      : { status: 'sent', shared, keptLocal, unsent: pending, failure: 'unreachable' };
  }
}
