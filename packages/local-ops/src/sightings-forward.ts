import { statSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';

import { manifestKindOf } from '@akasecurity/detections';
import type {
  CredentialSightingsSend,
  ScanSighting,
  SightingScanProject,
} from '@akasecurity/persistence';
import { forwardCredentialSightings, scopeKeyOfProjectKey } from '@akasecurity/persistence';
import {
  resolveNonGitProject,
  resolveRepoIdentity,
  resolveWorktreeRoot,
} from '@akasecurity/plugin-sdk';
import type { CredentialSightingsOutcome, ManagedSettings } from '@akasecurity/schema';

import type { ScanPathResult } from './fs-scan.ts';
import { nestedRepositoryKey } from './shares-forward.ts';

export interface ScanSightingsDeps {
  send: CredentialSightingsSend;
  /** Replaces the managed settings file; `null` reads a machine with no administrator. */
  managedSettings?: ManagedSettings | null | undefined;
  /** False skips sharing for this run. */
  enabled?: boolean | undefined;
}

/**
 * The project a scan of `target` belongs to, resolved the way the Data Shares
 * record resolves it: the git working tree and its remote identity, else the
 * nearest directory carrying a dependency manifest.
 */
function scanProject(target: string): SightingScanProject {
  const abs = resolve(target);
  const identity = resolveRepoIdentity(abs);
  const worktreeRoot = resolveWorktreeRoot(abs);
  if (identity && worktreeRoot) {
    return {
      projectKey: `git:${identity.url}`,
      name: identity.name,
      root: worktreeRoot,
    };
  }
  const dir = statSync(abs).isDirectory() ? abs : dirname(abs);
  const { root, projectKey, project } = resolveNonGitProject(dir, manifestKindOf);
  return { projectKey, name: project, root };
}

/** Each sighting with the scope key of the repository holding its file. */
function withScopeKeys(
  sightings: readonly ScanSighting[],
  projectKey: string,
  nestedRepositories: readonly string[],
): ScanSighting[] {
  const projectScopeKey = scopeKeyOfProjectKey(projectKey);
  const deepestFirst = [...new Set(nestedRepositories)].sort((a, b) => b.length - a.length);
  const keys = new Map<string, string | undefined>();
  const keyOf = (dir: string): string | undefined => {
    if (!keys.has(dir)) keys.set(dir, nestedRepositoryKey(dir));
    return keys.get(dir);
  };
  return sightings.map((sighting) => {
    const holder = deepestFirst.find((dir) => sighting.file.startsWith(`${dir}${sep}`));
    return { ...sighting, scopeKey: holder === undefined ? projectScopeKey : keyOf(holder) };
  });
}

/**
 * Send the credential sightings a scan of `target` found, for the AKA home
 * `base`. Never throws: a scan's result never depends on this send.
 */
export async function forwardScanSightings(
  base: string,
  target: string,
  result: Pick<ScanPathResult, 'sightings' | 'nestedRepositories'>,
  deps: ScanSightingsDeps,
): Promise<CredentialSightingsOutcome> {
  try {
    const project = scanProject(target);
    return await forwardCredentialSightings(
      base,
      {
        project,
        sightings: withScopeKeys(result.sightings, project.projectKey, result.nestedRepositories),
      },
      deps,
    );
  } catch {
    return {
      status: 'sent',
      shared: 0,
      keptLocal: 0,
      unsent: result.sightings.length,
      failure: 'unreachable',
    };
  }
}
