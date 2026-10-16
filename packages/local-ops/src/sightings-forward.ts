import { sep } from 'node:path';

import type {
  CredentialSightingsSend,
  ScanSighting,
  SightingScanProject,
} from '@akasecurity/persistence';
import { forwardCredentialSightings, scopeKeyOfProjectKey } from '@akasecurity/persistence';
import type { CredentialSightingsOutcome, ManagedSettings } from '@akasecurity/schema';

import type { ScanPathResult } from './fs-scan.ts';
import { resolveScanProject } from './scan-project.ts';
import { nestedRepositoryKey } from './shares-forward.ts';

export interface ScanSightingsDeps {
  send: CredentialSightingsSend;
  /** Replaces the managed settings file; `null` reads a machine with no administrator. */
  managedSettings?: ManagedSettings | null | undefined;
  /** False skips sharing for this run. */
  enabled?: boolean | undefined;
}

function scanProject(target: string): SightingScanProject {
  const { projectKey, name, root } = resolveScanProject(target);
  return { projectKey, name, root };
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
    return { status: 'not-shared', reason: 'local-error' };
  }
}
