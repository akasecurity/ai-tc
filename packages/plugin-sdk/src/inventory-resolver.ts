import { arch, hostname, platform, release } from 'node:os';

import type { InventoryContext, InventoryInput, SourceProjectInput } from '@akasecurity/schema';

import { resolveRepoIdentity } from './repo.ts';

/**
 * Inputs the adapter threads in per session. `cwd` + `tool` come from the hook;
 * the harness build version and interface are descriptive (Part F: `interface`
 * stays in the bag, never hashed, so an `unknown` value can't fork the harness
 * dimension).
 */
export interface ResolveInventoryInput {
  cwd: string;
  // The harness tool the identity hashes on, e.g. 'claude-code'.
  tool: string;
  harnessVersion?: string | undefined;
  harnessInterface?: string | undefined;
}

/**
 * Resolve a session's {@link InventoryContext} — the host/harness/project
 * machine-and-repo facts `DataGateway.ensureInventory` upserts. Pure + fail-open
 * in spirit: `node:os` for the host, the existing git-config reader for the
 * project (no `git` spawn, no `process.env`). Only the *identity* attributes
 * drive each content-addressed id; volatile values (os_version, harness_version)
 * ride in the bag and are snapshotted onto the audit fact at capture, so an
 * upgrade can't fork the dimension.
 *
 * The User/Account dimension is deliberately NOT resolved here: the writer
 * adds it — `LocalDatabase.ensureInventory` derives it from the local
 * identity.
 */
export function resolveInventoryContext(input: ResolveInventoryInput): InventoryContext {
  const host: InventoryInput = {
    objectType: 'host',
    // Stable-ish machine id; os/arch live in the descriptive bag (a
    // harder machine id can replace this without a schema change).
    identityKey: hostname(),
    title: hostname(),
    attributes: { host_name: hostname(), os: platform(), os_version: release(), arch: arch() },
  };

  const harnessAttributes: Record<string, unknown> = {};
  if (input.harnessVersion != null) harnessAttributes.harness_version = input.harnessVersion;
  if (input.harnessInterface != null) harnessAttributes.interface = input.harnessInterface;
  const harness: InventoryInput = {
    objectType: 'harness',
    identityKey: input.tool,
    title: input.tool,
    attributes: harnessAttributes,
  };

  const ctx: InventoryContext = { host, harness };

  const repo = resolveRepoIdentity(input.cwd);
  if (repo) {
    const project: SourceProjectInput = { url: repo.url, name: repo.name, attributes: {} };
    ctx.project = project;
  }
  return ctx;
}
