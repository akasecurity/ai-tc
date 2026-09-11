import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { AgentPlugin } from './registry.ts';

// What the HOST will actually install, read from the marketplace manifest it
// resolved — as distinct from what npm has published.
//
// `aka update` decided whether an update existed by asking npm, while
// `claude plugin install` / `plugin update` resolve through the marketplace
// manifest, whose entries name an exact version. Nothing reconciled the two, so
// the report could offer an update the host structurally cannot deliver: a
// consent prompt promising a state change that cannot happen, and — where a
// marketplace is registered at a pinned ref — one that reappears on every run
// and no-ops every time.
//
// The two agree on the happy path, which is why this was latent. They come
// apart in the publish → manifest-bump window (two repositories, two commits),
// and indefinitely when a marketplace is registered against a branch or tag
// whose manifest holds an older pin.

// Its own guard rather than `updates.ts`'s `isRecord`, which is what keeps this
// module a LEAF: `updates.ts` has to import this one, so importing back would
// make a cycle out of a two-line type guard.
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Where the host records the marketplaces it knows and where each is unpacked. */
function knownMarketplacesPath(claudeHome: string): string {
  return join(claudeHome, 'plugins', 'known_marketplaces.json');
}

function readJson(path: string): unknown {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return undefined; // garbage on disk reads as "no pin", never as a throw
  }
}

/**
 * The directory a registered marketplace was unpacked into.
 *
 * Read from the host's own record rather than assembled from a convention. The
 * conventional layout — `<claudeHome>/plugins/marketplaces/<name>` — is what
 * this machine happens to use today, and a reader that assumed it would answer
 * confidently for a host that moved it. `installLocation` is the host stating
 * where it put the thing, so an unrecognised layout produces no answer instead
 * of a wrong one.
 */
function marketplaceRoot(claudeHome: string, marketplace: string): string | null {
  const known = readJson(knownMarketplacesPath(claudeHome));
  if (!isRecord(known)) return null;
  const entry = known[marketplace];
  if (!isRecord(entry)) return null;
  return typeof entry.installLocation === 'string' ? entry.installLocation : null;
}

/**
 * The version a marketplace manifest pins an agent's plugin to, or null.
 *
 * Null covers every way this can fail to produce an ANSWER — the agent is not
 * hosted by Claude Code, it carries no marketplace coordinates, the marketplace
 * is not registered, the manifest is absent or damaged, the plugin is not
 * listed, or its entry carries no version. That is deliberate rather than lazy:
 * an entry with no pin is the shape a `github` or `git-subdir` source really
 * has, and for those the host does follow the published head, so npm's latest is
 * the right answer and the caller falls back to it.
 *
 * THE HOST CHECK IS HERE rather than at the call sites, and that is the whole
 * reason this takes an agent instead of two strings. Everything below reads
 * CLAUDE CODE's layout, and every registered agent carries a marketplace and a
 * plugin name — the Codex entry's are `ai-tc` / `aka-codex`. A caller gating on
 * "are the coordinates present" therefore admits Codex into this reader, which
 * would answer it out of `~/.claude`'s ledger. That is inert today only because
 * no marketplace named `ai-tc` happens to be registered there, and dogfooding
 * both hosts against this repo is the obvious way to make it not inert.
 */
export function marketplacePinnedVersion(
  agent: AgentPlugin,
  claudeHome: string = join(homedir(), '.claude'),
): string | null {
  if (agent.cliBin !== 'claude') return null;
  const { marketplace, pluginName } = agent;
  if (marketplace === undefined || pluginName === undefined) return null;
  const root = marketplaceRoot(claudeHome, marketplace);
  if (root === null) return null;
  const manifest = readJson(join(root, '.claude-plugin', 'marketplace.json'));
  if (!isRecord(manifest) || !Array.isArray(manifest.plugins)) return null;
  const entry = manifest.plugins.find(
    (candidate): candidate is Record<string, unknown> =>
      isRecord(candidate) && candidate.name === pluginName,
  );
  if (entry === undefined || !isRecord(entry.source)) return null;
  const version = entry.source.version;
  return typeof version === 'string' && version !== '' ? version : null;
}
