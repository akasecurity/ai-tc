import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { printable } from '@akasecurity/schema';

import type { AgentPlugin } from './registry.ts';
// `semver.ts` imports nothing from this module, so reaching for it here keeps
// the LEAF property the header below protects.
import { isExactSemver } from './semver.ts';

// A range is carried as EVIDENCE and printed verbatim by every caller —
// `update-render.ts`'s CLI table and the dashboard's update card — so it gets
// the same guarantee `printable` gives every other string this tree writes
// into a terminal or a page (`@akasecurity/schema`'s control-plane shapes).
// The manifest is the host's own file, but it is unpacked from a cloned
// repository rather than typed by the user, so a control character, a
// newline or an ANSI escape in it is third-party text landing on a surface
// whose whole point is that what it prints is true.
const MAX_RANGE_LENGTH = 200;
const printableRange = printable(MAX_RANGE_LENGTH);

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
 * What a marketplace manifest's `source.version` field decides.
 *
 * `version` is the comparable answer — orderable against npm's own latest,
 * and what a caller installs. `range` is EVIDENCE rather than a comparable
 * value: present only when the manifest names something a report cannot
 * compare (a semver RANGE such as `^2.0.0`, or a dist-tag) — `version` is then
 * null, and a null `version` with no `range` means there is no pin at all.
 * Collapsing "a range" into "no pin" was the defect: a bounded range that
 * excludes npm's latest then read as unpinned, offered npm's answer as an
 * update, and re-nagged on every run once the host installed within the
 * range instead.
 */
export interface MarketplacePinLookup {
  version: string | null;
  range?: string;
}

const NO_PIN: MarketplacePinLookup = { version: null };

/**
 * What a marketplace manifest pins an agent's plugin to.
 *
 * `{ version: null }` covers every way this can fail to produce an ANSWER —
 * the agent is not hosted by Claude Code, it carries no marketplace
 * coordinates, the marketplace is not registered, the manifest is absent or
 * damaged, the plugin is not listed, or its entry carries no version (or an
 * empty one). That is deliberate rather than lazy: an entry with no pin is the
 * shape a `github` or `git-subdir` source really has, and for those the host
 * does follow the published head, so npm's latest is the right answer and the
 * caller falls back to it.
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
): MarketplacePinLookup {
  if (agent.cliBin !== 'claude') return NO_PIN;
  const { marketplace, pluginName } = agent;
  if (marketplace === undefined || pluginName === undefined) return NO_PIN;
  const root = marketplaceRoot(claudeHome, marketplace);
  if (root === null) return NO_PIN;
  const manifest = readJson(join(root, '.claude-plugin', 'marketplace.json'));
  if (!isRecord(manifest) || !Array.isArray(manifest.plugins)) return NO_PIN;
  const entry = manifest.plugins.find(
    (candidate): candidate is Record<string, unknown> =>
      isRecord(candidate) && candidate.name === pluginName,
  );
  if (entry === undefined || !isRecord(entry.source)) return NO_PIN;
  const version = entry.source.version;
  if (typeof version !== 'string' || version.trim() === '') return NO_PIN;
  // An EXACT version is the comparable answer. `isExactSemver` — not the
  // looser `isSemver`, which trims — because a padded pin (` 0.9.12 `) is not
  // usable as-is either: it is the same "not a single orderable version" case
  // as a range, carried as evidence rather than silently trimmed and accepted.
  //
  // Anything else is a RANGE (`^2.0.0`, `~1.2.3`) or a dist-tag (`beta`,
  // `latest`), and neither is something this report can compare:
  // compareSemver returns 0 for anything it cannot parse, so a range used to
  // be reported as `Latest: ^0.11.0-beta.0` with `updateAvailable` false for
  // ever — a row that could never move and never said why. Carrying it as
  // `range` instead lets the caller explain the pin rather than mistake it for
  // none at all — which is what let the row offer npm's own latest as an
  // update a host resolving within the range would never install.
  //
  // A range that fails `printableRange` reads as no pin rather than as
  // sanitized evidence: nothing distinguishes "a genuine range with stray
  // bytes" from a hostile one at this point, and half of this function's own
  // job is deciding what is safe to carry forward — a value already this
  // corrupted is not something a caller can act on either way.
  if (isExactSemver(version)) return { version };
  return printableRange.safeParse(version).success ? { version: null, range: version } : NO_PIN;
}
