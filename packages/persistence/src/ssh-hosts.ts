import { readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';

/**
 * Resolve an SSH `Host` alias to the real `HostName` the way git itself does,
 * by reading the user's `~/.ssh/config`.
 *
 * WHY THIS EXISTS. A clone made through an alias and one made over HTTPS name
 * the same repository with different hosts — `git@github-personal:acme/app`
 * against `https://github.com/acme/app` — and from the URL text alone the two
 * are as different as GitHub and GitLab. Without this the two clones are two
 * projects for ever, which is the duplicate a user sees on the Inventory page.
 * The alias is not guessable: `github-personal` resolves to `github.com` only
 * because a line in that file says so.
 *
 * WHAT IS READ, AND ONLY THIS. `Host` and `HostName` keywords. No key is read,
 * no `IdentityFile` path is kept, nothing else in the file is retained, and the
 * values never leave the local store — the mapping is used to compute a project
 * identity and then dropped. `Include` directives are followed, because a config
 * split across `~/.ssh/config.d/*` is ordinary, and a host answered from an
 * include is exactly as real as one answered inline.
 *
 * Same pure-file-I/O, never-spawns, never-throws contract as the git resolvers
 * in `@akasecurity/plugin-sdk`: this sits behind the capture path, so any
 * failure — no file, no permission, a malformed line — answers "no alias" and
 * the host is used as written. Failing to merge two projects is recoverable;
 * breaking a capture is not.
 */

// Only a literal, pattern-free alias is stored. A pattern (`*`, `?`, `!`) is
// matched by ssh against hosts this cannot enumerate, and nothing here
// implements that matching: lookup is an exact map hit, so a `Host *` entry
// would sit under the literal key `*` and answer only a host spelled `*`. That
// exact lookup — not this filter — is what keeps a wildcard block from
// rewriting every repository on the machine.
//
// The filter is what stops a pattern being stored AS IF it were a literal host,
// which is the narrower error it can actually make: a remote whose host really
// is `*` or `git?hub.com` would otherwise be rewritten by a block that was
// never about it. Dropping it at parse time also keeps the map to entries that
// mean what a lookup assumes they mean, so a later reader cannot mistake one
// for a host.
const PATTERN_CHARS = /[*?!]/;

// `Include` is resolved relative to `~/.ssh` when the path is relative, which is
// what ssh_config(5) specifies for a user config. Bounded so a cycle of includes
// (a file including itself, directly or through a chain) cannot spin.
const MAX_INCLUDE_DEPTH = 16;

// One parse per process. The map is small (a handful of aliases) and the file is
// read on the capture path, so re-reading it per project resolution would be a
// file read per event. The price is staleness: an alias added after the first
// read is not seen until the next process, which for a hook is the next event.
let cached: ReadonlyMap<string, string> | undefined;

// A PINNED map, which is read instead of the file when it is set. Test-only.
let pinned: ReadonlyMap<string, string> | undefined;

// The config to parse INSTEAD of `~/.ssh/config`. Test-only: a suite about the
// parser cannot reach the real path by mocking `node:os`, because a setup file
// imports this module before any test file registers a mock, so the binding it
// caches is the real `homedir`. A path seam needs no mock at all.
let configPathOverride: string | undefined;

/**
 * The real host for `host`, or `host` itself when it names no literal alias.
 * Lowercased on both sides: ssh matches a `Host` alias case-insensitively, and
 * DNS is case-insensitive by definition, so this cannot merge two real hosts.
 */
export function resolveSshHost(host: string): string {
  try {
    const lower = host.toLowerCase();
    const aliases = pinned ?? (cached ??= readSshHostAliases());
    return aliases.get(lower) ?? lower;
  } catch {
    return host.toLowerCase();
  }
}

/**
 * TEST-ONLY. Pin the alias map, so nothing reads `~/.ssh/config`; `null` drops
 * the pin and the next resolution reads the file again.
 *
 * WHY THIS EXISTS. `~/.ssh/config` is an absolute path outside `~/.aka` that a
 * temp home does not redirect, so without a pin every suite that computes a
 * project id or a scope key would depend on whose laptop it ran on — a
 * developer with `Host github.com` in their config would see a different key
 * than CI, which has no config at all. `test/setup/no-ssh-aliases.ts` pins an
 * empty map for every package, the same way `no-managed-settings.ts` declares
 * the machine has no administrator, and for the same reason.
 *
 * A CHILD PROCESS is outside it, exactly as it is outside the managed-settings
 * pin: the pin lives in one process's copy of this module, and a spawned hook
 * loads its own with no pin set.
 */
export function UNSAFE_TEST_ONLY_setSshHostAliases(
  aliases: ReadonlyMap<string, string> | null,
): void {
  pinned = aliases ?? undefined;
  cached = undefined;
}

/**
 * TEST-ONLY. Parse `path` instead of `~/.ssh/config`; `null` restores the real
 * one. For the suite that tests the PARSER, which cannot redirect the real path
 * by mocking `node:os`: the setup file above imports this module before any test
 * file registers a mock, so the `homedir` binding is already the real one by
 * then. Dropping the pin alone is not enough — the path has to move too.
 */
export function UNSAFE_TEST_ONLY_setSshConfigPath(path: string | null): void {
  configPathOverride = path ?? undefined;
  cached = undefined;
}

// alias -> real host, for every literal single-alias `Host` block carrying a
// `HostName`. A block naming several aliases maps each of them.
function readSshHostAliases(): ReadonlyMap<string, string> {
  const map = new Map<string, string>();
  const root = configPathOverride ?? join(homedir(), '.ssh', 'config');
  parseInto(map, root, dirname(root), 0, new Set());
  return map;
}

function parseInto(
  map: Map<string, string>,
  file: string,
  base: string,
  depth: number,
  seen: Set<string>,
): void {
  if (depth > MAX_INCLUDE_DEPTH || seen.has(file)) return;
  seen.add(file);
  const text = safeRead(file);
  if (text === undefined) return;
  // Aliases of the `Host` block being read. ssh applies the FIRST `HostName`
  // that matches, so a later block for the same alias does not override an
  // earlier one — `map.set` is guarded accordingly.
  let aliases: string[] = [];
  for (const raw of text.split('\n')) {
    // ssh_config comments run from `#` to end of line.
    const line = raw.split('#', 1)[0]?.trim() ?? '';
    if (line === '') continue;
    // `Keyword value`, or `Keyword = value`. Keywords are case-insensitive.
    const match = /^(\w+)\s*=?\s*(.*)$/.exec(line);
    const keyword = match?.[1]?.toLowerCase();
    const value = match?.[2]?.trim() ?? '';
    if (keyword === undefined || value === '') continue;
    if (keyword === 'host') {
      aliases = value
        .split(/\s+/)
        .filter((a) => a !== '' && !PATTERN_CHARS.test(a))
        .map((a) => a.toLowerCase());
      continue;
    }
    if (keyword === 'hostname') {
      const real = value.split(/\s+/)[0]?.toLowerCase();
      // A `HostName` carrying a token (`%h`, `%%`) is a template ssh expands per
      // connection, not a host — honouring one would key the project on a string
      // no clone resolves to.
      if (real !== undefined && real !== '' && !real.includes('%')) {
        for (const alias of aliases) if (!map.has(alias)) map.set(alias, real);
      }
      continue;
    }
    if (keyword === 'include') {
      // A `Host` block does not continue across an `Include` in a way this needs
      // to model: the included file's own `Host` lines set the scope there.
      for (const spec of value.split(/\s+/)) {
        if (spec === '') continue;
        const expanded = spec.startsWith('~/') ? join(homedir(), spec.slice(2)) : spec;
        const resolved = isAbsolute(expanded) ? expanded : join(base, expanded);
        for (const target of expandGlob(resolved)) {
          parseInto(map, target, dirname(target), depth + 1, seen);
        }
      }
    }
  }
}

// `Include` accepts a glob. Only the single-directory `*` form is expanded —
// the shape `~/.ssh/config.d/*` takes — by listing the directory. Anything else
// is treated as a literal path, which reads it when it exists and is a no-op
// when it does not.
function expandGlob(spec: string): string[] {
  if (!spec.includes('*')) return [spec];
  const dir = dirname(spec);
  const pattern = spec.slice(dir.length + 1);
  if (pattern.includes('/') || !/^[^*]*\*[^*]*$/.test(pattern)) return [];
  const [prefix = '', suffix = ''] = pattern.split('*');
  let entries: string[];
  try {
    entries = readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isFile() || e.isSymbolicLink())
      .map((e) => e.name);
  } catch {
    return [];
  }
  return entries
    .filter((name) => name.length >= prefix.length + suffix.length)
    .filter((name) => name.startsWith(prefix) && name.endsWith(suffix))
    .sort()
    .map((name) => join(dir, name));
}

function safeRead(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}
