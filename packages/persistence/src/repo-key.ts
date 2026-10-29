// How a repository is KEYED: the one reduction every identity on this machine
// goes through, and the rules a key a user typed is judged by.
//
// Split out of ./egress-wire.ts, which re-exports all of it, for a reason that
// is structural rather than tidy. That module also builds the wire payload, so
// it imports a SQLite repository for the cap helpers — and a parameter property
// in that repository is syntax Node's strip-only TypeScript loader refuses. Any
// module reached by a raw-Node child or worker that needs to canonicalize a key
// would therefore fail at LOAD, the moment it imported one. Keeping the string
// work here, with nothing under it but `@akasecurity/schema`, is what makes the
// canonicalization reachable from those paths.
//
// PURE for a second reason, and it is a constraint rather than a preference:
// the web dashboard compiles `@akasecurity/persistence` as its own source
// (Next's `transpilePackages`), so a module reached from here that reads a
// home-rooted path goes into that build. One that did broke the Windows binary
// build outright — listing the user profile hits the legacy `Application Data`
// junction and raises EPERM — on every run, while lint, typecheck and every
// test suite stayed green. Nothing here may read a file.
import { createHash } from 'node:crypto';

import {
  ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH,
  printable,
  SUPERSEDED_PROJECT_KEYS_MAX,
} from '@akasecurity/schema';

/**
 * The shape of the string that is digested, stamped into the digest itself.
 *
 * Without it a later change to the canonicalization below is INVISIBLE: every
 * device silently moves to a new digest, history stays under the old one, and
 * nothing on either side can tell the two apart or say which rule produced a
 * given hash. With it, a future revision is a different version and the
 * difference is legible.
 *
 * Bumping it re-buckets every project on the receiving side, so it moves only
 * when the canonical form itself does.
 *
 * v2 → v3: a path is now folded on a host in `CASE_INSENSITIVE_FORGES`, so a
 * repository cloned as `acme/App` and as `acme/app` digests to one value where
 * it used to digest to two. That is exactly the case the paragraph above
 * refuses to leave unversioned.
 */
export const PROJECT_KEY_DIGEST_VERSION = 'v3';

/**
 * Each earlier digest version, newest first, and whether its canonical form
 * folded a path's case on a host in `CASE_INSENSITIVE_FORGES`. Every other
 * rule of the reduction is the same in each of them.
 */
const EARLIER_PROJECT_KEY_DIGESTS: readonly {
  readonly version: string;
  readonly foldsForgePathCase: boolean;
}[] = [{ version: 'v2', foldsForgePathCase: false }];

// A `git:` URL in scp form — `[user@]host:path`, which has no `://` and whose
// first colon separates host from path. Anchored on a host that cannot contain
// `/`, so a `path:`-style absolute path is never mistaken for one.
const SCP_FORM = /^(?:[^@/]+@)?([^/:]+):(.+)$/;

// A Windows drive prefix, which scp form cannot be told from by shape alone:
// `C:/Users/dev/demo` parses as host `C` and path `Users/dev/demo`.
//
// It has to be excluded because a `git:` key does NOT always carry a remote. A
// repository with no remote falls back to its worktree ROOT PATH, and both
// producers keep the `git:` prefix on that fallback — so on Windows this was
// handed an absolute path and canonicalized it: lowercasing the drive and, far
// worse, stripping a trailing `.git`, so `…/demo` and `…/demo.git` digested to
// ONE project. That is the silent merge the docblock below calls the worse
// error, produced from a value that was never a remote at all.
//
// Git draws this same line for this same reason — its own URL parser excludes a
// DOS drive prefix from scp-like syntax. A local path is returned untouched,
// exactly as a `path:` key is: it never converges across devices, so there is
// nothing to canonicalize it toward.
const DOS_DRIVE = /^[A-Za-z]:[\\/]/;

// A `file://` URL, which names a repository by a path on ONE machine — the
// remote `git clone file:///srv/repos/demo.git` records. It is returned
// untouched for the reason a drive path is: it never converges across devices,
// and the trailing-`.git` strip would merge `…/demo` and `…/demo.git` into one
// project. Neither form below reads it correctly on its own: with the usual
// empty authority (`file:///…`) scheme form misses it, since its host needs a
// character, and scp form then takes `file` as the host; with an authority
// (`file://localhost/…`) scheme form reads that authority as a forge host.
//
// Only the `://` spelling is a file URL. `file:acme/widgets` is scp form against
// a host named `file`, exactly as git reads it, and still canonicalizes.
const FILE_URL = /^file:\/\//i;
const SCHEME_FORM = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]+@)?([^/:]+)(?::\d+)?(\/.*)?$/i;

const SLASH = '/'.charCodeAt(0);
const GIT_SUFFIX = '.git';

/**
 * A path with its leading and trailing `/` runs removed.
 *
 * Written as a scan rather than as `/^\/+/` and `/\/+$/` because the trailing
 * form is QUADRATIC in a slash run that does not reach the end of the string:
 * the anchor fails after consuming the whole run, and the engine retries from
 * every position inside it. Measured on an arm64 Mac against `a` + n slashes +
 * `b` — 30ms at n=10,000, 114ms at 20,000, 450ms at 40,000, 11.5s at 200,000,
 * i.e. exactly 4x the cost for 2x the input.
 *
 * That is reachable rather than theoretical. This runs on the remote URL of
 * whatever repository the scanner was pointed at, read out of that repository's
 * own git config, so its length is chosen by whoever wrote the clone — and the
 * two callers are `aka scan` and the dashboard's folder-scan Server Action,
 * which has no harness timeout at all.
 */
function trimSlashes(path: string): string {
  let start = 0;
  let end = path.length;
  while (start < end && path.charCodeAt(start) === SLASH) start += 1;
  while (end > start && path.charCodeAt(end - 1) === SLASH) end -= 1;
  return path.slice(start, end);
}

/**
 * The two halves of a remote URL that every clone of one repository shares —
 * the host, lowercased, and the path with its slash runs and a trailing `.git`
 * removed — or `undefined` when the string is not a remote at all: a Windows
 * drive path, a `file://` URL, or a shape neither form recognizes, which is
 * where every POSIX path lands.
 *
 * ONE parse behind both readers of a remote, so the digest and the scope key
 * cannot disagree about what a remote is. They differ only in what they make of
 * the result. `canonicalGitUrl` passes a non-remote through, trimmed, as a
 * stable identity for one machine's project, and digests every remote it gets.
 * `canonicalRepoUrl` refuses a non-remote, and also a remote whose key would
 * name no repository or could not be enrolled. The rules themselves are the
 * ones `canonicalGitUrl` documents below.
 */
export function parseGitRemote(
  url: string,
): { readonly host: string; readonly path: string } | undefined {
  return parseRemote(url, true);
}

function parseRemote(
  url: string,
  foldsForgePathCase: boolean,
): { readonly host: string; readonly path: string } | undefined {
  const trimmed = url.trim();
  if (DOS_DRIVE.test(trimmed) || FILE_URL.test(trimmed)) return undefined;
  const scheme = SCHEME_FORM.exec(trimmed);
  const scp = scheme === null ? SCP_FORM.exec(trimmed) : null;
  const host = (scheme?.[1] ?? scp?.[1])?.toLowerCase();
  if (host === undefined) return undefined;
  const bare = trimSlashes((scheme === null ? scp?.[2] : scheme[2]) ?? '');
  const path = bare.endsWith(GIT_SUFFIX) ? bare.slice(0, -GIT_SUFFIX.length) : bare;
  const folds = foldsForgePathCase && CASE_INSENSITIVE_FORGES.has(host);
  return { host, path: folds ? path.toLowerCase() : path };
}

/**
 * Hosts that treat a repository path case-insensitively, so two clones
 * differing only in case are one repository and must reduce to one identity.
 *
 * An ALLOWLIST rather than a rule, because the cost of being wrong runs one
 * way only: fold a case a host really distinguishes and two repositories share
 * an identity, which blends their egress with nothing to notice it; keep a case
 * a host ignores and one repository shows up twice, which a human can see and
 * reconcile. So a host goes in here only where the behaviour is known.
 *
 * It is the PUBLIC instance that is listed. A self-hosted GitHub Enterprise or
 * GitLab is case-insensitive too and is NOT covered, because nothing in a
 * hostname says which software answers it — those keep their case and miss the
 * convergence, which is the safe side of the same trade.
 */
const CASE_INSENSITIVE_FORGES: ReadonlySet<string> = new Set([
  'github.com',
  'gitlab.com',
  'bitbucket.org',
]);

/**
 * Whether `url` names a REMOTE ADDRESS — a host and a path every clone shares —
 * rather than a location on this machine. False for a POSIX path, a Windows
 * drive path and a `file://` URL.
 *
 * The caller this exists for is remote SELECTION. git does not guarantee that
 * `origin` names a forge: a submodule checked out inside a linked worktree gets
 * an `origin` pointing at the parent repository's gitdir on local disk, while
 * the real forge URL sits on a second remote. Keying a project on the first of
 * those makes a machine-local directory the repository's identity, which can
 * never converge with any other clone and renders as a project named after the
 * submodule directory.
 */
export function namesARemoteAddress(url: string): boolean {
  return parseGitRemote(url) !== undefined;
}

/**
 * One repository's remote URL reduced to the form every clone of it shares.
 *
 * The same repository is cloned four ways that produce four different strings —
 * scp-style, HTTPS with `.git`, HTTPS without it, and any case variant of the
 * host — and digesting those raw gives one repository four identities, which is
 * the opposite of what the digest exists for.
 *
 * What is normalized, and why only this much:
 *   - the transport scheme and any userinfo are dropped. `git@`/`https://` say
 *     how a clone authenticates, not which repository it is.
 *   - the host is lowercased. DNS is case-insensitive by definition, so this
 *     cannot merge two different hosts.
 *   - any port is dropped, whether or not it is the scheme's default. One
 *     repository is reached over SSH on one port and HTTPS on another, so
 *     keeping it would split every repository cloned both ways. The cost is
 *     that two different forges on one host, told apart only by port, share a
 *     digest. Scp form carries no port — its colon is the path separator.
 *   - a trailing `.git` and trailing slashes go. Both are spellings of the
 *     same remote.
 *
 * The PATH's case is folded ONLY on a host known to treat it
 * case-insensitively (`CASE_INSENSITIVE_FORGES`). Forges differ, and the two
 * errors are not symmetric: on GitHub `acme/App` and `acme/app` are one
 * repository, so keeping the case splits it; on a self-hosted git over a
 * case-sensitive filesystem they are two, so folding the case silently blends
 * two repositories' egress into one. Folding is therefore allowed exactly
 * where it is known to be true and nowhere else — an unrecognised host keeps
 * its case and simply misses the convergence, which shows up as two projects a
 * human can reconcile rather than as a collision nobody can see.
 *
 * A string that matches neither form is returned trimmed and otherwise as-is.
 * It is still a stable identity for whatever produced it; it simply does not
 * get the convergence, which is better than guessing at a shape this does not
 * recognize. A local path is returned the same way even where it would match
 * one — a Windows drive path, or a `file://` URL — because it is a location on
 * one machine rather than a remote every clone shares.
 */
export function canonicalGitUrl(url: string): string {
  return canonicalUnder(url, true);
}

function canonicalUnder(url: string, foldsForgePathCase: boolean): string {
  const remote = parseRemote(url, foldsForgePathCase);
  if (remote === undefined) return url.trim();
  return remote.path === '' ? remote.host : `${remote.host}/${remote.path}`;
}

function digestUnder(version: string, projectKey: string, foldsForgePathCase: boolean): string {
  const canonical = projectKey.startsWith('git:')
    ? `git:${canonicalUnder(projectKey.slice('git:'.length), foldsForgePathCase)}`
    : projectKey;
  return createHash('sha256').update(`${version}:${canonical}`, 'utf8').digest('hex');
}

/**
 * Digest a local `projectKey` for the wire.
 *
 * Unsalted SHA-256 over the version, the prefix and the canonical key, rendered
 * as 64 lowercase hex characters. The `git:` / `path:` prefix is part of the
 * input — there is no digest that drops it — which is what keeps `git:X` and
 * `path:X` from aliasing, while the canonicalization above is what lets the
 * same `git:` identity converge across every device that scanned it.
 *
 * Only a `git:` key is canonicalized. A `path:` key is a local filesystem path:
 * it never converges across devices (that is the whole reason a repo with a
 * remote is keyed by the remote), and case-folding it would merge two real
 * directories on the case-sensitive filesystems where most of them live.
 *
 * WHAT THIS DOES NOT BUY. The digest is for stable cross-device identity, not
 * concealment. Its inputs are low-entropy and enumerable — a repo URL, or a
 * local filesystem path — so anyone holding the digests recovers the plaintext
 * by hashing a candidate list. It keeps an absolute `path:` root (which on macOS
 * embeds an OS username) out of request logs and off the wire in front of a
 * passive observer; it does not hide it from the deployment receiving it.
 *
 * That trade is deliberate. The org running the control plane is entitled to
 * know which repos its own devices scanned, and `site.file` crosses in plaintext
 * anyway. But do not upgrade this in place if concealment from the RECIPIENT is
 * ever wanted: that needs a keyed construction (HMAC under a per-tenant secret),
 * and a per-tenant key destroys the cross-device convergence above. It is a
 * contract change, not a one-line swap here.
 */
export function hashProjectKey(projectKey: string): string {
  return digestUnder(PROJECT_KEY_DIGEST_VERSION, projectKey, true);
}

/**
 * The digests `projectKey` had under each earlier `PROJECT_KEY_DIGEST_VERSION`,
 * newest first, each computed with that version's own canonical form, and
 * never the current digest. A receiver that stored rows under one of them
 * files those rows under `hashProjectKey(projectKey)`.
 *
 * Every key has one: the version is part of the digested string, so even a
 * key whose canonical form did not change digests differently under each
 * version.
 */
export function supersededProjectKeys(projectKey: string): string[] {
  const current = hashProjectKey(projectKey);
  const digests: string[] = [];
  for (const { version, foldsForgePathCase } of EARLIER_PROJECT_KEY_DIGESTS) {
    const digest = digestUnder(version, projectKey, foldsForgePathCase);
    if (digest !== current && !digests.includes(digest)) digests.push(digest);
  }
  return digests.slice(0, SUPERSEDED_PROJECT_KEYS_MAX);
}

/**
 * The shape every scope key has: the shape a scope entry's identity has, at
 * most ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH characters and none of them a
 * control or format character. Built once; `canonicalRepoUrl` checks each key it
 * returns against it.
 */
const SCOPE_KEY = printable(ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);

// What makes a string a URL rather than an scp-style remote: a scheme and `://`.
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

// The userinfo `parseGitRemote` skips: what its optional `[^@/]+@` group takes at
// the start of the authority (scheme form) or of the string (scp form), which is
// everything up to the first `@` when no `/` comes first.
const SKIPPED_USERINFO = /^([^@/]+)@/;

// A character that ends a URL's authority before git gets as far as an `@`.
const ENDS_AUTHORITY = /[?#\\]/;

// A plain host name: letters, digits, dot, underscore and hyphen, and nothing
// else. The hyphen and underscore keep an ssh config alias such as
// `github.com-personal` valid. The parse lowercases the host, so the capitals
// are here for the reader, not for a value that reaches it.
const PLAIN_HOST = /^[A-Za-z0-9._-]+$/;

// A query or a fragment, which no repository's identity includes.
const QUERY_OR_FRAGMENT = /[?#]/;

/**
 * Whether the host `parseGitRemote` read out of this remote is the one git would
 * contact: a plain host name, and judged also on what the parse skipped on the
 * way to it. KEY ONLY: the digest has no such refusal and hashes whatever the
 * parse produced.
 *
 * The parse takes any `[^@/]+@` prefix as userinfo, then any run of characters
 * but `/` and `:` as the host, and when the URL form does not match it falls back
 * to scp form. A string git reads differently then names a host it would never
 * contact, and a key built from it could be matched against an enrolled
 * repository on a host that checkout does not talk to. Four shapes:
 *
 *   - a host that is not a plain host name: one with any character outside
 *     letters, digits, dot, underscore and hyphen. The parse puts no limit on
 *     what the host holds, so a `?`, `#` or `\` (each ends a URL's authority, so
 *     git contacts the text in front of it), an `@` (a second userinfo separator,
 *     or one with nothing on a side of it) or a control character can sit in it.
 *     An ssh config alias such as `github.com-personal` is plain and keeps its
 *     key. A host written with non-ASCII characters is not plain and gets no key;
 *     its punycode spelling is, and does. A bracketed IPv6 literal gets none
 *     either, as it did before.
 *   - a URL whose skipped userinfo holds a `?`, `#` or `\`. Each ends the
 *     authority before the `@`, so git's request goes to the host in front of
 *     that character, and what follows the `@` is a query or a fragment.
 *   - an scp remote whose skipped userinfo holds a `:`. Git takes everything
 *     before the first colon as the host, so it ssh-connects to the text in
 *     front of that colon and reads the rest, `@` and all, as the path.
 *   - a string that begins with a URL scheme but fits no URL form the parse
 *     reads: a bracketed IPv6 host, a non-numeric port. Those fall through to scp
 *     form, which keeps the scheme as the host and the userinfo, a password
 *     included, in the path, so the key would carry it.
 *
 * The userinfo is the text before the first `@`, which is what the parse's group
 * takes whenever it takes anything. It can refuse one scp remote the parse read
 * no userinfo from: a colon in front of an `@` inside the first path segment.
 * That costs a key and forwards nothing, which is the safe side of the choice.
 */
function namesTheHostGitContacts(url: string, host: string): boolean {
  if (!PLAIN_HOST.test(host)) return false;
  const trimmed = url.trim();
  const scheme = URL_SCHEME.exec(trimmed);
  if (scheme === null) {
    const userinfo = SKIPPED_USERINFO.exec(trimmed)?.[1];
    return !userinfo?.includes(':');
  }
  if (!SCHEME_FORM.test(trimmed)) return false;
  const userinfo = SKIPPED_USERINFO.exec(trimmed.slice(scheme[0].length))?.[1];
  return userinfo === undefined || !ENDS_AUTHORITY.test(userinfo);
}

/**
 * A repository's identity as a scope key: `host/path`, the canonical form
 * above, or `undefined` when the URL names no remote every clone shares.
 *
 * The digest and the key want OPPOSITE things from a value that is not a
 * remote. The digest keeps it, trimmed, because a stable identity for one
 * machine's project is still worth having. A scope key must not: it is matched
 * against what a user enrolled, and every machine-local spelling — a POSIX or
 * Windows worktree path, which is what a repository with no remote resolves to;
 * a `file://` URL; a relative path remote — would let a repository with no
 * shared identity be enrolled by where it happens to sit on one disk. Those are
 * `undefined`, and scopeVerdict keeps an event with no key local on a scoped
 * attachment.
 *
 * A host with no path is `undefined` too: `github.com` names a forge, not a
 * repository, and enrolling it would enroll every repository on it.
 *
 * So is a remote whose host is not one git would contact as the parse read it,
 * which `namesTheHostGitContacts` judges. The host must be a plain host name —
 * letters, digits, dot, underscore and hyphen — so a `?`, `#`, backslash, `@` or
 * control character inside it gives no key, and so does a host spelled in
 * non-ASCII characters (its punycode spelling keys). The userinfo the parse
 * skipped is judged too: a `?`, `#` or backslash in a URL's, or a colon in an scp
 * remote's, means git reads a different host. A string that begins with a URL
 * scheme but fits no URL form the parse reads, such as a bracketed IPv6 host or a
 * non-numeric port, gets none, rather than being re-read as scp form.
 *
 * So is a path with a query or a fragment in it, a `?` or `#` anywhere in the
 * path. Neither is part of a repository's identity. A query can carry a token,
 * which a key would then store, stamp on each capture and print wherever a scope
 * is listed; and a fragment would give one repository a second key. The refusal
 * is on the character, whatever follows it.
 *
 * So is a key that is not printable: longer than the cap a scope entry's
 * identity has, or carrying a control or format character. Whoever wrote a
 * repository's git config chose every byte of its remote, and a key is meant to
 * be stamped on each capture, compared against what a user enrolled and printed
 * wherever a scope is listed. The rule is the one `AttachmentScopeEntry.identity`
 * has, from the same exported cap, so every key returned here is one a user could
 * enroll, and a key nobody could enroll is never handed on to be stored, compared
 * or rendered. The check lives here rather than with each caller, so every
 * producer of a key draws the line in the same place, however it found the
 * remote. The digest has no such limit and keeps hashing whatever the parse
 * produced.
 *
 * The port is not part of the key, and that is deliberate. One repository is
 * commonly reached over ssh on one port and over https on another — ssh on 2222
 * and https on 443 behind the same host name — so a key that kept the port would
 * be two keys for it, an enrolled repository would forward or stay local
 * depending on how a checkout was cloned, and a user would have to enroll each
 * port separately. The cost is that two different git services on one host,
 * told apart only by port and serving the same org/repo path, share a key.
 * Converging every spelling of one repository matters more here than separating
 * those two, and it is the same trade the digest makes.
 *
 * Path case follows `canonicalGitUrl`: folded on a host known to ignore it,
 * kept everywhere else. Keys are compared byte-exact (scopeVerdict is a set
 * lookup), so two producers that built one key differently would disagree about
 * it — which is why the fold has to happen in the one shared parse and not at a
 * call site.
 *
 * A canonical key is not itself a remote — `github.com/acme/widgets` has neither
 * a scheme nor an scp colon — so it reads as `undefined` here. A caller holding a
 * key a user typed validates it by its own rule rather than feeding it back
 * through this.
 */
export function canonicalRepoUrl(url: string): string | undefined {
  const remote = parseGitRemote(url);
  if (remote === undefined || !namesTheHostGitContacts(url, remote.host)) return undefined;
  // The `.git` strip leaves the slash in front of a `/.git` directory behind, so
  // a path read `org/repo/` there. The digest keeps that, and must; the key does
  // not, or it would read a second key for the repository `org/repo` names.
  const path = trimSlashes(remote.path);
  if (path === '' || QUERY_OR_FRAGMENT.test(path)) return undefined;
  const key = `${remote.host}/${path}`;
  return SCOPE_KEY.safeParse(key).success ? key : undefined;
}

// One label of a host name an enrollable key may carry: a letter, digit or
// underscore at each end, hyphens allowed between. `canonicalRepoUrl` has
// already lowercased the host, so lowercase is all that can arrive.
const ENROLLABLE_HOST_LABEL = /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/;

/**
 * Whether a key `canonicalRepoUrl` produced names a repository a user could mean
 * to enroll: a host made of real labels, then at least two path segments, none
 * of them empty, `.` or `..`.
 */
function isEnrollableKey(key: string): boolean {
  const [host = '', ...path] = key.split('/');
  if (!host.split('.').every((label) => ENROLLABLE_HOST_LABEL.test(label))) return false;
  if (path.length < 2) return false;
  return path.every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

/**
 * The scope key to store for a repository a user names by hand — a clone URL, or
 * a canonical key typed as it is stored — or `undefined` when what they typed is
 * neither, or names no repository.
 *
 * A clone URL (https, ssh://, scp-style, with or without `.git`) goes through
 * `canonicalRepoUrl`, the rule every producer of a key uses, so a key stored
 * from one is the one a checkout of that repository stamps on its events. Not
 * every key a checkout stamps can be named here, though: the rules below refuse
 * some, a key with one path segment among them.
 *
 * A typed key is accepted only when it is ALREADY canonical:
 * `canonicalRepoUrl('ssh://' + key)` must give back exactly the key. Keys are
 * compared byte for byte, so a key that is almost canonical — a capitalised
 * host, a trailing slash, a `.git` suffix — would look like a key and match
 * nothing a checkout stamps. It is refused rather than repaired, so the
 * difference is visible instead of silently rewritten. That covers path case on
 * a case-insensitive forge too: `github.com/Acme/Payments` is REFUSED, naming
 * `github.com/acme/payments` as the key, since that is what a checkout stamps.
 * On a host not in `CASE_INSENSITIVE_FORGES` the case is significant and a
 * capitalised path is accepted as itself.
 *
 * Either way, a key that names no repository is refused:
 *   - a host not made of real labels: `.`, `..` or `-` (which is how a typed
 *     relative path such as `./payments-api` reads), an empty label (a
 *     trailing-dot host such as `github.com.` names the same host as
 *     `github.com` and would be a second key for it), or a label that begins or
 *     ends with a hyphen;
 *   - fewer than two path segments, from a clone URL as well as from a typed
 *     key. From the text alone a repository kept at the top of its host cannot
 *     be told from an owner: `git@git.example.com:payments.git` keys as
 *     `git.example.com/payments` and names a repository, while
 *     `https://github.com/acme` keys as `github.com/acme` and names an owner.
 *     Accepting the second would store a key no repository cloned from GitHub
 *     carries, and report it as an enrollment. A caller enrolling a repository
 *     kept at the top of its host takes the key its checkout resolves for
 *     itself;
 *   - an empty, `.` or `..` path segment.
 *
 * An absolute path, a Windows path, a `file://` URL, a query or fragment, a
 * control character and an over-long key are refused too: `canonicalRepoUrl`
 * gives no key for them. Surrounding whitespace is ignored.
 *
 * THIS DOES NOT REFUSE EVERY LOCAL PATH. A relative path that begins with `./`,
 * `../` or `-` is refused by the host rule above, but a bare relative path of
 * three or more segments can be accepted, for example `src/acme/payments-api`:
 * it is indistinguishable from a key whose host has no dot. A caller must refuse
 * text that names an existing local directory before calling this.
 *
 * For a repository named by hand only. A key a checkout resolved for itself is
 * already a producer's key and is not re-judged by this. Pure; no I/O.
 */
export function enrollableRepoKey(input: string): string | undefined {
  const value = input.trim();
  // `ssh://`, not `https://`. A TYPED key names no transport, so it is judged
  // under the rule a CHECKOUT's key is built with, and the scp form is what a
  // bare `host/owner/repo` reads as. The two schemes answer alike for every
  // spelling this reduction converges today — the reduction is pure, so no
  // transport is privileged — and ssh is kept because that is the form a key
  // mirrors. The scheme is a probe here and reaches no network.
  const typed = canonicalRepoUrl(`ssh://${value}`) === value ? value : undefined;
  const key = canonicalRepoUrl(value) ?? typed;
  return key !== undefined && isEnrollableKey(key) ? key : undefined;
}

/**
 * The key a repository stored under the spelling `input` is keyed by NOW, when
 * that differs from the spelling itself — and `undefined` when the spelling is
 * already the key, or names nothing this build can key.
 *
 * This is the one reading of a near miss, and both callers that need one share
 * it: `aka enroll`, whose refusal names the spelling a typed key should have
 * had, and the stored-enrolment sweep, which rewrites one. Two copies of the
 * rule would be free to disagree about which spellings converge, and the
 * sweep's job is precisely to write what enroll's refusal would have named.
 *
 * `ssh://`, for the reason `enrollableRepoKey` gives: a key names no transport,
 * and an scp-form spelling is the one a key reads as. Text carrying a `:` is left alone —
 * it is a clone URL rather than a key, `enrollableRepoKey` already judges it
 * whole, and prefixing a scheme onto it would read its port or its scp path as
 * part of the host. The answer is always enrollable, so a spelling only ever
 * converges onto a key a checkout could stamp.
 *
 * It is never an alternative reading of a key that already stands: an
 * enrollable key is its own canonical form, so this answers `undefined` for
 * every one of them and the two functions cannot disagree. That is what makes a
 * sweep built on it idempotent — a second pass finds nothing to do. Pure; no
 * I/O — `parseGitRemote` reads nothing, and nothing here may.
 */
export function respelledRepoKey(input: string): string | undefined {
  const value = input.trim();
  if (value.includes(':')) return undefined;
  const respelled = canonicalRepoUrl(`ssh://${value}`);
  if (respelled === undefined || respelled === value) return undefined;
  return enrollableRepoKey(respelled) === respelled ? respelled : undefined;
}

/**
 * The scope key of a scan's pre-hash `projectKey`: the canonical repository of a
 * `git:` key's remote, and `undefined` for anything else.
 *
 * A `path:` key is a directory with no remote. So is a `git:` key whose suffix
 * is a worktree path — both producers keep the `git:` prefix on the no-remote
 * fallback — and `canonicalRepoUrl` refuses that suffix. The prefix match is
 * case-sensitive, exactly as `hashProjectKey`'s is, so the two never read one
 * key two ways.
 */
export function scopeKeyOfProjectKey(projectKey: string): string | undefined {
  return projectKey.startsWith('git:')
    ? canonicalRepoUrl(projectKey.slice('git:'.length))
    : undefined;
}
