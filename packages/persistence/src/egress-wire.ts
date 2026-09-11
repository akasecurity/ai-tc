// The device-side projection of a project's egress-recording unit onto the
// wire-boundary-safe shape every forwarding surface sends. This is the ONLY
// place that builds an `EgressIngestRequest` — no caller hand-rolls the
// payload, so the privacy boundary has exactly one implementation.
//
// It sits in this package, beside the cap helpers it applies, because the
// plugin gateways are not the only callers: the CLI and the dashboard record
// the same register and neither may depend on the plugin stack. A projection
// living above that line would have had to be written twice, and two copies of
// a privacy boundary is one copy too many.
import { createHash } from 'node:crypto';

import type {
  EgressIngestHit,
  EgressIngestRequest,
  RecordProjectEgressInput,
  ResolvedEgressHit,
} from '@akasecurity/schema';

import { capHits, withoutDroppedFiles } from './repositories/shares.ts';

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
 */
const PROJECT_KEY_DIGEST_VERSION = 'v2';

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
 *   - a trailing `.git` and trailing slashes go. Both are spellings of the
 *     same remote.
 *
 * The PATH's case is deliberately left alone. Forges differ — GitHub treats it
 * case-insensitively, a self-hosted git over a case-sensitive filesystem does
 * not — so lowercasing it would merge two genuinely different repositories on
 * the hosts that distinguish them. Merging identities is the worse error here
 * than failing to merge: convergence that is missed shows up as two projects a
 * human can reconcile, while a collision silently blends two repositories'
 * egress into one.
 *
 * A string that matches neither form is returned trimmed and otherwise as-is.
 * It is still a stable identity for whatever produced it; it simply does not
 * get the convergence, which is better than guessing at a shape this does not
 * recognize.
 */
function canonicalGitUrl(url: string): string {
  const trimmed = url.trim();
  if (DOS_DRIVE.test(trimmed)) return trimmed;
  const scheme = SCHEME_FORM.exec(trimmed);
  const scp = scheme === null ? SCP_FORM.exec(trimmed) : null;
  const host = (scheme?.[1] ?? scp?.[1])?.toLowerCase();
  if (host === undefined) return trimmed;
  const path = (scheme === null ? scp?.[2] : scheme[2]) ?? '';
  const bare = trimSlashes(path);
  const cleaned = bare.endsWith(GIT_SUFFIX) ? bare.slice(0, -GIT_SUFFIX.length) : bare;
  return cleaned === '' ? host : `${host}/${cleaned}`;
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
  const canonical = projectKey.startsWith('git:')
    ? `git:${canonicalGitUrl(projectKey.slice('git:'.length))}`
    : projectKey;
  return createHash('sha256')
    .update(`${PROJECT_KEY_DIGEST_VERSION}:${canonical}`, 'utf8')
    .digest('hex');
}

function toIngestHit(hit: ResolvedEgressHit): EgressIngestHit {
  return {
    host: hit.host,
    kind: hit.kind,
    name: hit.name,
    category: hit.category,
    trust: hit.trust,
    network: hit.network,
    method: hit.method,
    transport: hit.transport,
    url: hit.url,
    template: hit.template,
    dataClass: hit.dataClass,
    site: {
      file: hit.site.file,
      line: hit.site.line,
      dynamic: hit.site.dynamic,
      vendored: hit.site.vendored,
    },
  };
}

/**
 * Build the outbound ingest payload for one project's egress-recording unit.
 *
 * Applies the same per-project cap the local write enforces (`capHits`), drops
 * the corresponding files from the reconcile set (`withoutDroppedFiles`), then
 * strips everything that must not leave the device: `site.snippet` (source
 * text), the plaintext `projectKey` (replaced with its digest), and
 * `projectId` (a device-local id the tenant's inventory cannot resolve).
 */
export function toEgressIngestRequest(input: RecordProjectEgressInput): EgressIngestRequest {
  const { hits, droppedFiles } = capHits(input.hits, input.reconcile.mode);
  const reconcile = withoutDroppedFiles(input.reconcile, droppedFiles);
  return {
    projectKey: hashProjectKey(input.projectKey),
    project: input.project,
    reconcile,
    hits: hits.map(toIngestHit),
  };
}
