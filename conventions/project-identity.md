### 8. A project's identity is the repository, not the remote string

**`canonicalGitUrl` is the ONE reduction, and all three identities go through
it**: the project id (`sourceProjectId`), the scope key (`canonicalRepoUrl`) and
the wire digest (`hashProjectKey`). One repository is cloned in spellings that
share no bytes — scp-style and HTTPS, with and without `.git`, any case of the
host — so a reduction applied to one of those and not the others gives one
repository several identities, differently on each surface.

Keeping them unified is not tidiness. A scope key is matched against what a user
enrolled by EXACT STRING (`resolved.keys.has(key)`), so a key that splits per
spelling is a security-control failure, not a display bug: an organization
enrols `github.com/acme/app`, a developer whose clone keys any other way
matches nothing, forwards nothing — and the repository still reads as enrolled.
Nothing reports the gap. The same split makes every
org-wide count a fraction of the truth, leaves policy bound to one spelling, and
lets `syncLaneRetentionOf` expire bodies it should have held.

Two rules hold it together, and one deliberate NON-rule:

- **Transport is not identity.** `canonicalGitUrl` drops the scheme, any
  userinfo and any port, lowercases the host and strips a trailing `.git` and
  trailing slashes. The PATH's case is folded only on a host in
  `CASE_INSENSITIVE_FORGES` (the public github.com / gitlab.com /
  bitbucket.org), because the two errors are not symmetric: on GitHub
  `acme/App` and `acme/app` are one repository and keeping the case splits it,
  while on a case-sensitive self-hosted git they are two and folding blends
  their egress invisibly. An unrecognised host — a GitHub Enterprise instance
  included, since no hostname says what answers it — keeps its case and misses
  the convergence, which is the visible failure rather than the silent one.
- **The reduction is PURE, and an SSH `Host` alias is therefore NOT resolved.**
  `github-personal` is `github.com` only because a line in `~/.ssh/config` says
  so, and that mapping exists on the machine and nowhere else — the control
  plane receives the remote as written (`inventoryForWire` sends `project.url`
  through `remoteWithoutCredentials`), so it could never derive it. Resolving it
  on the machine or not at all is the whole choice, and for now it is not done:
  a clone made through an alias keys to the alias and shows up as its own
  project. That is convergence MISSED, which is the direction this section
  prefers to fail in — two entries a human can reconcile rather than two
  repositories merged into one.

  **It is a BUILD constraint, not an oversight, and it is why nothing here may
  read a file.** The web dashboard compiles `@akasecurity/persistence` as its
  own source (Next's `transpilePackages`), so a module reached from the
  reduction that reads a home-rooted path goes into that build. One that did
  broke the `win32-x64` binary build on every run — listing the Windows user
  profile hits the legacy `Application Data` junction and raises EPERM during
  `next build` — while `pnpm lint`, `pnpm typecheck` and every vitest suite
  stayed green, so nothing but that one CI job noticed. Proven by experiment:
  removing the single import edge and nothing else took all four platforms
  green, and MOVING the import rather than removing it did not help. Resolving
  aliases therefore needs the map handed in by callers that are not in the
  dashboard's graph — `resolveRepoIdentity` reaches local-ops and scanner, both
  of which the dashboard imports, so it is a change across three packages'
  public APIs. Tracked separately. Do not re-add a file read here to get it.

- **The remote picked is an ADDRESS where one exists.** git does not guarantee
  `origin` names a forge: a submodule checked out inside a linked worktree gets
  an `origin` pointing at the parent repository's gitdir on local disk, with the
  real URL on a second remote. `remoteUrl` prefers a remote
  `namesARemoteAddress` accepts, falling back to `origin` and then to the first
  remote — a preference, not a filter, so a repository whose only remote is a
  local path still gets it.

**Changing what `sourceProjectId` hashes RE-KEYS every existing row, and that is
handled rather than incidental.** `reconcileSourceProjectIds` runs on every store
open, folds any row whose stored id no longer equals the current answer into the
canonical row, and repoints `audit_events`, `share_call_site`, `project_file` and
`file_access_override` first. A future change to the reduction inherits that
sweep; one made without it would strand every row in the store.

The rows it CANNOT fold are the gitdir-path identities the `origin` defect
minted, because nothing in SQL can tell which repository a local directory was a
clone of. Those are handled from both ends instead.
`resolveSupersededProjectUrls` reads one back out of the checkout's own config
and the SessionStart and scan passes hand it to `reconcileWorktreeProjects`.
**AT MOST ONE, and only the remote the OLD resolver picked** (`origin`, else the
first in config order), never the other local-path remotes beside it: one the
old resolver did not pick was never this checkout's identity, and it is very
likely another repository's — a sibling added as `git remote add scratch
~/src/scratch` keys on exactly that path, so handing it over would delete a LIVE
project and repoint its events, on every session in the first repository. Nor
one that is still the identity, which a checkout whose only remote is a local
path has.

`GHOST_PROJECT_FILTER` is the backstop for a checkout deleted before a session
next runs in it, and it is scoped to a PER-WORKTREE gitdir
(`<repo>/.git/worktrees/…`) rather than to `.git/` at large. The shared
`<repo>/.git/modules/<name>` is a legitimate identity — a submodule whose only
remote is that path keys on it, new events attach to it, and it reads the same
from every worktree — so hiding it would leave a project being written to that
no read surface can reach, which is worse than the duplicate it removes.

**Bumping `PROJECT_KEY_DIGEST_VERSION` also re-keys the RECEIVING side, and the
wire says how to fold it.** Every forward carries `supersededProjectKeys`: the
same key's digest under each earlier version, computed by
`supersededProjectKeys` from `EARLIER_PROJECT_KEY_DIGESTS` in `repo-key.ts`. A
receiver files rows it holds under any of them under the current digest. A bump
therefore adds the outgoing version to that table, with the canonical form it
used — a digest cannot be reversed, so a version left out of the table strands
every row filed under it.

**The ENROLMENT LIST is matched byte for byte, so a re-key has to MOVE it.**
`AttachmentScopeEntry.identity` is a plain string (`scopeVerdict` is
`keys.has(key)`), so an entry left under a spelling the canonical form has moved
away from reads as enrolled and enrolls nothing — with no error anywhere, since
nothing on either side can tell "not enrolled" from "enrolled under a key no
checkout stamps". `respellStoredEnrolments` is the sweep that closes it,
`respellAttachmentScopeEntries` the raw-record edit under it, and
`respelledRepoKey` the one reading of a near miss that it and `aka enroll`'s
refusal SHARE — the sweep's whole job is to write what that refusal would have
named, so two copies of the rule would be free to disagree. Six properties are
load-bearing:

- **It is IDEMPOTENT by construction, not by a marker.** `respelledRepoKey`
  answers `undefined` for a key that is already canonical, so a swept record has
  nothing left to do and the editor hands `raw` itself back. That is why it
  carries no window of its own, unlike the jobs beside it in the sync child, each
  of which bounds how stale something is allowed to get.
- **TWO reads, and the outer one is only a GATE.** `applyOnboarding` writes
  whatever its updater returns and stamps `onboardedAt` while it is there, so
  reaching it per pass would rewrite `settings.json` for ever and mark a machine
  that never onboarded as onboarded. The edit that LANDS is derived again inside
  the lock, through the updater, because a read-modify-write whose read sits
  outside the lock is §6's lost update exactly. Getting the gate wrong therefore
  costs one skipped pass and never an answer.
- **It takes no endpoint**, unlike its neighbours in `attachment-scope-edit.ts`:
  those act for a user command aimed at a deployment, while a stale spelling
  matches nothing whichever deployment the record names. Skipping a record for a
  deployment the machine has left would only re-key it the day it attached back.
- **A respelling that collides is FOLDED, never duplicated**, and the entry that
  was already canonical wins wherever it sits — it carries the label and
  timestamp set under the spelling that works. A duplicate forwards identically,
  reads double on `aka status`, and would leave `aka unenroll` removing one copy
  while the other went on forwarding. A duplicate the record ALREADY held is not
  the sweep's to remove.
- **An identity it cannot re-key is LEFT for `aka status` to name.** That is
  still the reporting surface, and the two now divide cleanly: the sweep fixes
  what converges, and `staleKeyNote` names what does not — an identity that is
  not `enrollableRepoKey`'s own answer is one no checkout here stamps. Caching a
  guess instead would file the enrolment under a second key nothing stamps
  either. Two shapes reach it: a `repo` identity that respells to nothing
  enrollable (an owner's page), and one carrying a transport, where prefixing
  `ssh://` would read a port or an scp path as part of the host.
- **Everything else in the record is copied as found** — the binding, the
  work-subscription opt-out, a key a newer build put on the envelope, an
  `account` entry, an entry whose kind this build does not know, and an entry it
  cannot read at all. That is `attachment-scope-edit.ts`'s whole convention and
  the sweep is no exception to it.

What this does NOT do is reach a machine that is not attached: the sweep runs
from the detached sync child, which only an attached machine spawns. That is the
right scope — a scope record forwards nothing until there is an attachment — but
it means the fix arrives with the next session's sync rather than the moment the
build is installed.

**A near miss is REPORTED rather than silently stored.** `aka enroll` refuses a
typed key that is not how the repository is really keyed and names the spelling
that is — a capitalised path on a folding forge (`github.com/Acme/App` → "its
key is `github.com/acme/app`"), a trailing slash, a `.git` suffix. That matters
because the failure it prevents is invisible: an enrolment nothing produces
reports no error, forwards nothing and still lists the repository as covered.
`respelledRepoKey` is the one reading of such a near miss, SHARED with the
stored-enrolment sweep below, whose whole job is to write what this refusal
would have named.

**What this still does not reach.** A clone made through an SSH `Host` alias
keys to the alias, for the build reason given above. A path whose case differs
on a host NOT in the forge list — a self-hosted GitHub Enterprise most
obviously — keys as two. A repository RENAMED on the forge keys as two, because
the key is a path rather than the forge's immutable id, which no hook can ask
for without a network call. All three are convergence that is MISSED, which
shows up as two entries a human can reconcile, rather than two repositories
merged into one —
the direction this whole section prefers to fail in.
