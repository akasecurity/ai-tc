### 6. Every writer of `settings.json` takes its lock

`writeOwnerOnlyFileSync`'s tmp+rename makes each PUBLISH indivisible. It does not make a
**read-modify-write** indivisible, and that is the shape every settings write has: read the file,
merge answers over it, rename the result. The plugin, the CLI and the dashboard are three separate
processes over one home, so two of them read the same bytes and the second rename discards the
first one's answers — with both reporting success, because neither ever learns the other existed.

`withFileLock` (`packages/persistence/src/file-lock.ts`) is the section around that pair. It is the
existence of a sibling `<file>.lock`, taken with an exclusive create — `flock` has no Windows
equivalent, and an fd-held lock is lost by any writer that opens the file a second time. Seven
properties are load-bearing:

- **It is ADVISORY, and it is scoped to one file.** A writer that skips it is not excluded by the
  ones that take it, so the guarantee is only as wide as the set of writers holding it. Two
  writers hold it today: `applyOnboarding` (which the `/aka:setup` wizard and the dashboard's
  Settings action both go through) and `aka init`'s create-if-absent. A third that writes
  `settings.json` directly reopens the hole for both. **Other `~/.aka` files are NOT covered** —
  `fingerprint.ts`'s key ROTATION and `local-ops`' `update-cache.ts` are unlocked
  read-modify-writes with the same shape, and each is its own outstanding fix.
  `plugin-sdk`'s `host-floor.ts` (`data/host-version.json`) is a third, and is the one
  that is NOT owed a fix — though not because it self-heals, which it does NOT. Its
  max-keeping loses the race that matters: two sessions reading `null` both pass the
  comparison, and the loser PERSISTS, because the only caller sits behind a
  once-per-session claim it keeps, so the winner never writes again. What earns the
  exemption is the BLAST RADIUS rather than the duration — nothing on the hook path
  reads that file, so a stale value costs a wrong line on `aka status` and
  /aka:health, pull surfaces somebody is reading because they are already debugging.
  `plugin-sdk`'s `hook-fail-opens.ts` (`data/hook-fail-opens.json`) is a fourth, and it
  holds the same exemption on its own account rather than by being listed here: it is
  written only after a hook has already failed open, and nothing but `aka status` renders
  it, as a count that already says "at least". A fifth writer does not inherit that by
  being on this list, and a file any enforcement path READS would not qualify for it at
  all. The first MINT
  is no longer one of them, and it was not fixed with a lock: `createKeyFile` publishes through
  `createOwnerOnlyFileSync`, which links an already-complete tmp into place, so exactly one
  caller wins and every loser reads the file back and ADOPTS the winner's key. That works only
  because a first mint has nothing to preserve — rotation must replace an existing file, so it
  still reads the current version and writes version+1 over it, and the same fix does not reach
  it. Do not read this section as a property the store has; it is a property `settings.json`
  has.
- **An ADMINISTRATIVE overlay is read, never written, and that is what keeps the writer count at
  two.** `managed-settings.ts` reads a root-owned file outside `~/.aka` that an MDM or
  config-management tool owns — `/Library/Application Support/AKASecurity` then
  `/Library/Managed Preferences` on macOS (FIRST READABLE WINS, so the order is part of the
  contract, not a detail), `%ProgramData%\AKASecurity` on Windows, `/etc/aka` on Linux. AKA overlays what it finds — `readEffectiveSettings` returns the settings in force
  plus the locked set — and writes it never. Making AKA a writer of it would be the third
  `settings.json`-class writer this section exists to prevent, on a file the lock does not cover.
  Three consequences. A pinned VALUE and a LOCK are separable: a value with no lock is a default
  the user may still change, a lock with no value freezes whatever they last chose — with one
  exception the writer cannot see: a pinned CONNECTION (`runMode` / `controlPlane`) is written
  through and then overlaid straight back on the next read, so both surfaces that change it —
  `aka attach` / `aka detach` and the dashboard's attach and detach Settings actions — refuse to
  move away from it ahead of every side effect, deciding against the effective settings rather
  than the lock list. That decision is ONE copy, `packages/persistence/src/managed-connection.ts`,
  worded by `connectionRefusalMessage` in `@akasecurity/schema`, and the Settings page withholds
  the controls it would refuse from the same call. What an attach under such a pin leaves in the
  user's file is judged one half at a time: an echo of the pinned mode is stripped like any other
  echo, but the descriptor the attach writes is kept even where it matches the pin, because it
  records what the pin cannot — when this machine enrolled, and what the user called the
  deployment. A descriptor without the mode is not an attachment, so once the pin is gone the
  machine is in the mode the user last chose, holding that record — never attached on the
  strength of an echo. A locked field
  is refused inside the lock (`ManagedFieldError`), by THROWING rather than dropping the key and
  writing the rest — a half-applied save reports success while losing the answer the user cared
  about, which is this section's whole failure mode. And a damaged managed file leaves the machine
  UNMANAGED rather than refusing to run, because a typo in an MDM payload must not break every
  hook on every managed machine at once; that direction is deliberate and stated in the module.
  One shape is deliberately NOT damage: a lock naming a key this build does not know is dropped
  from the locked set and reported (`unknownLockedFields`), never a reason to run unmanaged.
  That is what an older build sees when an administrator locks a key a newer build added, and
  refusing the whole file there cost it every pin and lock it understood, on exactly the fleets
  most likely to carry a version skew. A name outside the enum is still never honoured.
- **Anything derived from the current file is derived INSIDE it.** `applyOnboarding` takes an
  updater function for exactly this: a caller that reads first and passes a plain object has put
  its read outside the lock and kept the lost update, one frame further out. The dashboard's
  vault-consent carry-forward is the worked example — read outside, it writes a grant back over a
  concurrent revoke.
- **It fails loudly rather than writing unlocked.** The fields at stake include the vault and
  model-judge consent grants, so the write that goes missing can be a REVOCATION. A refused save
  the user retries beats a silent one they never learn about.
- **A killed holder must not wedge the file, and a slow one must not be evicted.** Taking an
  abandoned lock needs BOTH that its own recorded acquire clock is older than the stale window and
  that the pid it names is gone. Age alone evicts a holder that is merely suspended or throttled,
  which puts two writers in the section — the defect, reintroduced by its own recovery. The clock
  is read from the lock BODY, never from mtime, which on a network home is the file server's clock
  and drifts a fresh lock straight into staleness. `FileLockError.reason` separates `timeout`
  (contention) from `unavailable` (a directory that will never hold a lock); `aka init` branches on
  it, swallowing the first — another writer is already creating the file — and propagating the
  second, which is the fault its pre-lock write raised too.
- **A release must prove it still owns the lock.** Each acquisition writes a token and removes the
  file only while that token is still there — an unreadable body counts as somebody else's, since
  a lock exists for an instant between its exclusive create and its body write. Unlinking by path
  alone means a holder that was stolen from deletes its successor's lock, and the section is
  unguarded while that successor is mid-write, every writer reporting success.
- **Recovering an abandoned lock is itself a critical section**, held by a second exclusive file.
  Several waiters meet the same dead lock at once; unserialised they all judge it stale, one
  removes it and takes a fresh lock, and the next one's removal lands on THAT. Neither a rename
  nor a re-read closes it — every check is separated from its removal by a window another waiter
  acts in, and a rename that has to be undone clobbers whatever took the path meanwhile. Measured
  at 5 of 12 trials losing an update with eight waiters over one abandoned lock; zero once the
  judging and the removal became one section.

`packages/persistence/test/concurrency/settings-race.test.ts` is what holds this: real child
processes, released together on a readiness handshake, asserting no answer is lost and no
revocation is resurrected. It uses processes rather than worker threads deliberately — a worker
shares `process.pid`, and the atomic write's tmp path is per-process, so two threads meet a
collision two processes never can, which is the wrong axis.
