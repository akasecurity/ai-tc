# Security Policy

AI Traffic Control (`ai-tc`) is a security tool, and we take the security of the
project itself seriously.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report privately through GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab), or by email to
**security@akasecurity.io**.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- affected versions, and
- any suggested remediation.

We aim to acknowledge reports within **3 business days** and to provide a
remediation timeline after triage. Please give us a reasonable window to release a
fix before any public disclosure; we are happy to coordinate disclosure and to
credit reporters who wish to be named.

## Scope

In scope: the CLI, the local web dashboard, the Claude Code plugin, the detection
engine, and the built-in rule packs in this repository. The local store lives under
`~/.aka`; findings and audit records never contain raw secret/PII values (masked or
hashed only) — a report showing raw sensitive values reaching disk or the network is
in scope and appreciated.

## Data at rest

The local store under `~/.aka` holds a record of your agent activity — prompts,
responses, and tool calls. Only the spans a detection rule flags as sensitive are
masked; **everything else is stored verbatim and unencrypted**, so `aka.db`
accumulates a full local prompt corpus. It is protected by **filesystem
permissions, not encryption**. On macOS and Linux the store directories (`~/.aka`,
`~/.aka/data`, `~/.aka/settings`, `~/.aka/keys`) are created owner-only (`0700`)
and the files — `aka.db` and its `-wal`/`-shm`/`-journal` sidecars,
`exception.key`, `settings.json`, and `vault.key` — are written `0600`, so only
your user account can read them. These modes are the only at-rest control, so
treat a copy of the store (a backup, a synced folder, a stolen disk image) as
sensitive.

Which of those sidecars exist depends on how SQLite is journalling. `-wal` and
`-shm` are the pair it keeps in write-ahead logging, the mode it uses by default;
where WAL is unavailable it silently falls back to a rollback journal and writes
`-journal` instead — a DrvFs path such as `/mnt/c` under WSL, and some network
mounts, behave that way. Any of the three can hold store content, so `ai-tc`
tightens all three.

`vault.key` is the one file that is not a copy of your data but the means to read
it. If you consent to the secret vault, detected values are kept as recoverable
encrypted rows in `aka.db`, and this key is what decrypts them. It lives in its own
directory so that a backup or sync tool can exclude `~/.aka/keys/` and carry the
store without the means to open what is vaulted — that separation is the whole of
what encryption at rest buys here. The file appears only once vaulting is granted;
without that consent there is no key and no recoverable copy.

`ai-tc` also leaves copies of the store beside it: before a migration rewrites the
schema, or a recovery resets a store it cannot open, it snapshots `aka.db` to a
sibling `.bak` file. Where the store cannot be copied at all — a corrupt page, or
no room for a second copy — it moves the whole set aside instead, so that backup
carries its own `-wal`/`-shm`/`-journal` sidecars. Those copies hold the same
prompt corpus and are held at `0600` too.

A snapshot cut short part-way — a plugin hook killed at its timeout — leaves a
`.bak.partial` **directory** behind, holding as much of the copy as had been
written. That directory is created owner-only (`0700`) before the copy starts,
which is what protects the copy for the whole time it is being written: SQLite
refuses to write a copy over a file that already exists, so the copy itself
cannot be pre-created at `0600` and lands at the process umask (commonly `0644`)
until it is complete. Only the directory around it can cover that interval, and
it survives a kill exactly as the copy does. `ai-tc` clears an abandoned
`.bak.partial` **on the next open of the store**, once nothing has written to it
for five minutes — a copy another process has in flight is left alone. Treat a
`.bak.partial` under `~/.aka/data` as a full copy of the store, and delete one
that outlives the process that was writing it.

Those POSIX modes are a **no-op on Windows**: Node cannot apply them, so `ai-tc`
sets no at-rest protection there. On Windows the store simply inherits whatever ACL
its parent directory grants — by default a per-user profile path, but `ai-tc`
neither sets nor asserts any Windows ACL. **Treat the store as unprotected at rest
on Windows** and rely on full-disk encryption (e.g. BitLocker) or your own directory
ACLs.

A mode is never applied **through a symlink**. If a store path — `~/.aka` itself,
`~/.aka/data`, `~/.aka/settings`, `~/.aka/keys`, or any store file — is a symlink,
`ai-tc` leaves the target alone rather than changing the permissions of a directory
you may be sharing on purpose. Two consequences follow, and neither is obvious from
the outside, so `aka init` prints the link, what it resolves to, and the mode that
target currently carries:

- **The store keeps the target's own permissions**, which may be looser than `0700` —
  `aka init` says so explicitly when they are. Directories and files `ai-tc` creates
  _inside_ the target are still held owner-only.
- **The store is written inside the target** — including the prompt corpus in
  `aka.db`. A symlink pointing into a synced or shared folder puts that corpus there.
  This is reported on Windows too, where no mode is applied at all and where the
  redirection is the only at-rest fact left to report.

A store directory that is a symlink resolving **nowhere** is refused rather than
created through: `aka init` names the broken link and its missing target instead of
failing with a bare `ENOENT`. Plugin hooks are unaffected — they fall back to
unonboarded defaults, as they do for any home they cannot read.

## Supported versions

Security fixes target the latest released version. Please upgrade to the latest
release before reporting.
