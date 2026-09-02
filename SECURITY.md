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
`~/.aka`; a finding row never contains raw secret/PII values (masked or hashed
only), but the event content stored beside it does wherever the detection's policy
is below redact — see [Data at rest](#data-at-rest). That stored content is also
what an attached machine forwards, so below redact the value crosses the network
unmasked as well — see [Data in transit](#data-in-transit). A report showing raw
sensitive values reaching disk, or leaving the machine, where a redact or block
policy should have masked them is in scope and appreciated. The same values under
monitor or warn are the assigned policy doing what it says, not a vulnerability.

## Data at rest

The local store under `~/.aka` holds a record of your agent activity — prompts,
responses, and tool calls. What is masked in it follows the policy assigned to the
detection that flagged the span: a flagged span is masked at rest only where that
policy is redact or block. Under monitor or warn the value is stored as it was
seen, and **everything outside a flagged span is stored verbatim and unencrypted**
either way, so `aka.db` accumulates a full local prompt corpus. Every detection
ships on monitor, so **on a default install nothing in the store is masked at
all** — raw secrets included — until you promote a detection to redact or block,
which changes what is stored from then on and not what is already there. Files
read by `aka scan` are stored under the same rule. The store is protected by
**filesystem permissions, not encryption**. On macOS and Linux the store directories (`~/.aka`,
`~/.aka/data`, `~/.aka/settings`, `~/.aka/keys`) are created owner-only (`0700`)
and the files — `aka.db` and its `-wal`/`-shm`/`-journal` sidecars,
`control-plane-credential.json`, `exception.key`, `settings.json`, and
`vault.key` — are written `0600`, so only
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
it. Where you consent to the secret vault and assign a detection Redact & Vault,
its matched values are kept as recoverable encrypted rows in `aka.db`, and this
key is what decrypts them. The key lives in its own directory so that a backup or
sync tool can exclude `~/.aka/keys/` and carry the store without the means to open
what is vaulted — that separation is the whole of what encryption at rest buys
here. The file appears only once vaulting is granted; without that consent there is
no key and no recoverable copy, and with it a detection on any other policy is
still never vaulted.

`ai-tc` also leaves copies of the store beside it: before a migration that would
destroy rows, or on a recovery reset of a store it cannot open, it snapshots
`aka.db` to a sibling `.bak` file. Neither is routine, so a healthy store may
carry no `.bak` at all — a new install writes none, because the only migration
that destroys anything has nothing to destroy on a store it just created. Where
the store cannot be copied at all — a corrupt page, or no room for a second
copy — it moves the whole set aside instead, so that backup carries its own
`-wal`/`-shm`/`-journal` sidecars. Those copies hold the same
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
the outside, so both surfaces report it: `aka init` prints the link, what it resolves
to, and the mode that target currently carries, and the plugin hooks warn once per
session on stderr — a store that is merely redirected still opens, so the hooks
would otherwise run a whole session without ever mentioning it:

- **The store keeps the target's own permissions**, which may be looser than `0700` —
  `aka init` says so explicitly when they are. Directories and files `ai-tc` creates
  _inside_ the target are still held owner-only.
- **The store is written inside the target** — including the prompt corpus in
  `aka.db`. A symlink pointing into a synced or shared folder puts that corpus there.
  This is reported on Windows too, where no mode is applied at all and where the
  redirection is the only at-rest fact left to report.

A store directory that is a symlink resolving **nowhere** is refused rather than
created through: `aka init` names the broken link and its missing target instead of
failing with a bare `ENOENT`. A store path occupied by a regular file — or by a link
to one — is refused the same way rather than failing with a bare `EEXIST`. Plugin
hooks stay fail-open throughout: they fall back to unonboarded defaults, as they do
for any home they cannot read, and report the link on stderr without ever failing a
tool call over it.

## Data in transit

Detection and enforcement run on the machine, and while it is unattached the
store stays there; the narrow outbound paths a standalone install still has are
enumerated in the egress footnote in [README.md](README.md), and none of them
carry stored event content. `aka attach` is what sends it: it registers one
machine against a control plane **your organization runs**, never a service AKA
operates, and from then on the plugin forwards each captured event to that
deployment as it stored it.

That is the same content [Data at rest](#data-at-rest) describes, so the masking
rule is the same one: a flagged span is masked before the event is sent only
where the detection's policy is redact or block. **Under monitor or warn the
matched value — the secret itself — reaches that deployment exactly as it was
seen**, and everything outside a flagged span crosses either way. Every detection
ships on monitor, so on an attached machine carrying default policy nothing is
masked before it is sent; that is the default posture, not an edge case.
Promoting a detection to redact or block masks its matches at rest and in transit
together, from then on — it does not reach what has already been sent, and what
has been sent cannot be recalled.

The separate `aka sync-history` backfill, which covers activity recorded before
you attached, sends the record of that activity rather than event content, so
this rule does not reach it.

Attaching is opt-in and inert until both an endpoint and an access key are on
disk; `aka status` says what a machine is attached to and `aka detach` ends the
forwarding. A machine that was never attached forwards none of this.

## Supported versions

Security fixes target the latest released version. Please upgrade to the latest
release before reporting.
