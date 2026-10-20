# Security Policy

AI Traffic Control (`ai-tc`) is a security tool, and we take the security of the
project itself seriously.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report privately by email to **security@akasecurity.io**.

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
either way, so `aka.db` accumulates a full local prompt corpus. No detection ships
on redact or block, so **on a default install nothing in the store is masked at
all** — raw secrets included — until you promote a detection to redact or block,
which changes what is stored from then on and not what is already there. Files
read by `aka scan` are stored under the same rule. The store is protected by
**filesystem permissions, not encryption**. On macOS and Linux the store directories (`~/.aka`,
`~/.aka/data`, `~/.aka/settings`, `~/.aka/keys`) are created owner-only (`0700`)
and the files — `aka.db` and its `-wal`/`-shm`/`-journal` sidecars,
`control-plane-credential.json`, `exception.key`, `settings.json`, `sighting.key`
and `vault.key` — are written `0600`, so only
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

`sighting.key` is written only on an attached machine. It holds the HMAC key
versions the attached deployment issues to the machine, records which deployment
issued them, and is not used for any other one. It follows the same custody
setting as `vault.key`: under keychain custody it is an OS-keychain item rather
than a file. `aka detach` and the dashboard's disconnect both remove it, file or
keychain item.

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
tool call over it. The one deliberate exception is a single prompt, tool input or tool
output field of 32,768 characters or more whose bounded scan does not finish in time
(or finds no scan worker to run it): that field is blocked, or withheld from the model,
rather than passed unscanned. The same holds for the Antigravity and GitHub Copilot
tool-call hooks, which deny such a call, and for a prompt the browser extension's native
host could not scan in time, which is not sent. Each deadline ends before the point at
which the host itself would let the input through — 6 s for Claude Code and Codex prompts
and tool inputs (7 s for tool output), 5.5 s for Antigravity, 15 s for Copilot, and 2 s
from when the native host receives a prompt.

## Data in transit

Detection and enforcement run on the machine, and while it is unattached the
store stays there; the narrow outbound paths a standalone install still has are
enumerated in the egress footnote in [README.md](README.md), and none of them
carry stored event content. `aka attach` is what sends it: it registers one
machine against a control plane **your organization runs**, never a service AKA
operates, and from then on this machine forwards each captured event to that
deployment as it stored it, and a scan you run on it (`aka scan`, or the dashboard's
Scan page) sends the Data Shares register it just recorded over the same
connection — destinations and call sites, never source text.

That is the same content [Data at rest](#data-at-rest) describes, so the masking
rule is the same one: a flagged span is masked before the event is sent only
where the detection's policy is redact or block. **Under monitor or warn the
matched value — the secret itself — reaches that deployment exactly as it was
seen**, and everything outside a flagged span crosses either way. No detection ships
on redact or block, so on an attached machine carrying default policy nothing is
masked before it is sent; that is the default posture, not an edge case.
Promoting a detection to redact or block masks its matches at rest and in transit
together, from then on — it does not reach what has already been sent, and what
has been sent cannot be recalled.

The separate `aka sync-history` grant covers three things, and the rule reaches
the first two of them. The backfill of activity recorded before you attached marks that
activity for delivery the same way a live send would have; for a prompt, an
assistant reply or a tool result, what it sends is that text, not just the
record that the activity happened. The second is the drain of anything a live
send could not deliver, which sends the capture as the store holds it. Both
send the same content a live forward would have, so the rule applies exactly
as it does there: **under monitor or warn the matched value is drained as it
was seen**, and no detection ships on redact or block, so on a default install that
is what a backfill or a drain sends. The third, on a machine attached
machine-wide only, is the labels a person gives there: the exceptions they
grant and the findings they dismiss, each with the reason picked from the list —
a grant's id, rule id, category, masked preview, what it permits, scope, expiry, use limit and use count, key version, how it was made, and when it was made, changed, last used and revoked; a dismissal's id, finding key and time; and for each, who it is from, which is always this machine's user — and never the reason typed or the local account name. A label
carries no captured text, so the masking rule does not come into it.

An attached machine also sends things that are not activity, and no repository
limits them. Whenever a session starts anywhere on this machine, in a repository
or not (a browser chat included), the machine pulls the deployment's policy (at
most every 15 minutes) and its sighting key (when none is stored or the stored
one is a day old) and sends it a device report (at most hourly): a device
identifier, host name, versions, detection packs, policy counts, finding counts
and dates for everything recorded on the machine, and, when the machine is
attached as a personal device, the fact that it is one. Where a scan is
available (the coding-agent plugins, not a browser chat), the same session
start also checks it for device commands. On a personal device, the background sync also asks the deployment
which account its key belongs to, and asks again at later syncs until the device has an answer; syncs that overlap can each send one. The finding count is the number of findings
detected in captured prompts, responses, code changes and tool uses, from every
session, with the dates of the first and latest one. A report can also go when a
response finishes in a session that is already running, still at most hourly.
The report carries no event content and names no repository. The deployment
therefore learns when the tool is in use anywhere on this machine.

A machine attached machine-wide also sends the Claude Code configuration a
Claude Code session start's scan found, with the next policy pull rather than
during the session start, and only when it differs from what was last sent or
was last sent an hour or more ago: each skill, hook, MCP server and
configuration file, with its name, scope, file path and the plugin or
marketplace it came from; a skill's description, version and modification time;
a hook's event, matcher, command and timeout, and an MCP server's transport and
command or URL, each description, command and URL with any secret the bundled
detection rules find masked, and an MCP server's URL also stripped of its
credentials and query values; the names of an MCP server's environment
variables, never their values; a configuration file's kind, modification time
and a summary of its shape (key names, line and entry counts), never its
contents; and the repository's remote URL with any credentials and query
removed, or the working directory where it has none, that the project's own
items belong to. A machine attached with `--scoped` keeps this configuration on
the machine.

On a personal device, Claude Code and Codex sessions signed in to a work
subscription forward beyond what is enrolled. A Claude Code session counts
as a work subscription when it is signed in through
claude.ai to a Team or Enterprise plan under the same email as the AKA account
that attached the device. Such a session sends everything it records from its
first reply on, from any folder, with that folder's project and branch names,
and your organization's prohibited models are refused in any folder of it. To
tell whether a session is one, the device reads Claude Code's login file, the
session's own log, and Claude Code's settings files (the project's own
included) and environment variables that choose the account or provider, and
compares the signed-in email with the account that attached the device. The
check sends none of what it reads, though the token usage and tool calls read
from that same log are forwarded with the rest of the activity of a recognised
session or of one signed in to an account enrolled by hand. The first prompt of
a new session, a personal plan, another email, an API key or another provider,
a reply written before the device has confirmed the account, and the rest of a
session whose organization changes follow the repository rule;
`aka enroll --account` enrolls by hand an account the device cannot recognise,
and the Claude Code sessions of an account enrolled that way then forward from
their first reply on whatever the plan or email, though not under an API key or
another provider. An organization recognised this way never records or forwards
a claude.ai chat. A personal device that attached before
its plugin could recognise work subscriptions starts recognising them when the
plugin updates, with no new prompt, so update `aka` first.
`aka unenroll --work-subscriptions` turns recognition off on this device and
`aka enroll --work-subscriptions` turns it back on; it turns off only the
automatic recognition, so while it is off, enrolled repositories and accounts
enrolled by hand still forward (`aka unenroll --account` stops an account), and
your organization's model restrictions apply only to them. A machine whose
connection an administrator manages attaches machine-wide only, so it has no
personal-device mode and no such opt-out.

A Codex thread counts as a work subscription when it is new and signed in with
ChatGPT to a Business, Team, Enterprise or Edu workspace under the same email
as the AKA account that attached the device, with its login saved in Codex's
login file and OpenAI as the provider. Such a thread sends everything it
records, from any folder, with that folder's project and branch names, and your
organization's prohibited models are refused in any folder of it. To tell
whether a thread is one, the device reads Codex's login file, the first line of
the thread's own log and the environment variables that choose the account or
provider, and compares the signed-in email with the account that attached the
device and the login's workspace with the one that created the thread. The
check sends none of what it reads, though the token usage and tool calls read
from that thread's log are forwarded with the rest of the activity of a
recognised thread or of one signed in to a workspace enrolled by hand. A token
refresh keeps a recognised thread forwarding; a switch to another workspace or
email, to a plan that does not count, or to another login mode ends it for the
rest of that thread. A resumed thread, a personal plan, a service account,
another email, a saved login that uses an API key or any login mode other than
ChatGPT, a `CODEX_API_KEY` or `CODEX_ACCESS_TOKEN` in the environment, an
`OPENAI_BASE_URL` naming a host other than api.openai.com, a thread whose log
does not name OpenAI as its provider or the login's workspace as its creator,
and a login Codex keeps outside its login file (in the system keychain, for one)
follow the repository rule.
A Codex thread whose first log line is not on disk when it starts is checked
again at its next prompt or tool call: its session record and the token usage
and tool calls read from its log follow the repository rule, and its prompts,
tool calls and results forward from any folder from that check on if the
workspace is then recognised or enrolled by hand; if the line is still missing
then, it follows the repository rule for the rest of the thread.
`aka enroll --account` enrolls by hand a workspace the device cannot recognise,
and the Codex threads of a workspace enrolled that way then forward whatever the
plan or email, though not a resumed thread, one whose saved login uses an API
key or any login mode other than ChatGPT, one with a `CODEX_API_KEY` or
`CODEX_ACCESS_TOKEN` in the environment, one with an `OPENAI_BASE_URL` naming a
host other than api.openai.com, one whose log does not name OpenAI as its
provider, or one whose login Codex keeps outside its login file; a switch of
workspace or login mode ends them.
`aka unenroll --work-subscriptions` turns the recognition of Codex threads off
too and `aka enroll --work-subscriptions` turns it back on; a workspace
enrolled by hand still forwards while it is off (`aka unenroll --account` stops
it). Recognising a Codex thread reads Codex's login token only in memory, for
the claims that give its email, plan and workspace: the token is never kept,
logged, printed or sent, and the recognition never copies the login file into
the local store.

Attaching is opt-in and inert until both an endpoint and an access key are on
disk; `aka status` says what a machine is attached to and `aka detach` ends the
forwarding. On a machine attached with `aka attach --scoped`, the forwarding of
activity described above — live events, the scan register, and the history
backfill and drain — covers only activity in the repositories enrolled with
`aka enroll`, in Claude Code and Codex sessions signed in to a recognised work
subscription (above) or to an account enrolled by hand with
`aka enroll --account` and, from the browser extension, the replies in a
claude.ai account enrolled with `aka enroll --account`, with their tool calls
and token usage (a prompt typed into a web chat is not recorded there at all);
everything else stays on the machine. Under the `aka sync-history` grant,
enrolling a repository or an account also queues the captures still kept for
it, including those a repository recorded between attaching and enrolling. The
policy pull, the sighting-key fetch, the command check and the device report
are the exception: they go on either kind of attachment, whatever is enrolled,
and a scoped machine's report also says that it is attached as a personal
device. A machine that was never attached forwards none of this.

## Supported versions

Security fixes target the latest released version. Please upgrade to the latest
release before reporting.
