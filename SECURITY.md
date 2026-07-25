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

The local store under `~/.aka` is protected by **filesystem permissions, not
encryption**. On macOS and Linux the store directories (`~/.aka`, `~/.aka/data`,
`~/.aka/settings`) are created owner-only (`0700`) and the files — `aka.db` and its
`-wal`/`-shm` sidecars, `exception.key`, and `settings.json` — are written `0600`,
so only your user account can read them. These modes are the only at-rest control,
so treat a copy of the store (a backup, a synced folder, a stolen disk image) as
sensitive.

Those POSIX modes are a **no-op on Windows**: Node cannot apply them, so `ai-tc`
sets no at-rest protection there. On Windows the store simply inherits whatever ACL
its parent directory grants — by default a per-user profile path, but `ai-tc`
neither sets nor asserts any Windows ACL. **Treat the store as unprotected at rest
on Windows** and rely on full-disk encryption (e.g. BitLocker) or your own directory
ACLs.

## Supported versions

Security fixes target the latest released version. Please upgrade to the latest
release before reporting.
