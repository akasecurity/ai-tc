# Detection Exceptions

Sometimes AKA blocks a value you genuinely mean to use — a sandbox credential, a
test fixture, a documented example key. A **detection exception** is the
sanctioned way through: an explicit, audited grant for that **exact value**,
made from a terminal or the local dashboard — never from inside the agent
session.

This page walks the whole flow once, end to end.

## 1. You get blocked

You submit a prompt (or Claude runs a tool call) containing something a rule
flags, and AKA blocks it. The block message in the transcript looks like this:

```text
AKA blocked this prompt — flagged secrets/aws-access-key (A******E). Remove the flagged content and resubmit.
If this is intentional and you accept the risk, grant an exception:
  aka exception approve 3f2a91       (asks for scope + reason, then resubmit)
  aka exception approve <value>      (same flow, pasting the blocked value itself)
More: aka exception --help
```

Reading it:

- **What fired** — the rule id(s), plus a masked preview of the matched value.
- **The primary fix** — remove the flagged content and resubmit. If the value
  doesn't need to be there, that is always the better outcome.
- **The escape hatch** — the `aka exception approve 3f2a91` line. `3f2a91` is a
  short-lived reference to the block that just happened (kept for 30 minutes),
  so the command already knows _which value_ you mean — you never retype or
  paste the secret anywhere. Pasting the blocked value in place of the
  reference works too (it is matched by fingerprint, never stored), at the
  cost of the value landing in your shell history.

When AKA **redacts** instead of blocking, the warning carries the same pointer:
redacted values can be excepted through the identical flow.

## 2. Grant the exception

Copy the command from the message into a terminal:

```bash
aka exception approve 3f2a91
```

(Ran out of the 30-minute window, or lost the reference? Plain
`aka exception approve` lists your recent blocks to pick from. You can also
paste the blocked value itself in place of the reference — it is matched by
its keyed fingerprint, never stored or echoed. Just note that anything typed
on a command line lands in your shell history; the reference avoids that.)

Prefer a UI? `aka dashboard` → **Exceptions** shows the same 30-minute
blocked ledger with an **Approve** button per entry, plus the full grant
register, a pre-authorize form (`aka exception add`'s twin), revoke, and key
rotation. Grants made there are recorded with `web approve` / `web add`
provenance so the audit trail says which surface created them.

The command asks two questions.

**Scope** — how long the grant lives. There is no default: the choice is the
point of the flow, so you make it explicitly:

| Scope       | Meaning                                      |
| ----------- | -------------------------------------------- |
| `once`      | exactly one use, then the grant is spent     |
| `temporary` | expires after a duration (e.g. 30m, 1h, 24h) |
| `permanent` | until you revoke it                          |

Pick the narrowest scope that solves your problem — `once` for a one-off paste,
`temporary` for a working session, `permanent` only for stable non-secret
values (e.g. your own email address).

**Reason** — a short justification, required. It is the audit trail: six weeks
from now, "temp deploy creds, rotating after infra apply" is the difference
between an explainable grant and a mystery hole in your policy.

Approving is accepting a risk on the record — the grant carries who created it,
when, why, and how often it has been used.

## 3. Resubmit

Go back to your session and resubmit the prompt (or retry the tool call). The
same detection fires, matches the exception, and the content goes through. The
pass is still recorded: findings show the value was allowed _because of_ the
exception, never silently missed.

## 4. Review, and undo

```bash
aka exception list          # active grants: masked value, rule, scope, expiry, uses
```

Inside a Claude Code session, the read-only
[`/aka:exceptions`](../plugin/claude-code.md#read-surface-slash-commands)
command shows the same list; the dashboard's **Exceptions** page shows it too
(add `?all=1` — or use the "Show all" toggle — for the terminal
consumed/expired/revoked audit rows). Revoke anything that shouldn't live any
longer:

```bash
aka exception revoke <id>
```

Revocation is immediate and terminal; the record is retained as audit evidence.

## The security model, honestly

An exception never stores the approved value. What is kept is a **keyed
fingerprint** (an HMAC under a machine-local key) plus a masked preview for
display — the store can _recognize_ the exact value when it appears again, but
the value cannot be recovered from anything on disk. Grants are
**exact-value**: excepting one sandbox key does not loosen the rule, and a
different key — even one character off — is still blocked. And creation is
deliberately out-of-band: only a human — at a terminal, or in the local
dashboard bound to `127.0.0.1` — can grant one; nothing model-invocable can
approve its own bypass.

## Key rotation ends grants naturally

Because a grant is bound to the exact value, rotating the underlying credential
retires the grant on its own — the new secret has a different fingerprint and
is enforced like any other value. This is the recommended cleanup after a
temporary credential: rotate it, and any exception for the old value becomes
inert.
