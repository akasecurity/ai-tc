---
description: List active AKA detection exceptions (masked) from the local store
---

# AKA exceptions

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is a space-aligned monospace table that Markdown would
otherwise collapse. Do not reformat the columns or restate each row.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" exceptions
```

This lists the **active** detection exceptions from `~/.aka/data/aka.db` — the
masked value, rule, scope, relative expiry, use count, and who granted it. The
approved value is never stored, only a keyed fingerprint and a masked preview.

This command is strictly **read-only**. Do not offer to create, approve, or
revoke an exception from here — creation and revocation happen only in a
terminal, out-of-band, via the `aka` CLI (`aka exception approve`,
`aka exception revoke <id>`; see `aka exception --help`). If the user asks you
to grant or revoke one, tell them to run those commands themselves in a
terminal instead.
