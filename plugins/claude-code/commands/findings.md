---
description: List recent AKA findings (masked) from the local store
---

# AKA findings

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is a space-aligned monospace table that Markdown would
otherwise collapse. Do not reformat the columns or restate each row.

If the user asked to filter by severity — e.g. `--critical`, `--high`,
`--medium`, `--low`, or `--severity <level>` — pass that flag through to the
script unchanged. Otherwise run it with no flag.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" findings [--severity <critical|high|medium|low>]
```

This lists the most recent findings from `~/.aka/data/aka.db` with their rule,
category, severity, action taken, and the **masked** match (raw secrets are
never stored), narrowed to one severity when a filter is given. It is read-only.
