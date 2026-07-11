---
description: Show token usage and estimated cost per model from your local AKA store
---

# AKA tokens

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is space-aligned monospace (a per-model usage table)
that Markdown would otherwise collapse. Do not reformat or summarize the table;
you may add at most one short sentence of context after it.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" tokens
```

This reads the local store at `~/.aka/data/aka.db` (token counts reconciled from
your Claude Code transcripts, grouped by provider/model, with estimated USD cost).
It is read-only. Token counts are exact; cost is **derived** at read time — a `—`
means unknown pricing (a local or non-Anthropic model), so a `≥` total is a lower
bound, not an understatement. If the store is empty, the script says so — relay
that as-is; nothing is wrong.
