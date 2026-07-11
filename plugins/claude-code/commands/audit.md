---
description: Show AKA's recent enforcement decisions
---

# AKA audit

Run the read script and show the user its output **exactly as printed**. The
script already prints its content inside a Markdown code fence — reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it.
The fence is required: it is a space-aligned monospace table that Markdown would
otherwise collapse. Do not reformat or re-narrate the rows.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/query.js" audit
```

This is the decision log: the most recent detections from `~/.aka/data/aka.db`
with the action AKA took (block / redact / warn / allow), the rule, and where it
fired (source tool + event kind). It is read-only.
