/**
 * The tools that start a subagent.
 *
 * BOTH spellings, because the harness renamed this tool: older builds send
 * `Task`, current ones send `Agent`. Naming only one of them is how this
 * boundary came to be unguarded in the first place — the manifest matcher went
 * on listing `Task` long after the harness had stopped sending it, so the hook
 * never ran here at all and every check inside it was dead code.
 *
 * Kept in a module with no imports so that the model guard, the PostToolUse
 * response extractor and the withheld-output notice all read this one set. A
 * rename has to reach this set, the PreToolUse field table and both manifest
 * matchers; the manifest test derives its subagent cases from this set, so a
 * matcher or table that misses a spelling fails there.
 */
export const SUBAGENT_TOOLS: ReadonlySet<string> = new Set(['Task', 'Agent']);
