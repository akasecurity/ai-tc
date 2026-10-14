import type { FindingContextSource, FindingContextView } from '@akasecurity/persistence';
import { bundledMaskingRules, createFindingLocator, evidenceLookup } from '@akasecurity/plugin-sdk';
import { DetectionCategory, FindingContext } from '@akasecurity/schema';

// The placeholder prefix `redact` writes into a stored body. Present before a
// finding's end offset, it means the body was rewritten ahead of the match and
// the stored offsets no longer land on it.
const REDACTION_MARK = '[REDACTED:';

/**
 * One finding's masked excerpt, for the dashboard drawer: the excerpt stored
 * when the finding was detected, or — for a finding recorded before excerpts
 * existed — one rebuilt from the event's stored text where that is safe.
 *
 * The rebuild runs only when the stored text still exists and holds no
 * redaction placeholder before the match's end, because a placeholder shifts
 * every offset after it and the excerpt would show the wrong lines. It masks
 * through the same builder a new finding uses, with the bundled rules. Null
 * whenever none of that holds: the drawer says the code was not kept.
 */
export function loadFindingContext(db: FindingContextView, id: string): FindingContext | null {
  const source = db.findingContextSource(id);
  if (source === null) return null;

  if (source.context !== null) {
    try {
      const parsed = FindingContext.safeParse(JSON.parse(source.context));
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  const { content, spanStart, spanEnd } = source;
  if (content === null || spanEnd > content.length || spanStart >= spanEnd) return null;
  if (content.slice(0, spanEnd).includes(REDACTION_MARK)) return null;
  const category = DetectionCategory.safeParse(source.category);
  if (!category.success) return null;

  const rules = bundledMaskingRules();
  const hit = {
    ruleId: source.ruleId,
    category: category.data,
    span: { start: spanStart, end: spanEnd },
    rawMatch: content.slice(spanStart, spanEnd),
  };
  const locate = createFindingLocator({
    text: content,
    basis: wholeFileText(source) ? 'file' : 'excerpt',
    hits: [hit],
    evidenceOf: evidenceLookup(rules ?? []),
    backstopRules: rules,
  });
  return locate(hit).context;
}

// Whether an older finding's stored text is a whole file. A capture marked so,
// a Claude Code Write (its content is the file), or a `code_change` no tool
// produced — the folder scan and the worktree scan, which read whole files.
function wholeFileText(source: FindingContextSource): boolean {
  if (source.wholeFile || source.toolName === 'Write') return true;
  return source.eventType === 'code_change' && source.toolName === null;
}
