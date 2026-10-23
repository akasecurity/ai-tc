// The paths a tool call names that the user marked off-limits, as scan units
// for the PreToolUse pipeline. Each path found becomes one synthetic field whose
// text is `protected-path-access:<normalized path>`, which the built-in rule
// command-risk/protected-path-access matches. The finding then resolves its
// action through the same policy, redact fallback and ledger as every other
// finding, with no second decision path to keep in step.
//
// The fields are synthetic and executable: a redact on them degrades to the
// workspace's redactFallback and is never written back into the tool input, so
// a call is never rewritten to read a different file.
//
// What is checked: a Read's `file_path`; a Grep's or Glob's `path` (the working
// directory when it names none), joined to its `glob` or `pattern`; and the
// words of a Bash `command` that could be paths. A glob is compared as spelled,
// so a Grep or Glob over a parent of a protected file is not expanded. The
// matching dialect and what a shell command hides are in
// @akasecurity/plugin-sdk's protected-paths module.
//
// Kept free of I/O beyond the injected resolver so it unit-tests without a hook.
import {
  bashPathCandidates,
  compileProtectedPaths,
  protectedPathMatches,
} from '@akasecurity/plugin-sdk';

import type { ScannableField } from './pre-tool-use-fields.ts';

/** What the rule's pattern is anchored on; the path follows it. */
export const PROTECTED_PATH_TEXT_PREFIX = 'protected-path-access:';

// The path segment every protected-path field is addressed under. Never
// dereferenced (see ScannableField.text).
const PROTECTED_PATH_SEGMENT = '<protected-path>';

// One capture per field, so a command naming a hundred files costs a bounded
// number of them. This bounds how many matching paths one call reports; any
// match already yields a finding, so the decision does not depend on the rest.
const MAX_FIELDS = 16;

/** The tools whose input is checked against the protected-path list. */
export const PROTECTED_PATH_TOOLS: ReadonlySet<string> = new Set(['Read', 'Grep', 'Glob', 'Bash']);

export interface ProtectedPathContext {
  /** The user's protected-path list. */
  entries: readonly string[];
  home: string;
  cwd?: string | undefined;
  /** Resolves links in an absolute path; see the SDK module. */
  realpath?: ((absolute: string) => string | undefined) | undefined;
}

const text = (input: Record<string, unknown>, key: string): string | undefined => {
  const value = input[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
};

const isAnchored = (path: string): boolean => /^(?:[/\\~]|[A-Za-z]:[/\\])/.test(path);

// A glob placed under the directory it is searched in. The `*` and `?` stay in
// the text; a pattern segment matches its own spelling.
function underBase(base: string | undefined, glob: string): string {
  if (base === undefined || isAnchored(glob)) return glob;
  return `${base.replace(/[/\\]+$/, '')}/${glob}`;
}

function candidatesOf(
  toolName: string,
  toolInput: Record<string, unknown>,
  context: ProtectedPathContext,
): string[] {
  switch (toolName) {
    case 'Read': {
      const file = text(toolInput, 'file_path');
      return file === undefined ? [] : [file];
    }
    case 'Grep':
    case 'Glob': {
      const base = text(toolInput, 'path') ?? context.cwd;
      const glob = text(toolInput, toolName === 'Grep' ? 'glob' : 'pattern');
      if (glob !== undefined) return [underBase(base, glob)];
      return base === undefined ? [] : [base];
    }
    case 'Bash': {
      const command = text(toolInput, 'command');
      return command === undefined ? [] : bashPathCandidates(command, { home: context.home });
    }
    default:
      return [];
  }
}

/**
 * One synthetic field per protected path the call touches; none for a tool this
 * does not govern, an empty list, or an input naming nothing protected.
 */
export function protectedPathFields(
  toolName: string,
  toolInput: Record<string, unknown>,
  context: ProtectedPathContext,
): ScannableField[] {
  if (context.entries.length === 0) return [];
  const candidates = candidatesOf(toolName, toolInput, context);
  if (candidates.length === 0) return [];
  const env = { home: context.home, cwd: context.cwd, realpath: context.realpath };
  const compiled = compileProtectedPaths(context.entries, env);
  return protectedPathMatches(compiled, candidates, env)
    .slice(0, MAX_FIELDS)
    .map((path, index) => ({
      path: [PROTECTED_PATH_SEGMENT, index],
      executable: true,
      text: `${PROTECTED_PATH_TEXT_PREFIX}${path}`,
    }));
}
