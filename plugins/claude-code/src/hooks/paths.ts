// Path addressing for nested tool payloads, shared by the PreToolUse and
// PostToolUse hooks. Both sides do the same two things: read a string leaf out
// of a structure Claude Code owns the shape of, and write a replacement back at
// the same address without disturbing anything else.
//
// Array-aware by necessity. MultiEdit's scannable text lives at
// edits[i].new_string, and rebuilding that spine with object spread would hand
// back `edits` as a plain object. Claude Code validates a hook's updatedInput /
// updatedToolOutput against the tool's own schema and silently falls back to the
// ORIGINAL payload when it doesn't match — so a shape slip does not fail loudly,
// it just runs the unredacted arguments.
//
// Kept free of I/O and hook wiring so it unit-tests without a hook process
// (hook entry modules run main() on import and hang vitest collection).

/** Object key or array index. */
export type PathSegment = string | number;

/**
 * The string at `path`, or undefined if the path doesn't resolve or the leaf
 * isn't a string. Own properties only: a bare index would walk into
 * Object.prototype for segments like 'constructor' or 'toString'.
 */
export function stringAtPath(root: unknown, path: readonly PathSegment[]): string | undefined {
  let current: unknown = root;
  for (const segment of path) {
    if (typeof current !== 'object' || current === null) return undefined;
    if (Array.isArray(current)) {
      if (typeof segment !== 'number') return undefined;
      current = current[segment];
      continue;
    }
    if (!Object.hasOwn(current, segment)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return typeof current === 'string' ? current : undefined;
}

/**
 * Copy of `root` with the string at `path` replaced, leaving the original
 * untouched. Only the spine along `path` is rebuilt — siblings are shared by
 * reference, and arrays stay arrays. Returns `root` unchanged when the path
 * doesn't resolve, so a stale path degrades to "no rewrite" rather than
 * corrupting the payload.
 */
export function replaceAtPath(root: unknown, path: readonly PathSegment[], value: string): unknown {
  const head = path[0];
  if (head === undefined) return value;
  if (typeof root !== 'object' || root === null) return root;
  const rest = path.slice(1);

  if (Array.isArray(root)) {
    if (typeof head !== 'number' || !Number.isInteger(head) || head < 0 || head >= root.length) {
      return root;
    }
    const copy = [...(root as unknown[])];
    copy[head] = replaceAtPath(copy[head], rest, value);
    return copy;
  }

  const record = root as Record<string, unknown>;
  // Symmetric with the array branch's range check. Without it a path that
  // doesn't resolve grafts the missing key on — replaceAtPath({a:1},
  // ['missing','deeper']) would return { a: 1, missing: undefined } — and a
  // payload carrying a key the tool's schema doesn't declare is a shape
  // mismatch, which Claude Code answers by falling back to the ORIGINAL
  // unredacted arguments. Also what keeps a '__proto__' segment from grafting
  // onto an object that has no such own key; where one genuinely exists (JSON
  // can carry it), the computed key below writes an own property rather than
  // reaching the prototype setter a literal `{ __proto__: x }` would.
  if (!Object.hasOwn(record, head)) return root;
  return { ...record, [head]: replaceAtPath(record[head], rest, value) };
}
