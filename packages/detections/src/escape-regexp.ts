// Escapes every regex metacharacter so a literal string can be embedded in a
// pattern. The escaped set is exactly the ECMAScript SyntaxCharacters, so the
// result is a valid pattern under the `u` flag as well as without it.
//
// Load-bearing in two places — the keyword matcher and the engine's
// `requiresNearby` label matching — and kept here as one copy so the two escape
// sets cannot drift: a character added to one but not the other would silently
// change what a keyword or a label matches.
export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
