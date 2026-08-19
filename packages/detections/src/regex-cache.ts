// Compiled-`RegExp` cache shared by every per-scan construction site in this
// package. Rule patterns, keywords and `requiresNearby` labels are all immutable
// after `Rule.parse`, so the object built from one is reusable for the life of
// the rule — but nothing reused it, and `scan()` rebuilt every one of them on
// every call.
//
// KEYED ON THE OWNER OBJECT, NOT ON THE PATTERN TEXT. V8 keeps its own
// compilation cache keyed on source and flags, so re-running `new RegExp` on a
// pattern it has already seen does not recompile — it allocates a fresh wrapper
// around compiled code it still holds. What that leaves to win is the wrapper,
// and a cache keyed on the pattern text spends more than that to collect it:
// the key has to be built and hashed on every lookup, and rule patterns run to
// hundreds of characters. Looking up by the owner object skips both.
//
// The trade is that two distinct rules carrying identical patterns now compile
// separately. That costs one wrapper object apiece around compiled code V8
// already shares between them, which is the cheap half of what was being rebuilt.
//
// THE OWNER MUST NOT BE MUTATED AFTER FIRST USE. Identity is standing in for the
// pattern text, so editing a matcher's `pattern`, `flags` or `keywords` in place
// leaves this handing back the object compiled from the old text — a rule that
// reads as updated and never matches, with nothing raised. Rules are built by
// `Rule.parse` and treated as frozen from then on; a caller that needs a changed
// pattern builds a new rule rather than editing one.
//
// THE RETURNED OBJECT IS SHARED AND MUTABLE. A `RegExp` carries exactly one
// piece of mutable state, `lastIndex`, which `exec` advances and which a caller
// that stops early (a match cap, a sticky pattern, a zero-length bump) leaves
// pointing into the middle of the input it gave up on. A later caller reusing
// that object starts its search from that offset and silently finds nothing.
// Both accessors below therefore hand back objects whose `lastIndex` is already
// 0, which is why acquisition goes through a function rather than a bare
// `WeakMap.get`: a reset every caller has to remember is a reset somebody
// eventually forgets.
//
// Use what you get synchronously and do not retain it — two live users of one
// object would interleave their `lastIndex`. Every call site in this package
// holds it for one loop over one input, which is what makes sharing safe here.
//
// BOUNDED BY LIVENESS. The maps are weak, so an entry lives exactly as long as
// the rule it was built for and no size cap is needed: a ruleset that is dropped
// takes its compiled patterns with it, and a caller that rebuilds its rules per
// scan gets no benefit rather than an unbounded map. That last case is the one
// to know about — the cache pays off only for a ruleset held across calls, which
// is how every scanner in this workspace holds one.
//
// PER-THREAD BY CONSTRUCTION. An isolated scan runs this same engine on a worker
// thread, and a worker gets a fresh module registry — so it evaluates this
// module again and gets its own maps. The main thread and a worker therefore
// never share a `lastIndex`, and that follows from module scoping rather than
// from any locking, which is why there is none here. Keeping the compiled object
// out of the rule itself is the other half: a ruleset reaches a worker by
// structured clone, a `RegExp` is cloneable, and a cache hung on the rule would
// hand the worker a copy carrying whatever `lastIndex` the parent left on it.

// A `RegExp` reads and writes `lastIndex` only when it is global or sticky —
// every other pattern ignores the field entirely, including the `test()` calls
// the proximity labels use. Recording that per list at build time turns the
// reset below into one branch for those, instead of a write per entry per
// acquisition on the densest path in the engine.
interface CompiledList {
  readonly entries: readonly (RegExp | undefined)[];
  readonly stateful: boolean;
}

// One map per kind of value rather than one shared by both. They are keyed by
// different objects — a rule's `matcher` and its `requiresNearby` — and a single
// keyspace would return a keyword list to a label lookup for any owner that ever
// appeared in both positions.
const singles = new WeakMap<object, RegExp>();
const keywordLists = new WeakMap<object, CompiledList>();
const labelLists = new WeakMap<object, CompiledList>();

/** Which list cache a call is addressing. */
export type ListKind = 'keyword' | 'label';

function listCache(kind: ListKind): WeakMap<object, CompiledList> {
  return kind === 'keyword' ? keywordLists : labelLists;
}

/**
 * The compiled `RegExp` belonging to `owner`, built by `build` on first ask and
 * handed back with `lastIndex` reset to 0.
 *
 * `owner` must be the immutable object the pattern is derived from — a rule's
 * `matcher` — so that identity stands in for the pattern text.
 */
export function memoizedRegExp(owner: object, build: () => RegExp): RegExp {
  const cached = singles.get(owner);
  if (cached !== undefined) {
    cached.lastIndex = 0;
    return cached;
  }
  // A freshly constructed RegExp has lastIndex 0 already, so the miss path needs
  // no reset of its own. Built before the store, so a pattern that fails to
  // compile throws without recording anything.
  const compiled = build();
  singles.set(owner, compiled);
  return compiled;
}

/**
 * The compiled `RegExp`s belonging to `owner` in the `kind` cache — one per entry
 * of whatever list it holds, `undefined` where that entry compiles to nothing —
 * built by `build` on first ask and handed back with every stateful entry's
 * `lastIndex` reset to 0.
 */
export function memoizedRegExpList(
  kind: ListKind,
  owner: object,
  build: () => readonly (RegExp | undefined)[],
): readonly (RegExp | undefined)[] {
  const cache = listCache(kind);
  const cached = cache.get(owner);
  if (cached !== undefined) {
    if (cached.stateful) {
      for (const re of cached.entries) if (re !== undefined) re.lastIndex = 0;
    }
    return cached.entries;
  }
  const entries = build();
  cache.set(owner, {
    entries,
    stateful: entries.some((re) => re !== undefined && (re.global || re.sticky)),
  });
  return entries;
}
