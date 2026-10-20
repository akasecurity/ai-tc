/**
 * How many characters the string-examining builtins were asked to look at
 * while `work` ran.
 *
 * A count rather than a duration, so it says the same thing on any machine
 * however busy it is: the work a framing loop does is the characters it
 * reads, and reading a retained tail again on every chunk shows up as those
 * characters counted again.
 *
 * Each method is charged what it can examine, not what it happened to: a
 * character accessor one, a search the rest of the string from where it
 * starts, a prefix or suffix test the length it compares, a split or a pattern
 * method the whole string, a regex run the input from where it starts, and
 * iteration (`for (const char of text)`, a spread, `Array.from`) each
 * character it yields.
 * Copying builtins (`slice`, `concat`, `join`) are not charged, because a copy
 * is not a re-examination and V8 can make one without visiting a character.
 *
 * What it cannot see is a read that calls nothing: `text[i]` goes through no
 * patchable method, so a rescan written as raw index access is invisible to it.
 */
export function charactersExamined(work: () => void): number {
  let examined = 0;
  const lengthOf = (value: unknown): number =>
    typeof value === 'string' ? value.length : String(value).length;
  const fromIndex = (value: unknown): number =>
    typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;

  type Charge = (self: string, args: unknown[]) => number;
  // A pattern method handed a RegExp runs it through `RegExp.prototype.exec`,
  // which is charged on its own, so only a string pattern is charged here.
  const unlessRegExp: Charge = (self, args) => (args[0] instanceof RegExp ? 0 : self.length);
  const stringCharges: Record<string, Charge> = {
    charCodeAt: () => 1,
    codePointAt: () => 1,
    charAt: () => 1,
    at: () => 1,
    indexOf: (self, args) => Math.max(0, self.length - fromIndex(args[1])),
    includes: (self, args) => Math.max(0, self.length - fromIndex(args[1])),
    lastIndexOf: (self, args) =>
      args[1] === undefined ? self.length : Math.min(self.length, fromIndex(args[1]) + 1),
    startsWith: (_self, args) => lengthOf(args[0]),
    endsWith: (_self, args) => lengthOf(args[0]),
    search: unlessRegExp,
    match: unlessRegExp,
    matchAll: unlessRegExp,
    replace: unlessRegExp,
    replaceAll: unlessRegExp,
    split: unlessRegExp,
  };

  const restore: (() => void)[] = [];
  function patch(target: object, name: string, charge: (self: unknown, args: unknown[]) => number) {
    const original = Reflect.get(target, name) as (...args: unknown[]) => unknown;
    Object.defineProperty(target, name, {
      configurable: true,
      writable: true,
      value: function (this: unknown, ...args: unknown[]): unknown {
        examined += charge(this, args);
        return Reflect.apply(original, this, args);
      },
    });
    restore.push(() => {
      Object.defineProperty(target, name, { configurable: true, writable: true, value: original });
    });
  }

  for (const [name, charge] of Object.entries(stringCharges)) {
    patch(String.prototype, name, (self, args) => charge(String(self), args));
  }
  // Every built-in regex method (`test`, and the ones the string pattern
  // methods delegate to) runs the pattern through `exec`, so charging `exec`
  // charges each run once.
  patch(RegExp.prototype, 'exec', (self, args) => {
    const input = typeof args[0] === 'string' ? args[0] : String(args[0]);
    const from = self instanceof RegExp && (self.global || self.sticky) ? self.lastIndex : 0;
    return Math.max(0, input.length - from);
  });

  // Iterating a string looks up `String.prototype[Symbol.iterator]`, primitive
  // or not, so a for-of rescan is charged here, per character it yields.
  const iterate = Reflect.get(String.prototype, Symbol.iterator) as (
    this: unknown,
  ) => Iterator<string>;
  Object.defineProperty(String.prototype, Symbol.iterator, {
    configurable: true,
    writable: true,
    value: function (this: unknown): Iterator<string> {
      const inner = Reflect.apply(iterate, this, []);
      return {
        next(): IteratorResult<string> {
          const step = inner.next();
          if (step.done !== true) examined += step.value.length;
          return step;
        },
        [Symbol.iterator]() {
          return this;
        },
      } as Iterator<string>;
    },
  });
  restore.push(() => {
    Object.defineProperty(String.prototype, Symbol.iterator, {
      configurable: true,
      writable: true,
      value: iterate,
    });
  });

  try {
    work();
  } finally {
    for (const undo of restore.reverse()) undo();
  }
  return examined;
}
