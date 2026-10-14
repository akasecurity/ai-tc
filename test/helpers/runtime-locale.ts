// Running a synchronous block as if the RUNTIME's default locale were another.
//
// Intl resolves its default locale once, when the process starts, so nothing a
// test does in-process can change it — and on an en-US runner a formatter that
// honours an explicit locale and one that falls back to the runtime default
// produce identical output. A test that wants to tell those apart has to move
// the default itself, and this is how it does it: every entry point that reads
// the default when it is given no locale is wrapped for the duration of `fn`,
// so an absent locale means `locale` instead.
//
// That is what lets one process stand in for both renderers of a client
// component: the server render runs under one default, the hydration under
// another, exactly as a Node host on en-US and a de-DE browser would.
//
// It sits at the repo root, beside remove-tree.ts, because the dashboard views
// and the web-ui routes that compose them both need the same stand-in, and a
// package wall stands between their test trees.
//
// What is wrapped: Number#toLocaleString, Date#toLocaleString /
// toLocaleDateString / toLocaleTimeString, and every Intl formatter constructor
// the ambient-locale lint ban names (INTL_FORMATTERS below), so a view the ban
// would reject also mismatches under this stand-in. "Absent" is `undefined` or an empty array —
// the two spellings that select the runtime default. A formatter CONSTRUCTED
// before `fn` runs keeps the locale it was built with, which is correct: it is
// not reading the default.

type Restore = () => void;

function isDefaultRequest(locales: unknown): boolean {
  return locales === undefined || (Array.isArray(locales) && locales.length === 0);
}

/**
 * Sets `target[key]` and returns what puts it back. A property the target only
 * INHERITED is deleted on restore rather than written back as an own copy — a
 * faked `Date` (vitest's fake timers) inherits its prototype's methods from the
 * real one, and an own copy left behind would outlive the fake's restore.
 */
function patch<T extends object, K extends keyof T>(target: T, key: K, value: T[K]): Restore {
  const hadOwn = Object.hasOwn(target, key);
  const original = target[key];
  target[key] = value;
  return () => {
    if (hadOwn) target[key] = original;
    else Reflect.deleteProperty(target, key);
  };
}

function wrapToLocale(
  proto: object,
  key: 'toLocaleString' | 'toLocaleDateString' | 'toLocaleTimeString',
  locale: string,
): Restore {
  type ToLocale = (this: unknown, locales?: unknown, options?: unknown) => string;
  const holder = proto as Record<string, ToLocale | undefined>;
  // Read through the prototype chain, not as an own property: see `patch`.
  const found: unknown = Reflect.get(proto, key);
  if (typeof found !== 'function') throw new Error(`no ${key} on this prototype`);
  const original = found as ToLocale;
  return patch(holder, key, function (this: unknown, locales?: unknown, options?: unknown) {
    return original.call(this, isDefaultRequest(locales) ? locale : locales, options);
  });
}

const INTL_FORMATTERS = [
  'NumberFormat',
  'DateTimeFormat',
  'RelativeTimeFormat',
  'PluralRules',
  'ListFormat',
  'DisplayNames',
] as const;

function wrapConstructor(name: (typeof INTL_FORMATTERS)[number], locale: string): Restore {
  const intl = Intl as unknown as Record<string, unknown>;
  const Real = intl[name] as new (locales?: unknown, options?: unknown) => object;
  // Callable with and without `new`, as the real constructors are; returning an
  // object from a constructor makes `new` yield it.
  function Wrapped(locales?: unknown, options?: unknown): object {
    return new Real(isDefaultRequest(locales) ? locale : locales, options);
  }
  Object.setPrototypeOf(Wrapped, Real);
  Wrapped.prototype = Real.prototype as unknown as object;
  return patch(intl, name, Wrapped);
}

/**
 * Runs `fn` with the runtime's default locale replaced by `locale`, then puts
 * everything back — on a throw too. `fn` must be synchronous: an await inside it
 * would hand the event loop to unrelated code while the default is moved, and
 * restore it before the awaited work ran.
 */
export function withRuntimeLocale<T>(locale: string, fn: () => T): T {
  const restores: Restore[] = [
    wrapToLocale(Number.prototype, 'toLocaleString', locale),
    wrapToLocale(Date.prototype, 'toLocaleString', locale),
    wrapToLocale(Date.prototype, 'toLocaleDateString', locale),
    wrapToLocale(Date.prototype, 'toLocaleTimeString', locale),
    ...INTL_FORMATTERS.map((name) => wrapConstructor(name, locale)),
  ];
  try {
    const result = fn();
    if (result !== null && typeof result === 'object' && 'then' in result) {
      throw new Error('withRuntimeLocale takes a synchronous function');
    }
    return result;
  } finally {
    for (const restore of restores.reverse()) restore();
  }
}
