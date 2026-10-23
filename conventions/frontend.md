## Frontend UI components

Shared, reusable UI **primitives** live in `packages/ui-kit` (`@akasecurity/ui-kit`). Shared,
reusable **presentational composites** (stat tiles, charts, the security widget views)
live in `packages/dashboard-ui` (`@akasecurity/dashboard-ui`). App-specific composition and data
wiring live in the app (e.g. `web-ui/app`).

`@akasecurity/dashboard-ui` is **bundler-agnostic and props-driven**: it depends only on
`@akasecurity/ui-kit` + `@akasecurity/schema` types and does **no data fetching**, so the Next.js
dashboard (`web-ui`, via `@akasecurity/persistence` Server Components) can feed it. It imports no
SVG assets via a bundler loader (svgr) — icons are inlined or taken as an `IconComponent`
prop — and marks interactive components with `'use client'`. Put a widget's presentation
here (a dumb `*View`) and its data-fetching wrapper in the app.

When adding a **new reusable component** to `@akasecurity/ui-kit`, follow the shadcn/ui pattern:

- **Build on Radix UI primitives** (`@radix-ui/react-*`) for anything interactive or with
  accessibility/focus/positioning concerns (popover, dialog, dropdown, tooltip, select, etc.).
  Do **not** hand-roll outside-click, focus traps, or anchored positioning — Radix already
  solves these. Add the matching `@radix-ui/react-*` package rather than reinventing it.
- **Expose a compound, composable API** (`Card` / `CardHeader` / `CardTitle` / `CardContent`…),
  not a monolithic prop-driven component. Each part is a plain function component that spreads
  native props, merges `className` via `cn`, and carries a `data-slot="…"` attribute.
  On React 19, **`ref` is a regular prop** — type props with `ComponentPropsWithRef<'div'>` (or
  `ComponentPropsWithRef<typeof RadixPrimitive.X>`) and let `ref` flow through `...props`. Do **not**
  use `forwardRef` (deprecated in React 19). See `card.tsx`, `button.tsx`, `popover.tsx`.
- **Style with Tailwind + design tokens** from `theme.css` (`bg-surface`, `text-text-2`,
  `border-border`, severity/`ok` tokens…). Use `cva` for variants (see `button.tsx`,
  `badge.tsx`). No hardcoded hex — add a token to `theme.css` if one is missing.
- Each component is its own file under `packages/ui-kit/src/`, exported from `src/index.ts`.

### Tonal tokens come in pairs: a hue and an ink

Every tonal family (`sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `ok`, `teal`,
`violet`) carries **two** foregrounds, and picking the wrong one is an accessibility bug
that compiles, renders, and reads fine in review:

- `--color-X` — the **hue**: chart series, status dots, bar segments. Non-text, so what
  matters is staying distinguishable from its neighbours (WCAG 1.4.11).
- `--color-X-ink` — **text** on that family's tint, and solid fills that carry text
  (WCAG 1.4.3, 4.5:1).

They cannot be collapsed. Forcing every hue dark enough to read as text on a pale tint
crowds them into one luminance band — severity chart separation measured 1.69 before and
1.05 after, with red/orange/yellow rendering as the same brown. So **a foreground always
spells the `-ink` form**, and every family carries one even where its hue already clears
4.5:1 (violet in light; all of them in dark, where ink == hue): a family missing its
`-ink` makes `text-X-ink` generate no CSS at all, because an undefined theme variable
produces no utility and the element silently inherits its color.

`--color-primary` is the one exception and reads the other way round — it **is** the ink,
and `--color-primary-solid` is its fill. So `text-primary` is right while
`text-sev-critical` is wrong, and nothing in the names says which. That is why it is
enforced rather than remembered: `tonalInkTokens` in `@akasecurity/eslint-config` is a
`no-restricted-syntax` ban on a bare hue reached through `text-*`, spread by `ui-kit`,
`dashboard-ui` and `web-ui`. It re-spreads `noNetworkSyntax()` because a flat-config
`rules` entry **replaces** the rule's options rather than merging them — drop that and
those three packages silently lose §4's dynamic-import ban.
`packages/eslint-config/test/tonal-ink-tokens.test.js` pins both halves.

What the ban does **not** see, and what still needs reading: a hue handed over as a CSS
variable string, since `iconColor="var(--color-ok)"` and `iconBg="var(--color-ok-fill)"`
are the same node to a selector (`toneColors()` is the live example); and a class
assembled from a non-literal.

`tonalInkTokens` is no longer only the tonal ban: it is the WHOLE
`no-restricted-syntax` value those three packages get, assembled by
`reactSyntaxBans()` from five groups (network, drizzle, tonal, ambient clock,
ambient locale) because a later entry replaces the rule's options rather than
merging them. A per-file opt-out is therefore written as `reactSyntaxBans({ … })`
with one group switched off, never as a hand-listed subset — the other four come
along by construction, so lifting one ban cannot silently lift five. A widening is
an option too, so it does NOT come along: in `dashboard-ui`/`ui-kit` `src/**` the
per-file form is `presentationalSyntaxBans({ … })`, which keeps both widenings on,
and in web-ui's `app/**` an entry has to pass `ambientLocaleEveryModule: true`
itself (see the clock exemption below, and `web-ui/eslint.config.mjs`).

### A time label is a function of two instants, and a client component is given both

A page under `'use client'` is rendered **twice** — once on the server, once when
the browser hydrates it. A label derived from the ambient clock is therefore two
different strings whenever a rounding boundary falls between those two renders,
and React resolves that by discarding the server HTML for the subtree. It is not
only cosmetic: `exceptionState` gates **structure**, since `ExceptionDetailView`
renders its revoke form only while the state reads `active`, so the two renders
can disagree about whether a whole subtree exists.

The class is closed in the type system rather than site by site. `relativeTime`,
`relativeTimeShort` and `exceptionState` take `now` as a **required** argument,
and every time-derived view takes a required `renderedAt: number` prop — a
DEFAULT would not do, because a default reads as safe at every call site that
omits it, which is every call site until somebody remembers. Required, the
compiler names each place that has to decide which instant it means, and a host
that forgets one fails the build instead of shipping the defect.

Where each instant comes from:

- A **server component** captures one per request with `renderInstant()`
  (`web-ui/app/lib/rendered-at.ts`) and passes it down. It is a function, not a
  module constant: a constant is captured once when the module loads and then
  served to every later request, so a long-lived dashboard process would render
  every age against the instant it booted. `exceptions-page.test.ts` pins that
  by rendering the route twice under two clocks.
- A **client component** that must not go stale feeds it to `useRenderClock`,
  which returns that instant for the render React compares against the server's
  HTML and the live clock from the commit after. It is built on
  `useSyncExternalStore`, whose third argument IS the server snapshot, so the
  split is in the signature rather than in a comment about effect ordering.
  Freezing is the floor everywhere; the refresh is applied where a derived
  lifecycle decays — a temporary grant expires in 30 minutes and a dashboard tab
  outlives that, so a frozen instant would label an expired grant `active` and go
  on offering to revoke it.

The remaining hole — satisfying the required argument with a fresh clock read at
the call site, which typechecks perfectly — is closed by the ambient-clock
selectors above. They are scoped by `Program:has(> ExpressionStatement[directive=
'use client'])`, so they fire only where the directive is a real directive-prologue
statement: a **server** component may still read the clock, which is what makes
capturing an instant possible at all, and a file that merely mentions the string
as a value is untouched. `Date.now()` and a zero-argument `new Date()` are clock
reads; `new Date(iso)` and `Date.parse(iso)` parse a value the caller already had
and are deliberately left alone.

Two things about that ban are worth knowing before trusting it. It reaches what
`react-hooks/purity` cannot — that rule reports a clock read inside a COMPONENT,
so a module-level helper in a client file is invisible to it, and that is exactly
where the one site this sweep did not find by hand was living
(`HarnessInventory`'s `formatEvent`). And it cannot follow a binding, so a clock
reached through an imported helper goes unseen; the required argument is what
covers that direction. `packages/dashboard-ui/src/lib/useRenderClock.ts` is the
one sanctioned reader, and its exemption is written in that package's
`eslint.config.mjs` through `presentationalSyntaxBans({ allowAmbientClock: true })`
— the presentational form, because a per-file entry re-states the whole rule and
one written through bare `reactSyntaxBans` would also drop the locale ban's
`src/**` widening for that file.

**A locale-formatted string is the same class, and it is closed the same way.**
`toLocaleString()` and its siblings, called with no locale, format in the
RENDERER's own locale, and the server's need not be the browser's: a Node host on
en-US emits `6,456` where a de-DE browser hydrates `6.456`, and passing one
instant does nothing for that. A server component has the mirror-image defect — it
renders once, but in the Node process's locale rather than the reader's. So the
locale is a second value a route captures per request and passes down:

- **`renderLocale()`** (`web-ui/app/lib/render-locale.ts`) reads the request's
  `Accept-Language` header and resolves it through `resolveLocale`
  (`packages/dashboard-ui/src/lib/locale.ts`) to the highest-weighted tag this
  runtime can format, else `en-US`. It is the sibling of `renderInstant()`, and
  for the same reason a function rather than a constant.
- Every shared formatter takes the locale as a **required** argument —
  `formatNumber` (`lib/numberFormat.ts`), `formatDateTime` (`lib/dateFormat.ts`),
  `startLabel`, `eventTime`, `fmtDateTime` — and every view that formats a count
  or a time takes a required `locale: string` prop, beside `renderedAt`. A
  default would hide every call site that forgot one, exactly as it would for the
  instant.
- The **ambient-locale** selectors are the ban that stops a call site formatting
  around those helpers: an argument-less `toLocale*String()`, its `[]` and
  `undefined` spellings, and the `Intl` formatter constructors in the same three
  forms. Unlike the clock ban, nothing in a UI package legitimately reads the
  runtime's locale, so it is widened to every module in `dashboard-ui` and
  `ui-kit` (`src/**`) and in `web-ui`'s `app/**` and `middleware.ts` — server
  components included, which is where the server-locale form lived. That
  widening is held against each package's REAL resolved config by
  `packages/eslint-config/test/package-walls.test.js`; `ambient-locale.test.js`
  tests the selectors and cannot see a config that stopped applying them. A NAMED locale passes, which is
  what lets the deliberate pins stay: compact notation (`compactCount`,
  `compactNumber`) is pinned to `en-US` because K/M/B/T is a product-wide
  convention shared with the CLI and the plugins, and `relativeTime` is pinned to
  `en` because its words are the dashboard's English copy rather than a format.

Two things this does not reach. The time ZONE is still each renderer's own; the
dashboard answers only loopback requests (`web-ui/middleware.ts`), so the browser
and the server share a machine and a zone, and a request carries no zone to pass.
And the same locale can still format differently under two ICU builds — Node's and
the browser's — so a CLDR change between them is a residual mismatch no prop
closes. Two suites hold the rest, one per layer.
`web-ui/test/pages/locale-hydration.test.ts` server-renders the route CLIENT
components and the dashboard views — never a `page.tsx` — under one runtime
default and hydrates them under another (`test/helpers/runtime-locale.ts` moves
the default); its first cases are the control that a bare `toLocaleString()` is
reported through the same harness. `web-ui/test/pages/render-instant-wiring.test.ts`
calls the pages themselves, and is what proves a route reads the request's
`Accept-Language` and hands that locale to every consumer.
`suppressHydrationWarning` silences a warning without reconciling anything, so it
is never a substitute for passing an instant or a locale.
