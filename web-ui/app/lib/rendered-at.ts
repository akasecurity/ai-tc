// The one instant a route renders against.
//
// Every relative label and every time-derived badge on a page has to be computed
// against the SAME instant during the server render and during hydration, or the
// two produce different HTML whenever a rounding boundary falls between them —
// which React resolves by discarding the server's markup for that subtree. The
// views make that impossible to forget by requiring the instant as a prop (see
// @akasecurity/dashboard-ui's lib/relativeTime.ts); this is where a route gets
// one to hand them.
//
// It is a function rather than a module constant on purpose: a constant would be
// captured once when the module first loaded and then served to every later
// request, so a long-lived dashboard process would render ages against the
// instant it booted.

/**
 * The instant this render is measured against, in epoch milliseconds.
 *
 * Call once per request, in a Server Component, and pass the result down. A
 * client component that wants the label to keep up after hydration feeds this
 * to `useRenderClock` rather than reading the clock itself.
 */
export function renderInstant(): number {
  // The lone ambient-clock read on the render path, and it is the point of this
  // module: the value is serialized to the client so both renders agree on it.
  // No `react-hooks/purity` disable is needed here and one must not be added —
  // the rule reports a clock read inside a COMPONENT, and this is a plain module
  // function, so a directive would be an unused one (which this repo fails on).
  return Date.now();
}
