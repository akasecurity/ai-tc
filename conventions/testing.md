## Testing

```bash
pnpm test                                    # all workspaces
pnpm test --filter @akasecurity/detections   # just the detection engine + fixtures
pnpm test --filter @akasecurity/persistence  # just the local-store adapter + repositories
```

Never mock `node:sqlite` or the filesystem — every store test runs against a real
database in a real temp dir, which is what catches real SQLite semantics.

### Coverage: per-package floors, no global threshold

Every package's `vitest.config.ts` spreads one shared block —
`coverageOptions(import.meta.url)` from `test/vitest/coverage.ts` — which carries the
provider, the reporters, the exclude list and **that package's floor**. A package with no
entry in `COVERAGE_FLOORS` throws rather than defaulting to zero, because an unlisted
package is one nobody chose a floor for.

Four properties are load-bearing:

- **Coverage is always on, not behind `--coverage`.** `turbo.json` declares
  `outputs: ["coverage/**"]` for the `test` task, and an output a task produces only
  sometimes is worse than one it never produces: turbo restores outputs on a cache hit, so
  a hit taken from a run without the flag hands back a report belonging to another commit.
  Unconditional is what makes that declaration true — and what makes a floor bind locally
  rather than only on the machine that remembered the flag.
- **There is NO global or aggregate threshold, and adding one is a regression.** It would
  be satisfied by covering `dashboard-ui`'s SVG icon sheet while a mutating Server Action
  stayed at zero — the number rises, the risk is untouched. Floors are per package and
  cannot be paid off that way. `coverage-config.test.js` pins the floors table as an
  **exact** set against the packages that run tests, so a global threshold has nowhere to
  live in it.
- **`test/vitest/**` is in `globalDependencies`.** It holds the floors, which are what
  `test` is allowed to pass with. Outside the hash, lowering one would move no package's
  hash and every package would replay a cached green taken under the stricter floor.
- **Floors are MEASURED, never estimated.** Each is one point below what its suite actually
  reported, with the measurement in a comment beside it. The estimates this replaced were
  wrong in both directions — `scanner` read ~75% and measures 96.8%, while four packages
  measured _below_ the floor their estimate implied, which would have failed CI on the
  first run. Numbers were taken on macOS/Node 24; platform-gated code (the macOS keychain
  backend most clearly) can read lower on another leg, and the fix there is to re-take that
  package's number on the platform that reports lowest — not to widen every floor.

The second half is **diff coverage**: of the lines a PR adds, how many does the suite
execute? A global percentage on a repo this size moves by fractions on any one PR, so it
can neither pass nor fail one honestly. `tools/coverage-gate` reads the reports
`turbo run test` already wrote, intersects them with the diff against the merge base, and
reports to the PR's step summary. It is a workspace tool rather than a third-party
uploader, so no coverage data leaves the runner.

```bash
pnpm turbo run test          # writes every package's coverage/ report
pnpm check:diff-coverage     # then measures the diff against origin/main
```

### Benchmarks are a trend, never a gate

```bash
pnpm bench                                    # every package that has benchmarks
pnpm bench --filter @akasecurity/detections   # just one
```

`vitest bench` (no second framework), one `bench/*.bench.ts` per package, a `bench` turbo
task, and a nightly `bench.yml` on `main` that uploads each package's
`bench-results.json` as a workflow artifact. **Nothing gates a PR on wall-clock.** Hosted
runners vary by a large factor on neighbour load alone — this repository has retuned three
timing assertions for exactly that — so a wall-clock check on a PR fails for reasons
unrelated to the diff, and a check that cries wolf is one people learn to re-run until it
is green.

What DOES gate a PR is the timing **guards**, which are correctness assertions rather than
measurements: the adversarial-rule bound in `packages/detections/test/security/redos.test.ts`
and the isolation ceilings in `packages/plugin-sdk`. Keep the two apart — a benchmark that
threw would be a timing gate wearing a different name.

A guard is only a correctness assertion while a loaded runner cannot fail it. The ReDoS
growth tier reads the scanning thread's CPU time on every platform — a thread waiting for a
core accrues none of it, where elapsed time on a loaded runner grows faster than the input
and failed linear rules as superlinear and as over budget — and never falls back to the
wall clock. That clock steps by up to 16 ms (the Windows runner), so each pair reading
repeats its scan until the clock has advanced by `GROWTH_WINDOW_STEPS` measured steps and
reads the cost per scan (`windowReadingMs`), which bounds the rounding to one step in that
many; a pair whose larger text reads under the 5 ms floor beyond one step is cleared after
a few scans rather than a window. Both sides of a ratio are the FASTEST of their windows,
taken in the same rounds, since what load adds to work only ever adds. Growth is judged over
two doublings, never one: a pair is read with the next doubling whenever it grew by more than
`SAMPLED_GROWTH` (the ratio's square over 4, so a quadratic next doubling could carry it), and
is superlinear when the second doubling grew past `MAX_GROWTH_RATIO` and the two together past
its square. One doubling cleared a quadratic control on the Windows leg: under load that
pattern reads 2.8x to 3.3x on the pair, under the ratio before any clock error, and 13x or more
over the two against a line of 9, where a linear rule reads 4x. The step is measured
by `packages/detections/test/helpers/growth-clock.ts`, a step it cannot measure is refused
rather than read, and the controls run on the native clock and on a forced 16 ms step. The
pair a ratio compares keeps all of its rounds when the next doubling goes over budget. The
per-rule walk screens on process-wide CPU, and a breach there is measured again on a fresh
worker thread charged with that thread's own CPU — a new isolate, so the regex runs
interpreted again as a hook process does (re-measuring on the same thread would measure
the compiled tier, see `worstProbeMs`) — and only that second reading decides, clearing
the rule only when it reads at least one measured clock step under the budget, since a
stepped clock reads low by up to a step. A control case holds the re-measurement to the
interpreted cost: more than three times the same probe's compiled cost on the calling
thread, read unquantized and the bound floored at one clock step, on the native clock and
on a forced 16 ms step; a reading within a step of either line is skipped as unmeasurable
rather than judged. `packages/detections/test/security/unicode.test.ts`'s
one-BOM slow-path ratio reads the fastest of the growth tier's windows and fails only when
three attempts breach. And a guard whose subject has a countable unit counts it rather
than timing it — `mergeOverlappingSameRule`'s growth guard counts the uses of the span
bounds it compares, and the browser extension's SSE rescan guard counts the characters the
string builtins examine (`plugins/browser-extension/test/helpers/scan-meter.ts`).

Six properties are load-bearing, and each is enforced by
`packages/eslint-config/test/bench-harness.test.js` rather than remembered:

- **`cache: false` on the `bench` turbo task.** Every other task derives its output from
  its inputs, so replaying one is sound; a benchmark returns a MEASUREMENT, and the machine
  it ran on is in none of the hashes. A cache hit hands the trend another runner's number
  and labels it this run's — the one stale green that cannot be spotted by reading it.
- **A package holding benchmarks declares a `bench` script.** `turbo run bench` skips a
  package without one silently and exits 0, so the nightly job goes on reporting success
  having measured nothing.
- **`bench/` is a lint target and a tsconfig `include` like any other source directory.** A
  bench file imports product code; outside those, its types are stripped unchecked and the
  network bans never apply to it.
- **`bench.yml` has no `pull_request` trigger**, still runs nightly, and still uploads.
- **`bench.yml` actually invokes the task.** An upload step is not a measurement: a
  workflow that schedules, checks out, installs and uploads — but never runs `pnpm bench` —
  satisfies every other property here, finds no files, and WARNS rather than failing,
  because `if-no-files-found: warn` is part of what keeps the job advisory. The Actions UI
  shows a green nightly run either way while the trend silently stops gaining points.
- **A claim about how the benchmarks run names the unattended run, wherever it is made.**
  The turbo comment is not the only place the repo explains this — a perf suite saying why
  its durations live in `bench/` rather than in an assertion makes the same claim about the
  same sibling file, with nothing between them. That is not hypothetical: this walk suite's
  header called the benchmarks "run by hand" in a comment written four hours AFTER
  `bench.yml` landed, and stayed green through the merge and every run since. So the sites
  are DERIVED rather than listed — any prose block in the tracked tree that talks about
  benchmarks and says a human is the only thing that runs them — because a two-entry list
  would read as exhaustive the day a third site was written. A specimen of the bad phrasing,
  quoted anywhere, is a real match rather than a false one; describe the shape instead, or
  name the workflow in the same block.

A benchmark carries no assertions, so anything a bench file would otherwise have checked
about its own input belongs in a test instead. `generateCaptureCorpus` is the worked
example: it writes through the product's own `recordCapture` (so the corpus cannot drift
from what the product writes), wraps the whole corpus in one transaction, and — because
`recordCapture` is fail-open — **counts the rows that actually landed and throws when they
are not there**. Without that last check a locked or full store hands back an empty one and
every downstream measurement is a timing of nothing, reported as a fast one.

### Store scale: what is bounded, and what grows for ever

`packages/persistence/test/performance/` holds the scale guards, and they are **tests
rather than benchmarks** because each asserts a size, a query plan or a row set — none
of them a wall clock. A benchmark reports a trend and gates nothing; these fail a PR.

**No gate here asserts an elapsed time against a budget, and one used to.** The two
per-call store costs are gated as a **ratio of the same cost at two store sizes**
(`scale-budgets.test.ts`, 2k against 20k), because a ratio cancels the runner: half the
machine halves both sides and moves the quotient not at all. The absolute form was tried
first — a p95 against a budget ~165x the median, which reads like unmissable headroom —
and it reddened a healthy tree twice, at 43 ms and 277 ms against a 30 ms budget on one
commit. A shared runner does not get 1/165th as fast, it gets **preempted**, and a
preempted sample has no upper bound; no headroom multiple fixes that. Anything newly
added here follows the ratio shape, and **`p95` is not the estimator to build one from** —
measured across idle and 3x-oversubscribed runs, a p95 ratio spread 4.6x on capture and
17x on open, where the same ratio over the **fastest** sample spread 1.08x and 1.06x.
Noise only ever adds time, so the minimum of n is the estimator a loaded runner cannot
inflate.

One absolute bound survives, and only as a **gross-regression backstop** four orders of
magnitude clear of the measurement: a ratio is blind to a constant-factor regression
(0.06 ms → 500 ms at every size keeps a ratio of 1.0), just as the backstop is blind to a
scaling one. They catch different defects; neither substitutes for the other.

The numbers, measured on arm64 macOS / Node 24 against corpora from
`src/test-fixtures/generate.ts`. The two ratio rows are ranges over six interleaved runs of
the suite itself (below), three on a machine carrying a video call and an antivirus scan and
three with 24 CPU burners added on its 8 cores:

| Property                                    | Measured                             | Gate                   |
| ------------------------------------------- | ------------------------------------ | ---------------------- |
| Store growth, 5k → 10k                      | **1,066.6 B/event** marginal         | ±15% band ✅           |
| `recordCapture` 2k → 20k                    | ratio **1.02–1.08** (fastest of 200) | ratio < 3 ✅           |
| `openLocalDatabase` 2k → 20k                | ratio **0.72–1.03** (fastest of 20)  | ratio < 3 ✅           |
| `recordCapture` at 1M rows                  | 0.076 ms median, 0.116 p95 (n=200)   | backstop ≤ 1,000 ms ✅ |
| `openLocalDatabase` at 1M rows              | 0.55 ms median, 0.72 p95 (n=20)      | backstop ≤ 1,000 ms ✅ |
| `/security` (8 aggregations) at 50k events  | **159 ms** (was 11,197)              | 3 flatness ratios ✅   |
| `/security` (8 aggregations) at 150k events | **350 ms** (was 125,987)             | 3 flatness ratios ✅   |
| `/security` (8 aggregations) at 300k events | **729 ms**                           | 3 flatness ratios ✅   |
| `/security` at 1M events                    | **~2.5–3 s** extrapolated            | ungated, unmeasured ❌ |

**Both pairs came down from a decade higher, and the reason is worth carrying.** They
were 5k → 50k and 10k → 20k, and at those sizes the two files were the largest single
pieces of work `@akasecurity/persistence` does — `scale-budgets` seeded for 117 s on a
macOS CI run that passed and 135 s on one that did not, against a 120 s hook ceiling. A
3% margin is not headroom, and it landed both ways inside one afternoon. The property in
each case is a RATIO or a SLOPE, and neither needs a particular absolute size, so the
corpus came down rather than the ceiling going up. The prices are stated where they are
paid: the ratio's sensitivity floor moved by 2.5x (below), and the growth band's centre
had to be retaken, because the marginal creeps with size — 902.8 B/event across 2.5k→5k,
902.8 across 5k→10k, 923.2 across 10k→20k, all measured, all byte-identical run to run.
**Do not carry a centre across a size change**; a stale one still reads green.

**Nor across a SCHEMA change**, which is what moved it last: migration 0029's
`idx_audit_capture_rollup` is bytes per row like any other index, and the 5k→10k marginal
went 902.8 → 1,048.6 — past the old ceiling of 1,038.2, which is how it announced itself.
That is the index being paid for rather than a regression, and the figures above describe
the corpus before it. Migration 0037 moved it again, 1,048.6 → 1,066.6 (+1.7%): three nullable
`inspection_findings` columns and a partial index, paid for even by findings that leave all
three empty. Inside the band, so nothing failed — which is exactly why it was re-taken anyway.

**Nor across a CORPUS change, which is the harder one to remember because the test's own
size did not move.** That centre was 797.9 until the generator's finding rate went from
0.1 to a measured 0.33: three times the finding rows per event took the marginal to 902.8,
which the old band's 917.6 ceiling **passed, by 1.6%**. So a 13% growth regression went
undetected and the band was left one unrelated commit away from failing for no reason — at
which point widening it is the obvious-looking fix. Re-take the centre whenever anything
about the corpus moves, not only its event count.

**A ratio gate has a sensitivity floor, and it is worth knowing before trusting one.**
The quotient is `(base + 10k) / (base + k)`, so clearing a ceiling of 3 needs the
size-dependent term to reach 2/7 of the baseline — ~15 us against `recordCapture`'s ~53 us
(measured 53.4 us at 2k and 53.0 us at 5k, i.e. flat in the corpus size),
i.e. a per-row slope of ~7.6 ns. Adding a `SELECT COUNT(*)` to that path is genuinely
linear and does **not** redden it: SQLite answers the count from a covering index. The
same scan with the index defeated (`WHERE LENGTH(id) = 999`, ~40 ns/row) reads 4.06–4.18
and fails. So a ratio gate catches a linear cost that changes what the operation costs, not
one inside its noise floor — and the floor is proportional to the SMALL size, so cutting
the pair by 2.5x raised it by 2.5x.

**Three of `/security`'s eight reads are BOUNDED, and a plan test cannot tell you that.**
`hot-read-query-plans.test.ts` drives every read the `/security`, `/activity` and
`/vault` pages issue and confirms each one runs indexed. That capture runs at 3k and
nothing re-captures the plans above it: the store carries no `ANALYZE` statistics, so
SQLite plans from the schema rather than from row counts and the plans are EXPECTED to
hold at 1M — reasoning, not a second measurement, and worth wording that way.

An indexed plan is not a bound, in either direction, and this page is where both halves of
that were learned. `mttrTrend` ran every step of its plan as a SEARCH while driving from
`audit_events` and joining every capture event before its window predicate could reject a
row. `recentFindings` now deliberately SCANS `idx_audit_started_at` so its `LIMIT` can stop
early, and EXPLAIN QUERY PLAN has no text for "terminates after 500 rows". So the plans pin
the mechanism and `security-page-scale.test.ts` pins the consequence, as a ratio across a
10x store step with `severitySummary` as the growth control. Neither implies the other.

`recentFindings`, `recentlyResolved` and `mttrTrend` are the three now flat in store size —
ratios **1.05–1.18**, **1.22–1.29** and **1.26–1.32** over 2k → 20k across the same six
interleaved runs as the table above, against a ceiling of 3 and a control reading
11.87–12.86. What each needed differs, and none of it was tuning:

- **`recentlyResolved` was QUADRATIC**, O(code_change events x resolved keys), because the
  join key was unreachable: `f` was reached FROM `latest`, so `latest` got probed on
  (rn, status, method) and the plan enumerated every pair before `f` could reject it. 10,966
  ms at 50k events and 125,322 ms at 150k — 3x the store for 11.4x the cost — returning 20
  rows. It read 8 ms to everyone who measured it before, because an EMPTY
  `finding_resolution` collapses the cross product to nothing.
- **`mttrTrend`'s `EXISTS` bounded the RESULT, not the scan.** Fixed by driving from
  `finding_resolution` over a `resolved_at` range. Migration **0021**'s index on that column
  is NOT what buys the flatness — remove it and the ratio does not move, because the
  latest-resolution derived table already passes over the whole table, so the read is
  O(resolutions) either way and resolutions are not the store. What it buys is the criterion
  the plan test hard-fails on: without it the driving step is a bare `SCAN fr`. Two guards,
  two different defects, and neither catches the other's.
- **`recentFindings` could not push its LIMIT down**, since the sort key sat on the joined
  table. Fixed with `+e.event_type` (making `idx_audit_type_t` unattractive, so
  `idx_audit_started_at` yields `started_at` order directly) plus `CROSS JOIN`.

**`CROSS JOIN` is load-bearing in all three and must not be tidied into `JOIN`.** In SQLite
it is semantically identical and exists only to stop the tables being reordered; with no
`ANALYZE` statistics the planner prices `event_type IN (...)` as a selective probe and puts
`audit_events` back on the outside. On `recentFindings` the unary plus ALONE recovers almost
none of the win — 23.6 ms against 0.9 ms with both, from 35.0 ms.

The page's `Promise.all` still buys nothing: every repository method here runs its SQL
**synchronously** and returns an already-resolved promise, so the page costs the SUM of the
eight.

**The dominant cost on a REAL store was none of the above — it was the ROW FETCH**, and the
analysis above could not see it because a generated corpus does not reproduce it. `content`
is declared before `attributes` in the record and holds whole file bodies on a
`code_change` (42 KB average, 1.79 MB at the top end), so on a field store ~91% of
`audit_events`' bytes are overflow pages, and reaching either `e.id` — this is a rowid
table with a TEXT primary key, so a secondary index entry carries the rowid and never
`id` — or any VIRTUAL column over the bag means walking that chain past the body, once per
row. Measured on one 6 GB store: the same 53,383 rows cost 14 ms read through a covering
index over two VIRTUAL columns and 5,020 ms read from the rows. Migration 0029's
`idx_audit_capture_rollup` carries `(event_type, started_at, repo, id)` for the four
capture kinds so the four broad rollups answer from the index, and the four reads carry
`INDEXED BY`; the page went ~15 s to ~2 s warm, with `topSources` — which needs `repo` for
every capture event in its window — going 8,278 ms to 72 ms WARM, and 8,922 ms to 74 ms
COLD. The pairs are like-for-like on purpose: a before-figure and an after-figure measured
in different cache states describe no speedup at all, and `security-probe-plans.test.ts`
quotes the warm pair against this same warm page total. Two traps come with it.
`EXPLAIN QUERY PLAN` will NOT say COVERING for a read naming `repo`, because SQLite counts
a generated column's dependency on `attributes` as a reference to the row even while
reading the value from the index, so the timing is the evidence and the label is not —
`security-probe-plans.test.ts` pins the index by name and requires COVERING only of the
reads that can reach it. And `LENGTH()` on a TEXT value **stops at the first NUL**, which
real bodies carry (134,576 rows on that store), so any size query over `content` must be
`LENGTH(CAST(content AS BLOB))` — the text form under-reported a 1.79 MB body as 9.

What the index does NOT fix is `findingsInRange`, which feeds `findingsTimeseries` and
`enforcementActions` and so runs twice per render: its cost is ~740k index probes across
369k findings, and folding the JS rollup into SQL was measured at 1.0x — no gain. That one
needs a rollup or a window, not tuning.

**What remains is `severitySummary`, the budget is still missed at 1M, and closing it is a
product decision.** Measured at three points — 159 ms at 50k, 350 ms at 150k, 729 ms at 300k
— and the page is mildly SUPERLINEAR rather than linear, which is the part a two-point
reading gets wrong. `severitySummary` carries that: 46.6 → 177.7 → 472.2 ms, i.e. 0.93 →
1.19 → 1.57 us per event, a cost per event rising ~1.33x per doubling (an all-time `GROUP BY`
whose temp B-tree and working set both grow with it). Everything else is flat or
window-bounded, so it goes from 29% of the page at 50k to 65% at 300k.

Carrying that factor from 300k to 1M puts `severitySummary` near **2.6 s** and the page at
**~2.5–3 s** — still OVER the 2,000 ms budget, with that one read accounting for ~85% of it.
Read the RANGE as the finding, not either endpoint: it is an extrapolation over 1.7 doublings
from three points whose slope is itself moving.

**Nothing here measures 1M, and the reason is the corpus rather than the reads.** Seeding is
badly superlinear — 142 s at 150k against 733 s at 300k, **5.2x for 2x the events** — so a 1M
corpus is tens of minutes and belongs in neither a test nor a session. Do not size a change
against a 1M figure from this section without taking it.

So the engineering half is done and the arithmetic says it is not sufficient. Bounding
`severitySummary` means a maintained rollup (exact, but invalidated from the resolution path
as well as the capture path, plus a backfill for existing stores), windowing the card (cheap,
changes what the number means from "ever" to "the last 30 days"), or retention on the corpus
itself. All three are product calls, not tuning.

**A VIRTUAL generated column is only faster than the bag when an index stores its value.**
The token rollup (`tokenReports` / `tokenReportForSession`) reads the `llm_call` usage
columns — model, provider, the four token counts and the tier, cache-split and web-search
members 0026 added — grouped in SQL per `(session, provider, model, service_tier)`, per
long-context band and per set of billed columns, and priced once per group, which the cost
model's linearity makes exact (activity.test.ts holds the SQL fold equal to the per-call fold
across every bag shape). The band is in the key because one request's prompt selects it, never
a sum; the billed columns are, because a summed group billing a column its model has no rate
for prices to null as a whole, and without them one such call would null the priced calls
beside it. That last part costs the all-time read ~9 ms at 50k calls (34 → 43 ms, fastest of
the run), still under folding the bags in JS. Naming those columns against the
TABLE is slower than parsing the bag in JS (137 ms against 98 ms at 50k calls), because each
VIRTUAL column is a `json_extract` recomputed per row; the read is fast only through
`idx_audit_llm_usage` (0027), a partial index over the columns that stores the values once,
at write (8.5 ms for a seven-day window against 31 ms, 38 ms all-time). Two things to know
before touching it. `INDEXED BY` is deliberate — with or without `ANALYZE` statistics the
planner prefers the event-type index and refetches every row — and the plan will never say
COVERING for an index over VIRTUAL columns, because SQLite counts the column's dependency on
`attributes` as a reference to the row even as it reads the value from the index; the
timing, not the label, is the evidence, and `token-rollup-plans.test.ts` pins the index by
name. The per-session form of the old fold walked EVERY `llm_call` in the store through the
event-type index to find one session's (17 ms at 50k, growing with the store); it now seeks
`idx_audit_session_type`.
**`/activity` had the same shape of defect, and the same pair of guards now holds it.**
`liveNow` walked every descendant of every open root to find the latest one, and on a real
store every root is open — the local writer never stamps `ended_at` on a session — so
"sessions live in the last thirty minutes" read the whole table on every page load: 90 ms at
200k captures, growing with history. It is driven from the rows active in the window now, as
three index ranges and one primary-key seek per root they name, with three `INDEXED BY`s
the planner takes none of on its own: whenever the range column is the second column of a
`(root_session_id, …)` index it prefers a skip-scan over every root through that index, and a
skip-scan over every root is the walk again (2.8 ms against 0.1 ms); and left to itself the
outer query enumerates every session root through an event-type-led index to test each
against the list — linear in roots, and invisible inside the `stats` composite because the
four day-windowed counters shrink faster than it grows (4.8x across a ten-fold store, 1.2x
pinned to the primary key, whose implicit index name the statement therefore depends on). The list's per-session rollups read partial indexes over their own kind
(migration 0028), and the last-activity rollup is two seeks per session through `json_each`.
`activity-page-scale.test.ts` pins the consequence on the real shape (`endedRate: 0`, 2k →
20k captures: before, `stats` 9.4, the first page 4.5 and the detail pane 3.5 across a
ten-fold store; after, every page-load read under 1), and `activity-probe-plans.test.ts` pins
each read to the index it must be seen using, which the plan test cannot — a per-root walk is
a SEARCH there. What still grows is the search: `q` matches `content` and a `json_extract` of
`detail` over every descendant in its window, twice (the page and the empty-session count); a
key-presence `LIKE` guard on that parse measured 48 → 43 ms per statement and was not taken.

**A corpus must never `ANALYZE`, and every kind-scoped read is pinned because of it.** The
shipped store never runs `ANALYZE`, so SQLite plans from the schema alone, and from the schema
alone `root_session_id IN (…) AND event_type = 'prompt'` takes an event-type-led index — every
prompt in the store, then a sort — over the per-root partial built for it; the same for the
detail pane's token sum, tool grouping and model list of ONE session (`~7 ms` of a
never-analyzed 20k store each, growing with it). The activity corpus first ran `ANALYZE` after
seeding, and with statistics all of those reads took the right index unpinned, so both guards
were green over plans no field store gets (review on the PR that added them; the ratios above
are from the never-analyzed corpus). Every `root_session_id … AND event_type = '…'` read on the
page now carries `INDEXED BY` its root-led index, `activity-probe-plans.test.ts` refuses the
two event-type-led indexes (`idx_audit_type_t`, `idx_audit_events_sync`) by name, and the
corpus helper says why it does not analyze. Two things to know when reproducing: a dropped
`sqlite_stat1` stays loaded on the connection that dropped it — measure from a fresh handle or
seed without ever analyzing — and a single-id `IN (?)` may plan differently from a hundred-id
one, so probe the page's real page size.

**Two tables have a ROW retention policy; six do not.**
`BLOCKED_DETECTIONS_RETENTION_MS` (24 h) sweeps `blocked_detections`, and
`EXCEPTION_RETENTION_MS` (90 days) sweeps terminal `exceptions`. `audit_events`,
`inspection_findings`, `inspection_definitions` and the three `secret_vault*` tables have
none — and `audit_events.content` is a full prompt corpus. The vault tables raise
a second concern beyond size: an entry nobody will reveal again is a ciphertext that
stays decryptable for as long as its key epoch survives. `retention-surface.test.ts` pins
the split behaviourally, with a positive control on the swept pair, so adding retention
for one of the unbounded tables is a deliberate edit rather than a silent one.

**A THIRD sweep expires BODIES, and it is on neither list because the lists are about
ROWS.** Local body expiry (`bodyRetention` in settings, OFF by default, 30 days when
switched on) clears `audit_events.content` past a horizon and stamps `content_expired_at`;
the row, its timestamps and severity, and every finding derived from it are kept, so
`audit_events` stays among the tables nothing sweeps. The one thing a finding loses is its
masked excerpt (`inspection_findings.context`, the lines the dashboard drawer shows): it is a
copy of the body's lines, so it goes with the body, and a `tool_call` finding's excerpt —
which has no body to follow — goes once its event is past the same horizon. Its `line` and
`col` stay. An excerpt beside a body the sync lane holds stays with that body. That is where the bytes are — one
measured 6 GB store carried 5.27 GB of body text, 4.85 GB of it `code_change` at 42 KB a
row — so this is the difference between a store that settles and one that grows at
~165 MB/day for ever. Three things about it are load-bearing. **The sync lane is gated**:
a `prompt`/`response`/`tool_use` body with `synced_at IS NULL` expires only when nothing
could still make it owed. `canSweepSyncLane` is the yes-or-no (a standalone machine with no
half attachment and no history-sync grant lets the lane age out like any other body), and
`syncLaneRetentionFor` in plugin-runtime refines it through `syncLaneRetentionOf` once an
attachment can be scoped. It is the one helper the background pass and `aka prune` both
call, each handing it the settings it read, so the same settings and credential give the same answer. A
machine attachment, half an attachment, and a history-sync grant with no scoped attachment
hold every unsynced body, and so does every failure: an unreadable credential, a scope
record that is absent, for another deployment or partly invalid, or a throw. A scoped
attachment holds the bodies of its enrolled repositories and any body still marked owed (an
earlier machine attachment's undelivered forward leaves that mark, and enrolling its
repository later makes it reachable), and lets every other body age out, since nothing can
forward those from a scoped machine. **It deletes no row**, and `retention-surface.test.ts`
now runs it in the same pass as the other two so that membership is a live assertion
rather than a claim. **It frees no disk by itself**: SQLite returns the pages to its
freelist, so new captures reuse them and the file stops growing, but the file does not
shrink without a `VACUUM` — and an in-place one on a live store is unsafe here, because a
held handle blocks the rename on Windows and loses writes to the unlinked inode on POSIX.
`aka prune` runs a pass by hand; `triggerContentRetention` runs one hourly from
SessionStart, in a detached child, never on the hook thread.

**The horizon is configurable, and its RANGE has one definition.** `bodyRetention`
(`{ enabled, retainDays }`, default `{ false, 30 }`) is editable under Settings → Storage
and pinnable by an administrator as ONE unit, the way `runMode` + `controlPlane` are — a
lock that froze the toggle while leaving the day count editable would not be a retention
policy. `BodyRetention`'s own `min(1).max(3650)` is the only place a legal window is
defined: `SaveSettingsInput` checks the SHAPE and the action checks the RANGE against that
schema, so the two cannot drift. An out-of-range horizon is **refused, never clamped** —
silently rounding one expires a different set of bodies than the user asked for, and
expiry is not undoable. The Settings control holds the field as raw TEXT and disables Save
while it does not parse, because parsing per keystroke cannot represent a half-typed or
emptied field without substituting a horizon nobody chose.

**`wal_autocheckpoint` is not set, and that does NOT mean the WAL is unbounded.**
`openWithPragmas` leaves it alone, so SQLite's own default of 1000 pages applies: at the
store's 4 KiB page size the log settles at about 4.2 MB and stays there over 20,000
committed captures. The unbounded case is a long TRANSACTION — a checkpoint cannot run
inside one — where the same writes grow the log nearly four times as far (both figures sit
beside `MEASURED_SETTLED_WAL_BYTES` in `store-growth.test.ts`, and are not restated here),
and the fixture generator's 1M-event transaction grows the log by its whole page footprint,
which is hundreds of megabytes. Nothing on the capture path does that (every
`recordCapture` commits, and every hook is its own process), but a batch importer would.
Do not "fix" the pragma without re-reading `store-growth.test.ts`.

**That same property makes a two-size RATIO test compare two different states, and it has
cost a red `main`.** `seedCaptureCorpus` commits its whole corpus in one transaction, so
the log it leaves is the seed's entire page footprint rather than the steady state above —
measured 4,132,392 B for 2,000 events against 17,637,752 B for 20,000, a factor of 4.27
that belongs to the FIXTURE and to nothing the product does. Every measurement taken
against those stores then carries a log-proportional cost on one side only. It reads as
nothing while the pages are cached, which is why `scale-budgets.test.ts` reported a
`openLocalDatabase` ratio of ~1.0 locally and on CI for months; on a runner executing the
whole workspace suite in parallel those pages are not resident, and the same asymmetry
arrived as a ratio of **3.619** (2.1464 ms against 7.7686 ms) against a ceiling of 3 — on a
commit whose diff touched `CLAUDE.md`, a shell script and one unrelated test file, with no
product code in it at all.

So a file that seeds two sizes and divides one measurement by the other **checkpoints after
seeding** (`PRAGMA wal_checkpoint(TRUNCATE)` through `corpusConnection`), which leaves both
stores at the steady state — measured 4,148,872 and 4,144,752 B, i.e. equal — so the cost
cancels in the ratio the way every other shared cost does. All four two-size suites here —
`scale-budgets`, `security-page-scale`, `findings-page-scale` and `activity-page-scale` —
do this. It equalizes the LOG and not the DATABASE (2.2
MB against 17.0 MB, still 7.7x apart), so a size-dependent cost in the thing under test
survives it: verified by mutation, an index-defeated per-open scan fails at 4.14 with the
checkpoint and 4.08 without. `store-growth.test.ts` is the deliberate exception — the
unbounded log is what it measures, so it must NOT checkpoint.

The failure this guards is quiet in the wrong direction: it reddens a tree whose diff
cannot explain it, and the obvious-looking fix is to widen `FLATNESS_CEILING`. Widening it
answers a state mismatch by weakening the one number that separates flat from linear.

**The same file also samples the two sizes INTERLEAVED, and that is the other half of the
same contract.** A checkpoint puts both stores in one STATE; it says nothing about WHEN
each is timed. The four suites used to time each store straight after seeding it, which
put the large store's samples several seconds of CI seeding after the small store's — and
a fastest-of-n survives a slowdown that reaches SOME of a side's samples, never one that
lasts through all of them on one side only. That is how `activity-page-scale.test.ts`
reddened a Linux CI leg at a ratio of **3.035** (1.974 ms against 5.989 ms) on a change
whose diff could not reach this package, while the same run's two other full-suite legs
passed it. So both stores are seeded first, and every probe is then timed against the two
in alternation through `test/helpers/interleaved-samples.ts`: one probe per block, the
leading store alternating per iteration and per block, and the microtask queue drained
between blocks. Its own suite pins each of those without a clock. **Do not hand-roll the
loop in a new two-size suite** — the four copies it replaced had each got block entry
wrong in the same way, and a copy's defects are visible to no assertion but its own.

**That WAL case runs its fixture connection at `synchronous = OFF`, which is NOT the
product's configuration — and the quantity it asserts does not depend on the difference.**
Demonstrating the bound needs 20,000 SEPARATE commits — a checkpoint cannot run inside a
transaction, so batching them removes the property under test — and `openWithPragmas`
leaves `synchronous` at node:sqlite's compiled `SQLITE_DEFAULT_WAL_SYNCHRONOUS=2`, where
every one of those commits fsyncs the log. That made the setup cost the runner's fsync
latency times twenty thousand, and it overran its 180 s hook ceiling on a commit whose diff
could not reach it. At `OFF` the loop makes no fsync at all; `NORMAL` is not enough, because
it still syncs at every checkpoint. Durability moves the cost and not the log — the
autocheckpoint counts frames, and a frame is the same bytes synced or not — so both
measurements the ceiling sits between read identically under `FULL` and `OFF`. Those
measurements live beside `MEASURED_SETTLED_WAL_BYTES`, and the fsync counts and the
injected-latency reproduction in the fixture's own comment, and are deliberately not
restated here. The case reads back every pragma the result depends on — `synchronous`,
which SQLite silently resolves to `NORMAL` when handed a value it does not recognise, and
the `wal_autocheckpoint` and `page_size` the peak is a product of — so each is held by
assertion rather than by comment. A slow setup there is never answered by lowering the
autocheckpoint, cutting the event count or raising the ceiling.

It is still **skipped on Windows, on cost rather than on behaviour.** It overran its own
180 s setup ceiling on that leg while every commit was an fsync, and starved neighbouring
suites on the shared leg while doing it; what the loop costs there without those fsyncs has
not been measured, so the skip stands until it is. What it asserts is SQLite's page
arithmetic, which does not vary by filesystem, so the other two legs cover it. Lowering the
event count instead is the worse trade: the count is what puts a log that never
checkpointed several times over the ceiling, so cutting it weakens the assertion on every
platform to buy coverage on one.

**`packages/persistence/bench/` is a separate tier, and it gates nothing.** `pnpm bench`
(turbo task `bench`, `vitest bench`) reports a TREND — the trajectory the table above was
taken from — and carries no assertions, because this repo does not gate a PR on
wall-clock. Its turbo task sets `cache: false`: every other task returns the same answer
for the same inputs, but a benchmark returns a measurement, and the machine it ran on is
not in the hash, so a cached hit would report another runner's number as this run's.
The nightly `.github/workflows/bench.yml` runs it unattended and uploads each package's
`bench-results.json`; the table above was taken by hand and is re-taken the same way.
Never wire it to a PR gate. Anything that must HOLD belongs in `test/performance/`
instead — restated as a **ratio** against a second store size, not carried over as the
elapsed number the bench prints, which is the one form that cannot survive a shared
runner.

Corpus scale is what decides where a scale test can live. Seeding is not flat per event,
so a six-figure corpus belongs in a `beforeAll`, where it is charged to `hookTimeout`
rather than eating a test's own budget before the first assertion. A synchronous body
cannot be interrupted, so one that overruns runs to completion and is then reported as a
timeout, which reads as a budget failure and is not one. Cut the corpus rather than
raising the ceiling.

**Take the rate yourself before sizing anything against it, and take the CI-to-local
FACTOR too — that factor, not the local rate, is what has cost a red main.** Measured as
the fastest of three seeds into a fresh store through `seedCaptureCorpus`, one warm-up
discarded, on arm64 macOS 26.5.2 / Node 24.18.0 with nothing else running: **0.0434
ms/event at 2k, 0.0427 at 3k, 0.0448 at 5k, 0.0558 at 20k, 0.0732 at 50k** (87 ms, 128 ms,
224 ms, 1.12 s and 3.66 s for the corpus). Seeding is not flat per event — it creeps ~1.7x
across that range — but there is **no step in it**, and no page-cache cliff: the rate runs
flat straight through 2,400 events (0.0434 / 0.0434 / 0.0427 at 2k / 2.4k / 3k).

What the 120 s ceiling in `scale-budgets.test.ts` was really missing is the runner
multiple. Seeding 5k + 50k costs 3.88 s locally, which is what that pair was sized
against and is accurate; the same hook took **116,970 ms on a macOS CI run that passed
and 135,237 ms on one that did not**, against a 120,000 ms ceiling — a factor of **~30x**,
not "several times". Size against the factor: 2k + 20k is 1.20 s locally, so ~36 s there.

Older figures in this section (a 0.091 ms/event rate at 3k, a cliff at ~2,400 events, and
the 100k and 1M rates of 0.096 and 0.639 ms/event) ran ~5-6x high and are retracted or
untaken. Re-measure rather than budget from them.

### The no-network guard

`test/setup/no-network.ts` is loaded by **every** package as a vitest `setupFiles`
entry. It refuses any outbound connection that is not loopback — TCP (and therefore
TLS, HTTP, HTTP/2, `fetch`), UDP, and the DNS `resolve*` family — and its error
**names the call site**, digging past ~60 frames of bundled undici to find the line
that actually reached out. It prefers this repo's own code over a `node_modules`
frame, since a transitive dependency reaching out is the case the ESLint ban cannot
see and the frame a reader has to act on is the one that called it. Loopback
(`127.0.0.0/8`, `::1`, `localhost`) and unix/named-pipe sockets stay open; the CLI's
port probe and the dashboard boot test depend on them.

**It covers `vitest bench` too**, and by construction rather than by a second wiring:
bench mode resolves the same `vitest.config.ts`, so the same `setupFiles` entry loads.
Both halves were confirmed live there — the throw on a non-loopback connect, and the
`afterAll` backstop that fails a run where a refusal was swallowed. What that argument
rests on is a `bench` script not steering vitest at another config, which
`packages/eslint-config/test/bench-harness.test.js` asserts: a bench-only config missing
the entry would run product code unguarded while every existing assertion here, all of
which read the config the `test` script uses, stayed green.

Five things about it are load-bearing:

- **A refusal is recorded as well as thrown.** Almost every boundary here is
  deliberately fail-open, so a throw inside a `catch {}` would be swallowed and the
  run would go green having reached the network. `afterEach`/`afterAll` fail on any
  undrained record. A test that provokes a refusal on purpose must drain it with
  `takeBlockedAttempts()`.
- **It imports `node:net`/`node:dgram`/`node:dns`, which the lint ban forbids.**
  That is the enforcement, not a violation. `packages/eslint-config/test/no-network-runtime.test.js`
  lints the file and fails if it trips a **fourth** ban.
- **It re-installs itself into every worker it can reach.** A `worker_thread` gets a
  fresh module registry, so a worker used to escape the guard **silently** — nothing
  threw, and the parent recorded nothing for `afterEach` to fail on, which is worse
  than a miss. The guard wraps the `Worker` constructor (both the module property and,
  via `syncBuiltinESMExports`, the named-import binding `isolated-scan.ts` uses) and
  appends `--import <itself>` to the worker's `execArgv`. Wrapping the CONSTRUCTOR
  rather than the call sites is what reaches a worker **product code** starts, which
  is the case that matters; a worker's refusal cannot land in the parent's array, so
  it goes to a file `takeBlockedAttempts()` drains alongside it. Three consequences to
  keep true: that file is written only when a worker actually **refuses**, so a run
  that reaches for nothing touches the filesystem never and the drain reads a missing
  file as "no refusals"; it is **appended to and never truncated**, because a
  read-then-truncate drain destroys a refusal appended between the two; and a nested
  worker reports to the same file rather than stacking another preload onto `execArgv`.
  Any read failure that is not `ENOENT` fails the run — a channel that cannot be read
  reports zero refusals, which looks exactly like a clean one.
- **A child process is invisible to it**, which is the whole reason the `No-network`
  CI job exists. Do not describe the guard as covering shell-outs — and note that a
  worker started **by** such a child is out of reach for the same reason, since the
  wrapper lives in this process and the child never loaded it.
- **Every package must wire it**, at the right relative depth. The same suite fails
  the workspace if a package drops the entry, points it at a path that does not
  resolve to the guard, or is added without one. That last one holds for packages
  that test through **vitest**; a package testing through another runner cannot load
  a `setupFiles` entry at all, so the suite enumerates every package with a `test`
  script and fails on any non-vitest one unless it is named in
  `EXPECTED_NON_VITEST_TEST_PACKAGES` (empty, and each entry would be a real hole).

The only opt-out is **`takeBlockedAttempts()`**, and there is no env escape hatch or
config flag. Draining is how a test consumes a refusal it provoked on purpose, so it
is also the way to hide one — the seam is deliberate, narrow, and visible in review.
A test that needs the outside world needs an injectable seam instead — `local-ops`'
`ReportDeps.viewDistTags` and `judge.ts`'s `spawnClaude` are the two worked examples,
and neither `vi.mock`s `execFileSync`: they take the boundary as a parameter, so the
network call site is never reached rather than being intercepted.

`dns.lookup` is deliberately **not** patched (the connect guard already gates what it
feeds). Be accurate about what that leaves: a bare lookup still discloses the hostname
to whoever runs the resolver, which is real egress even though it is not a dependency
on a remote service. Only the Linux `No-network` job blocks it.

**The CI script is a tested artifact, not a script nobody reads.** It is the only gate
covering child processes, and its whole value is a positive control that refuses to run
vacuously — which is worthless if nothing exercises it. The same suite drives
`tools/ci/no-network-test.sh` with a `PATH` of hand-written stubs and pins every
outcome: probe tooling missing, DNS still resolving, the target still answering, the
probe reporting itself broken, the probe file gone, no command to run, started as root,
the privilege drop-back not having landed, and the one green path where the command
actually runs.
Change a probe and a case fails; delete one and the case that covered it fails.

The drop-back case guards the only **silent** outcome on that path: as root the
read-only-store cases in `packages/persistence` report `effective: false` and **skip**,
so the run stays green having quietly lost them. Refusing to START as root guards the
front door only, which is why phase 3 asserts the drop-back landed as well — and why
`id` is demanded before any of it, since a missing `id` makes every one of those checks
evaluate false without checking. The full reasoning is in the script's own header and
phase-3 comment; it is not restated here, because a rationale kept in two places is one
that goes out of step.

### The no-managed-settings guard

`test/setup/no-managed-settings.ts` is the second shared setup file, wired beside
the no-network guard by every package whose dependency closure can load
`@akasecurity/persistence`. It declares, once per test file, that the machine has
**no administrator**.

The administrative overlay (§6) is read from absolute system paths — outside
`~/.aka` on purpose, so a lock is not removable by the party being locked — and
`base` redirects only the home. So a suite that builds a whole fake machine in a
temp dir still reads the REAL managed file, and its result depends on who ran it:
a laptop enrolled for dogfooding pins `runMode: attached`, which failed
twenty-eight cases across `persistence`, `plugin-sdk` and the CLI on a clean
checkout of main. CI has no such file, so CI stayed green and the failure landed
only on the machines with no gate on them.

Five things about it are load-bearing:

- **A per-call override cannot replace it.** `readEffectiveSettings` and
  `applyOnboarding` both take a `managedOverride`, and neither reaches the reads
  that actually fail: `db.installedPacks.setPolicy()` reaches
  `readWorkspaceSettings` through `openControlPlaneFloors`, and `aka sync-history`
  reaches it again inside the attached-mode pass. Threading a parameter there
  means a test-only argument on `openLocalDatabase` and on the history-sync deps,
  and the next deep caller reopens the hole. The property is process-scoped
  because the thing it describes — which administrator owns this machine — is.
- **It moves the DEFAULT only.** `readManagedSettings` still honours paths it is
  given, which is what keeps the managed layer's own suite testing the managed
  layer rather than asserting an unmanaged machine. Verified by mutation: making
  `overlayManagedSettings` a no-op still reds 39 of that file's 75 cases.
- **The seam it installs is test-only, and audited.**
  `UNSAFE_TEST_ONLY_setManagedSettingsPaths` is named by exactly one shipped file
  and is NOT re-exported from the package entry point — the same two properties
  the raw handle carries, held by
  `packages/eslint-config/test/test-only-seam.test.js`. The setup file reaches it
  by relative path, which is why no `exports` entry is needed.
- **It imports ONE MODULE, never the package barrel.** A setup file loads before
  every test file in every package that wires it, so whatever it imports is cached
  before any of them registers a mock. Importing the barrel pre-cached `paths.ts`,
  `fingerprint.ts` and the vault against the real `node:fs`, and the three suites
  that `vi.mock('node:fs')` and then `await import('../src/paths.ts')` got the
  unmocked instance back — nineteen cases failing on a branch they could no longer
  enter. Their own "the interception fired" guards are what caught it. That import
  is pinned by its own case in the guard suite.
- **A CHILD PROCESS is invisible to it**, exactly as one is to the no-network
  guard, and for the same reason: the pin lives in ONE process's instance of
  `managed-settings.ts`, and a spawned child loads its own copy with the shipped
  `null`. A redirected `HOME` does not move an absolute system path — which is
  the premise this whole section rests on — so the child reads the real
  administrator's file. Measured rather than reasoned: with the pin installed,
  the parent reads `null` while a child spawned with `HOME` redirected reads the
  machine's own managed values. Every suite that drives a BUILT script is on the
  far side of that boundary. `plugins/*/test/e2e/fail-open.e2e.test.ts` runs the
  built hooks under a redirected home and `loadConfig` applies the overlay inside
  the child, so an administrator pinning `redactFallback` — a key that is both
  pinnable and lockable — flips rows asserting an exact wire shape. Read that as
  REACHABLE rather than currently failing: those suites pass on the enrolled
  machine that motivated this section, whose file pins `runMode` and not
  `redactFallback`. `plugins/claude-code/test/e2e/content-retention-entry-bundle.e2e.test.ts`
  is a second suite on that side, and the sharper one: `bodyRetention` is
  pinnable too, and it is the whole subject of three of that file's cases —
  the two SessionStart cases and the one that runs the expiry child directly
  with no settings file — so a disagreeing pin would flip a case rather than
  perturb a wire shape. Those three read the machine's managed file
  themselves — by explicit path, since the pin moves only the default — and
  skip where it overrides what they write. A worker thread sits on the same boundary and is out of reach
  today only because `scan-worker.ts` takes no persistence dependency. It is
  documented rather than closed, because the no-network guard's own mechanism
  does not transfer: it reaches a worker by appending `--import <itself>` to its
  `execArgv`, and a child spawned with a deliberately minimal env cannot be
  reached that way. Nothing covers this the way the `No-network` CI job covers
  shell-outs.

### The PATH shim, and why it fails OPEN

A suite that drives a **built** script cannot reach that script's spawn seams — they are
in-process, and the script is another process. So the external command is faked by putting a
controlled executable first on the child's `PATH`: the journey harnesses' judge stub
(`claude`/`codex`/`agy`) and `plugins/claude-code/test/provenance.test.ts`'s fake `npm`.

**A shim that does not land is not an `ENOENT`.** Resolution walks the rest of `PATH` and runs
the REAL installed binary — measured by joining `PATH` with `';'` on a POSIX host, which
resolved and executed the live `claude` CLI. So the failure mode is a suite that looks hermetic
while reaching a live model or the npm registry, and no gate above sees it: the ESLint ban reads
source, the vitest guard cannot follow a child process, and the Linux `No-network` job is the
only one that would — on the one platform where the shim happens to work.

`plugins/*/test/helpers/path-shim.ts` is the shared answer, and it is a **peer copy per
plugin** for the reason `no-echo.ts` is: a package wall blocks the import, and a copy takes its
`path-shim.test.ts` with it — or `assertShimResolves` can be weakened back into a no-op with
every caller staying green. Four properties are load-bearing:

- **Resolution is PROVEN before a chain is driven, not assumed.** `assertShimResolves` spawns
  the command the way the code under test will, so a miss is a red setup rather than a live
  call. It **performs** resolution rather than modelling it, so it agrees with libuv about
  `PATHEXT` instead of restating it.
- **`shell` and `cwd` must mirror the spawn being stood in for**, because the probe cannot
  discover either and PATH is not the whole of resolution. `provenance.ts` exports its
  `USE_SHELL` so the probe imports the runner's own condition rather than re-deriving it;
  `triage/judge.ts`'s `spawnClaude` uses no shell. **Windows searches the working directory
  before walking PATH**, so a probe taken under a different cwd than its subject faithfully
  performs a resolution the subject never performs — which is why the journey harness keys its
  proof by cwd rather than latching it once, its `run()` taking a per-step cwd.
- **The probe answer comes before anything else the stub does**, so probing is never recorded
  as an invocation — which is what a `judgeWasInvoked()`-style sentinel assertion rests on.
- **Four POSIX-only defects, not one**: `path.delimiter` rather than a literal `':'`, a `.cmd`
  launcher on win32 rather than an extensionless `#!` file, no reliance on a `chmod` that
  is a no-op there, and the launcher naming its script by ABSOLUTE path rather than through
  `%~dp0`. `tools/portability-gate`'s `path-separator-literal` rule catches the first
  returning to a call site, which is how it arrived. The fourth is the one that reads as
  correct and is not: `%~dp0` means "the directory of the running batch file" only when `%0`
  holds a path, and for a batch cmd.exe resolved from PATH under a bare name `%0` is the name
  AS TYPED — so `%~dp0` expands against the CURRENT DIRECTORY instead. It went unnoticed for
  as long as nothing anchored the spawn's cwd; the moment §7's Windows anchor landed, every
  shim-driven suite in all three plugins failed with node reporting `Cannot find module` for a
  path under the anchor that nothing had written. Each plugin's `path-shim.test.ts` pins the
  launcher's bytes under an explicit `'win32'`, so a POSIX runner catches its return.

`writeCommandShim` takes an optional `platform` (as `judgeEnv` does), so both branches are
driven from either host: writing the other platform's form is a resolution failure on this one.
Pin the **artifact** as well as the refusal there — a branch that wrote nothing also refuses,
and reads identically.

Two smaller things the same reasoning decides. The probe's own deadline sits **well under the
package's `testTimeout`**, because it runs inside a test body: equal deadlines mean vitest wins
the race and the refusal — the whole point of failing closed — is replaced by a bare timeout.
And `shimmedPath` returns the bin dir **alone** when there is no base PATH: an empty PATH entry
means the current directory to execvp and to libuv, so a trailing separator quietly puts the cwd
on a search path whose only purpose is that nothing but the shim is on it.

### The adversarial fixture corpus

`test/fixtures/adversarial/hostile-repo/` builds the hostile trees the tree walkers
have to survive — symlink loops, `..`-bearing names, nesting past the depth a path can
address, a `.gitignore` that ignores everything, 500k files ignored by directory and
the same number ignored by pattern. It sits at the repo root for the same reason the
no-network guard does: `project-files`, `local-ops`' folder scan and `scanner` all need
the SAME inputs, a package wall blocks the import, and three private copies of a symlink
loop drift apart. All three drive it now, each from its own `test/performance/`
directory — and the two that were added last found two things a shared corpus is for: the
folder scan aborted its whole generator on one unreadable directory where the other two
tolerate it, and the three walkers disagree about a `..`-prefixed DIRECTORY, which the
folder scan's dot-directory floor refuses and the other two descend into. Both are pinned
where they differ rather than smoothed over.

The corpus is in `globalDependencies` (see "Adding a new workspace package" on why every
shared `test/` subtree must be): it is generated, so weakening a shape — shrinking the
tree, dropping the loop, breaking the deep chain — changes what every guard driving it
actually runs, and outside the hash those guards replay a cached green at the one moment
they are being changed. `packages/eslint-config/test/shared-test-inputs.test.js` derives
that requirement from what the tree really references rather than listing it.

Two things about it are load-bearing:

- **Generators, not checked-in trees.** Most of these cannot live in git at all, and
  the ones that could would read as a mistake in a listing. Everything goes into a temp
  dir and comes back out through `cleanup()`.
- **A shape that cannot be built everywhere reports `created: false` with a reason, and
  the caller `ctx.skip`s on it** — a symlink needs a privilege on Windows, `chdir` is
  absent in a worker thread. An early `return` would report as a pass, which is the
  failure mode the store harness exists to remove.

**Depth is the part that is easy to get expensively wrong.** Creating a directory whose
absolute path exceeds `PATH_MAX` means descending with `process.chdir`, and the OS
re-resolves an ever-longer working directory on every step — so that descent is
QUADRATIC. Measured on an arm64 Mac: the first 500 levels take 35 ms, the next 1,000
take 4.0 s, the next 2,000 take 31 s, and a 10,000-level chain costs ~348 s to build
and ~347 s to remove. `deepChain` therefore builds the addressable part with plain
absolute `mkdirSync` (one syscall a level) and gets PAST the ceiling by making a
handful of NAMES 255 characters rather than the chain deep. A fixture that reaches for
literal 10,000-deep nesting is not thorough, it is a timeout.

`packages/persistence/test/helpers/` holds the shared store harness. Tests **in this
package** import it rather than re-rolling the `mkdtempSync` + `openLocalDatabase` +
cleanup dance, and that is enforced rather than asked:
`packages/persistence/test/harness-adoption.test.ts` derives the file set from
`git ls-files` and fails on any suite that opens a store and builds its own temp tree.
It carries **no** exception for that pair. The suites that build a tree and open no store
are pinned as an EXACT set with a reason each — a floor would forbid removals while
letting the next hand-rolled teardown in, which is the direction this actually drifts.
That guard strips comments before it matches anything, because the count this replaced
was taken with a plain grep and came out two files high: `paths.test.ts` and
`local-layout.test.ts` name `openLocalDatabase` in prose and open nothing.

**Reach for `store.openRaw()` by default; a bare `new DatabaseSync` needs a reason written
at the top of the file.** `openRaw()` keeps every handle it hands out open until teardown,
so it is wrong in exactly two places. Where the CLOSE is part of the setup:
`legacy-writers.test.ts` replays a legacy _process_ — one connection, one statement, closed
again, never overlapping — and `legacy-compat-views.test.ts`'s fixture handles leave the
store at one point in a migration and close before the next pass drains further, so a live
handle changes what that pass does. And where the file is not the store at all: `openRaw()`
only ever opens `<home>/data/aka.db`, so a `.legacy.` backup copy or a moved-aside store has
to be opened by hand (`database.test.ts` has both).

**What is NOT a reason, though it reads like one, is a descriptor probe.**
`descriptorProbe().leakedBy` measures a delta around a **synchronous window**, so a fixture
handle opened outside that window sits in the before-count and the after-count alike and
moves the number not at all — only a handle opened _inside_ the window can. Measured rather
than reasoned: converting `database.test.ts`'s fixture handles to `openRaw()` left all 24 of
its cases green, which is what retired an earlier version of this paragraph claiming the
opposite.

**Outside `packages/persistence` the harness is deliberately NOT available, and the
decision is not "nobody got round to it".** It lives under `test/`, and the package's
`exports` map is `"." -> "./src/index.ts"` plus `"./sqlite-free"` (the store-free modules the
plugin-sdk runtime path needs: a subset of the root entry's bindings that never loads
`database.ts`, both held by `packages/persistence/test/sqlite-free-entry.test.ts`) — which is exactly
what makes `UNSAFE_TEST_ONLY_RAW_HANDLE` unreachable elsewhere. A `./testing` subpath would undo
that: `open()` hands back a spread copy that CARRIES the seam symbol, so every consumer
package would gain a supported route to the raw `DatabaseSync`, and
`test-only-seam.test.js` would stay green throughout because the new callers are tests.
The harness also imports `vitest` at module scope, and `noExternal: [/^@akasecurity\//]`
inlines whatever a shipped entry reaches. So store tests in `cli`, `local-ops`,
`plugin-runtime`, the three plugins and `web-ui` still roll their own, and each of those
is a teardown re-derived rather than reused. Closing that means a **separate dev-only
workspace package** built on the public index (the one route that keeps both properties),
with the full "Adding a new workspace package" checklist — its own lint config and script,
tsconfig, a vitest config wiring the no-network guard, and entries in
`EXPECTED_WORKSPACE_PACKAGE_NAMES` and `EXPECTED_VITEST_PACKAGES`. Tracked separately; do
not reach for a `./testing` export instead.

- `withTempStore(fn)` / `useTempStore(prefix)` — a disposable `~/.aka` (`settings/` +
  `data/`) whose handles are closed and tree removed for you. Use `useTempStore` when the
  suite shares setup across hooks, `withTempStore` when one test body owns the store. An
  async body is awaited before teardown.
- **`{ migrated: true }`** — the second argument to all three, and the one to reach for by
  default. `openLocalDatabase` runs every migration in the ledger on a store that has none,
  so a suite with per-test isolation rebuilds the whole schema on every test; this seeds
  `data/` from a template built ONCE per worker and copied. Isolation is unchanged — each
  test still gets its own file, and no handle is shared. Measured at roughly 9-10x cheaper
  per setup (`packages/persistence/bench/store-template.bench.ts`), which matters because
  the Windows leg charges about 30x local cost for exactly this work and a `beforeEach`
  that blows the hook ceiling fails a package the PR never touched.

  **It is opt-IN, and that is load-bearing.** A seeded store has nothing left to migrate,
  so a suite whose SUBJECT is the open path must not take it: migrations, the lineage
  reset, the `.bak` a fresh migration leaves beside the store, `aka init` creating the
  store, a first-run flow, or a fault injected so that `applyMigrations` is the thing that
  refuses. Those assertions would hold **vacuously** rather than fail — which is worse
  than losing them, because they go on reporting green. `test/helpers/store-template.ts`
  is the shared builder (six packages copy from it; `migrated-store.ts` is this package's
  build step), and it refuses a build that left no store, one that left a live `-wal`, and
  any seed over a store or a foreign log that is already there.

- `withTwoWriters(fn)` / `withWriters(n, fn)` — N independent `LocalDatabase` handles on
  one file, the shape the product runs in (hooks, CLI and dashboard share `aka.db` with
  only WAL and `busy_timeout` between them).
- `corpus.ts` — `seedCaptureCorpus(db, options)`, a deterministic store of a stated SIZE
  written through the product's own `recordCapture` inside one transaction, plus
  `corpusConnection(db)` and the corpus clock (`CORPUS_EPOCH_MS`, and
  `GeneratedCaptureCorpus.endsAt` — prefer the latter). Two rules. **Drive every windowed
  read with the corpus clock**, never `Date.now()`: the corpus is stamped from a fixed
  2024 epoch, so the wall clock puts every `WHERE … >= :from` years past the data and the
  read matches nothing while still returning a real plan and a real, meaningless number.
  And **reach the connection through `corpusConnection`, never `UNSAFE_TEST_ONLY_RAW_HANDLE`
  directly, from anything outside `test/`** — `bench/` is not a `test/` path, so a
  `*.bench.ts` naming that seam is read as a product caller and fails
  `packages/eslint-config/test/test-only-seam.test.js`.
- `query-plans.ts` — `recordingConnection(db, into)` captures the SQL and the bound
  parameters as the repositories execute them, and `explain` / `classifyPlanRow` /
  `indexOwners` turn one into a plan step (`full-table` / `full-index` / `search`). The
  point is that no query is ever spelled twice: a plan assertion over SQL restated in a
  test is a real plan for a query no user issues. Record at EXECUTION, not at prepare
  time — several repositories prepare in their constructor. It leaves out the two
  statements an index-presence probe (`src/internal/index-presence.ts`) issues: the
  `sqlite_master` lookup would classify as `full-table`, and it runs only on a name's
  first call, so a statement count would depend on test order.
- `fault-injection.ts` — `corruptStore`, `readOnlyStore` and `lockStore`, plus the
  `SQLITE_*` result codes, `sqliteErrcode()` and `primaryCode()`. Each injector produces a
  real error code from the real engine and refuses to run rather than take effect
  vacuously — an absent store, a live handle. Where the platform or the privilege decides
  instead of the helper, `readOnlyStore` reports it as `effective: false` and **the caller
  must gate**: `if (!readOnly.effective) ctx.skip(reason)`. Pass the store's `onCleanup` to
  any injector that has to be undone before the tree can be removed, and the store itself
  to any that needs no live connection.
  `fillStore` is in the same file and its page cap is connection-scoped, so it bounds only
  the handle it is given — which is what decides where it can be aimed. A repository
  constructed over a raw handle takes it (`SqliteAuditEventsRepository(raw)`, the
  `activity.test.ts` pattern), and so does `applyMigrations` — but only with a cap sized
  against a real migration: the default headroom on an empty file stops the ledger's own
  `CREATE TABLE`, so the applier's loop never runs and every claim about a partial
  migration then holds vacuously. The blanket fail-open sites in `database.ts`
  (`recordCapture`, `ensureInventory`, `recordConfigScan`, `recordProjectFiles`, and
  `reconcileWorktreeProjects`, which reaches `withTransaction` directly) are closures over
  the connection `openLocalDatabase` opened, so they are reached by capping **that**
  connection — `db[UNSAFE_TEST_ONLY_RAW_HANDLE]`, below. Handing `fillStore` a second
  handle on the same file instead is the mistake to avoid: it carries none of the cap, the
  facade writes on undisturbed, and every "the write was dropped" assertion then passes
  because nothing was ever refused.
- **`UNSAFE_TEST_ONLY_RAW_HANDLE`** — not a helper but the seam a connection-scoped
  injector aims at, so it is listed here: the `DatabaseSync` a `LocalDatabase` writes
  through, exported from `src/database.ts`, and the only test-only seam in shipped
  source. It is
  symbol-keyed and **not** re-exported from `src/index.ts`, and the package's `exports` map
  is `"." -> "./src/index.ts"` plus `"./sqlite-free"` — a subset of the root entry's
  bindings that never loads `database.ts`, both held by
  `packages/persistence/test/sqlite-free-entry.test.ts` — so no other package can reach the
  module that defines it. Two properties are load-bearing and easy to break: it is a plain **enumerable data
  property**, because the helpers hand out `{ ...db, close }` wrappers and spread copies own
  enumerable symbols — a getter or a non-enumerable definition loses it silently; and it is
  the **real** connection, so `close()` reaches it.
  `packages/eslint-config/test/test-only-seam.test.js` is what keeps "test-only" true: it
  walks the tracked tree and fails if any file naming the seam is neither its one definition
  site nor a test. That is a derived rule, not a list — a new fault test needs no edit there,
  a product caller anywhere in the workspace fails CI. It lives in that package rather than
  in `persistence` because only that task's turbo `inputs` hash the whole workspace; the
  same check inside `persistence` would replay a cached green while a caller appeared in
  `cli/src`.
- `assertNoOpenTransaction(db)` — a fault that leaves a transaction open is worse than the
  fault; assert this after injecting one. It reads `db.isTransaction` rather than probing
  with a transaction of its own, so it cannot disturb the handle it is inspecting.
  **It belongs at two shapes, not only after a fault.** After a path that REFUSES inside a
  transaction — `applyMigrations` on a partially-present migration, a `runInTransaction`
  that drops a malformed leaf — because refusing is half the requirement and containing the
  refusal is the other half; a handle left inside its `BEGIN` makes every later write on it
  join a transaction nobody started, and the store reads as healthy from outside. And after
  a fixture SEEDER's `COMMIT`, because a seeder that returns still inside its `BEGIN` has
  committed nothing, and every read below it then measures an empty store and reports the
  number as a result.
- `errorFrom(fn)` — the error a thunk threw, captured OUTSIDE its own catch (see
  [Testing](#testing) on why the try/catch form asserts on the test's own guard).
- `descriptorProbe()` — how many OS descriptors a synchronous thunk left behind. A
  `DatabaseSync` that escapes a failed open is unreachable to the caller, and POSIX
  unlinks an open file happily, so the temp tree still goes and the leak shows up
  nowhere; Windows alone refuses the delete. This counts instead, which is what makes
  the leak observable on the legs that run most of the suite. Three properties are
  load-bearing: the window must be **synchronous** (`leakedBy` refuses a thenable —
  an await hands the loop back and unrelated I/O lands in the delta), the count is
  the whole descriptor table rather than a per-file one (macOS `/dev/fd/N` entries
  are character devices, so `readlink` cannot name the store the way Linux's
  `/proc/self/fd` can), and the probe **self-checks** before reporting
  `observable: true` — a counter stuck at a constant reports "nothing leaked" for
  every input, so it proves it can see one descriptor it opens itself. Where it
  cannot (Windows has no `/dev/fd`), it reports `observable: false` with a reason and
  **the caller must gate**: `if (!probe.observable) ctx.skip(probe.reason)`, the same
  shape `readOnlyStore` uses for a mode the platform ignored.
- `captureEvent()` / `captureFinding()` — the minimal `recordCapture` pair. Both vary
  their identity per call, which is load-bearing: `contentHash` feeds the event's
  content-addressed id and `maskedMatch` is half the finding-level session dedup key, so a
  shared constant makes a second capture land as zero rows **by design** — and every "the
  event is gone" assertion in `test/faults/` would then pass whether or not the fault did
  anything.

`packages/persistence/test/faults/` is where those injectors are pointed at product code —
one file per fault (corrupt is covered in `database.test.ts`, which predates the
directory). A fault case documents the **actual** behaviour rather than the desirable one:
no fail-open site inspects a SQLite result code, so contention, a full disk, a read-only
file and a caller bug all arrive there as the same discarded `false`, and a dropped event
leaves no counter, marker or log line behind. (Scoped to those sites deliberately: the
package reads `errcode` in two places — `internal/sqlite-errors.ts` for
`SQLITE_CONSTRAINT_UNIQUE`, and `fingerprint.ts`, which separates "no such table" from a
damaged or locked store. Neither is a fail-open path.) Write that down and assert it; do not assert a signal the product does not
emit. Two behaviours there are the opposite of what the fault's name suggests and are
pinned so nobody "fixes" them: a store chmod'd read-only under a **live** handle keeps
being written (a descriptor carries the permission it was opened with, so only the next
open is refused), and a read-only store's refusal lands **inside the migration applier**
rather than on the first `PRAGMA journal_mode = WAL`, which succeeds and mints the
sidecars. A tightened directory the owner still owns is a third case, and the distinction
is the point: `ensureDataDirSync` widens the **data dir** back to 0700, so a 0500 there
never reaches SQLite — but a 0000 `~/.aka` is **reported**, as `EACCES` out of `mkdir`,
long before any chmod runs. `aka init` repairs a 0000 home because it calls
`ensureDataDirSync` on the home itself; `openLocalDatabase` does not, and the tests in
this directory assert the refusal.

Assert the result code, not an error message or an elapsed time — Windows CI runs several
times slower, and a timing assertion there is a flake. Compare with `primaryCode()`:
`errcode` carries the **extended** code, so `SQLITE_READONLY` also arrives as
`SQLITE_READONLY_DIRECTORY`. Do not add vitest `retry`.

Where a platform or a privilege makes an assertion meaningless, use `ctx.skip(reason)`.
An early `return` reports as a pass, which is the failure mode the store harness exists
to remove — and it is worse than a missing test, because a green tick is read as
coverage. The macOS-only `O_EXCL` case in `paths.test.ts` is the one that shows the cost:
it is the only thing anywhere pinning `flag: 'wx'`, so while it returned, deleting that
flag left every other leg green.

**Which of the two shapes to write is decided by what the test still asserts on the
guarded platform, not by taste.** A guard that ends the body before any assertion runs
must `ctx.skip(reason)`, because a pass there is a claim the run never checked. A guard
that only gates a subset — the test still verifies something real on that platform — is
written as a positive conditional, `if (process.platform !== 'win32') expect(…)`, and
**must not** become a skip: `ctx.skip` throws, so a skip at the tail discards a result
that genuinely held and reports the case as uncovered where it was not. Both shapes are
the same edit to make, and neither leaves an `if (process.platform …) return;` behind.

That last part is enforced rather than asked: `tools/portability-gate`'s
`platform-guard-early-return` (rule 6, spec files only) fails `pnpm lint` on the shape.
Three older suites predated it — `settings.test.ts`, `fingerprint.test.ts` and
`plugin-sdk`'s `config.test.ts` — and were exempt through `GRANDFATHERED_PLATFORM_GUARDS`
while their six guards were owed. All six are converted, so **that map is now empty and
nothing is exempt**: a guard in any spec file is reported. The mechanism stays, because it
is what lets a rule of this kind land on a tree that already carries its shape, and an
allowance is a ratchet in both directions — exceeding it is a violation, falling below it is
`platform-guard-stale-allowance`, so converting a guard means lowering the number in the
same commit and a file that reaches zero leaves the map. The ratchet is on the COUNT,
though, not on which guards make it up: converting one and adding another in the same
commit holds the number and passes both rules, so the gate cannot tell that pairing from an
honest conversion. That is the reason to keep the map empty rather than to re-open it —
with no entry at all, every guard in every spec file is reported and the pairing has
nowhere to hide.

### Testing a web-ui Server Action

A Server Action runs against the real store like any other test here, but four setup
steps are required before the first one will run at all, and **missing any of them
produces a failure that looks nothing like its cause**. `web-ui/test/actions/exceptions.test.ts`
is the worked example.

1. **Redirect the home dir** by mocking `node:os` and overriding `homedir()`. The action
   resolves `~/.aka` from it, and `n/no-process-env` rules out an env override, so this is
   the only seam. Set it through a `vi.hoisted()` box so `beforeEach` can point it at a
   fresh `mkdtempSync` dir per test.
2. **Alias `server-only` to an empty module** in `web-ui/vitest.config.ts` — `app/lib/db.ts`
   imports it, and the real package throws at import time outside a React Server bundler.
   Already wired; a new suite needs no change.
3. **Mock `next/cache`** — a mutating action calls `revalidatePath()`, which needs a Next
   render context that does not exist under vitest.
4. **Close and drop the memoised DB handle** on `globalThis` (`app/lib/db.ts` keeps it at
   `__akaDb` across requests and HMR reloads) in both `beforeEach` and `afterEach`, or the
   next test reads the **previous** test's temp store. Reset it again mid-test after any
   direct write through a second handle, so the action reopens and sees it.

Seed whatever snapshot the action reads before calling it — anything scanning a value needs
`installed_packs` populated via `recordInventory(bundledDetections())`, because the action
scans against the **DB snapshot**, not the engine's process-global registry.
`@akasecurity/plugin-sdk` is a **dev-only** dependency of `web-ui` for exactly this, which
is not a runtime package-wall crossing.

**A Server Action's parameter types are a claim its runtime never checks.** The arguments
arrive as JSON over an HTTP POST, so a caller may post a number, a null, or an object
carrying a hostile `toString` wherever the signature says `string`. Such a value reaching a
`.trim()`, a `.slice()`, a template literal or a SQL bind parameter throws — and a **thrown
Server Action rejects**, so the browser gets a framework error page instead of the
recoverable `{ ok: false, error }` the action was written to return. That is the same
failure the store-failure guards in `actions.ts` exist to prevent, reached by another door,
which is why a fail-open `catch` around the store is not enough on its own.

The exceptions surface closes it by parsing the **whole input** — the shapes live in
`@akasecurity/schema` (`src/zod/exception-action.ts`) and every mutating action there
`parseActionInput`s its payload before touching a field. Three rules make it hold:

- **Parse the whole input, not each field.** A payload that is not an object at all fails
  before any field is read, and no per-field check can express that case.
- **The refusal names the schema's KEY, never the payload.** A field arriving as the wrong
  type is still a live credential, so nothing derived from it — including a Zod issue
  message — may reach the message describing its rejection.
- **Widening in a test alias is per-PARAMETER, not per-action.** An alias that widens
  `confirmation` to `unknown` and leaves `reason` at `string` covers one field while reading
  as covering the action; that is exactly how `reason` went unwidened, and unguarded, across
  three actions at once. Widen the alias's whole input to `unknown`.

Assert three things per case, in this order: it does not throw, it names the field, and it
echoes no raw value (`expectNoEchoOf`). The middle one is not decoration — `expectNoEchoOf`
catches an absent error but not an empty one, and every `not.toContain` passes on `''`, so
requiring the message to say something specific is what stops the echo check going vacuous.
Keep a positive control that a well-formed payload still succeeds, or an action rewritten to
refuse everything satisfies all three.

Every other `'use server'` file under `web-ui/app` is **not** guarded this way yet — eight
files, 20 exported actions at the time of writing — so do not read the above as a property
the dashboard has. The set is deliberately **not** listed here: a partial list reads as
exhaustive and stops an audit at the files it names, and a full one goes stale the first
time an action file lands. Derive it from the **directive**, which is not the same as
grepping for the words — `app/lib/dropped-rules.ts` mentions them in a comment and exports
a sync function, so it matches the text and is not a Server Action.

### Testing a web-ui page

An async Server Component is a plain async function that returns an element, so a route's
own data work — which store reads it issues, and which one it hands to which consumer — is
testable by **calling the page and reading the props it hands down**. No renderer, no DOM,
no jsdom. `element.props` carries them; assert `element.type` alongside, so a page that
starts returning a wrapper fails naming that rather than reading every prop as `undefined`.
`web-ui/test/pages/exceptions-page.test.ts` is the worked example. The four steps above
apply unchanged (a read-only page needs no `next/cache` mock).

This is not the browser tier — nothing mounts, no event fires, no client component runs.
It covers the seam between the store and the props, which is where a route's derivations
live and where nothing else can see them.

**The one thing that makes it work is a config line.** `web-ui/tsconfig.json` sets
`"jsx": "preserve"` because Next's own compiler consumes untransformed JSX, and vitest
inherits it — so the page's JSX survives into the output and the parser that reads it next
rejects it. `oxc.jsx` in `web-ui/vitest.config.ts` overrides that for the test run only. It
is already wired; a new suite needs no change, but a parse error on a `.tsx` import is what
its absence looks like, and it names neither JSX nor the tsconfig.

A route that issues **more than one read of the same table** is the case worth writing a
page test for at all: a count derived from the wrong one of two windows is still a number,
so it typechecks, lints, and satisfies every assertion aimed at the pieces. Make the fixture
straddle the two windows and **pin the straddle itself** — with rows that all fall inside
both, the assertions pass whichever read the page used, and the suite proves nothing.

An at-rest leak scan must read **every file in the data dir**, not `aka.db` plus a
hardcoded `-wal`/`-shm` pair. This is not a corner case: a migration carrying pre-cutover
history forward leaves an `aka.db.pre-drop.<ts>.<rand>.bak` — a byte-for-byte copy of the
pre-migration store, as large again as `aka.db` itself — in that directory, so a name-list
reader misses more of the store than a `-wal` pair ever covered. **Which of those copies
exist is a property of the store's HISTORY, not a list anyone can write here**, which is the
argument for walking the directory and is why it survived that copy ceasing to be
unconditional: the pre-drop snapshot is taken only where the drop would destroy rows
(`legacyDropWouldDestroyRows` in `packages/persistence/src/migrations.ts`), so a store this
same open created writes none — it used to write one on **every** first open, half the bytes
in a new data dir, protecting a freshly-built schema that held nothing. On top of that SQLite writes an
`aka.db-journal` instead of the WAL pair wherever WAL silently no-ops (see `dbSidecars` in
`packages/persistence/src/paths.ts`), and the foreign-lineage reset leaves its own `.bak`.
`web-ui/test/helpers/store-bytes.ts` is that reader; import it rather than re-rolling one.
Bind one call and assert against it — the positive control and the absence check must
describe the same bytes, not two independent reads. Two rules keep it honest, because an
empty read contains no secret and so passes every `not.toContain` vacuously: keep the
**positive control** — assert a value that **is** expected on disk before asserting the raw
is absent — and **never swallow a failed read**. Only a sibling's `ENOENT` is tolerable (an
atomic write's `.tmp` vanishing mid-scan); a permission denial or a Windows sharing
violation on `aka.db` must throw.

Assert a raw value is absent from an **error** run by run, not whole. `not.toContain(value)`
stays green if a branch echoes a _truncated_ value, which is still a live credential's
prefix. `expectNoEchoOf` is the **required form for every raw-value absence assertion that is
newly written or newly touched** in a package carrying the helper — `cli/test/helpers/no-echo.ts`,
`plugins/claude-code/test/helpers/no-echo.ts`, `plugins/codex/test/helpers/no-echo.ts`,
`plugins/antigravity/test/helpers/no-echo.ts`, `web-ui/test/helpers/no-echo.ts`,
`packages/setup-wizard/test/helpers/no-echo.ts`,
`packages/persistence/test/helpers/no-echo.ts` and
`packages/remote/test/helpers/no-echo.ts`. A plain
`not.toContain(rawValue)` in a new or edited assertion is a defect, not a style choice, and
editing a file means its in-class assertions come along rather than being left beside converted
ones.

**The same rule holds in PRODUCT code, and one module is where it is enforced.**
`packages/plugin-sdk/src/raw-egress.ts` is the boundary every raw value crosses on its way out
of the triage path — its callers route a model's `reasoning` and `notes`, a downstream error
message bound for the parent command's stderr, the serialized plan document, a masked context
window and a file path through it. `assertRawFree` and `maskContextSlice` reject **run by run**
against `RAW_RUN_LEN`, for the reason the paragraph above gives: `text.includes(raw)` matches
only if the ENTIRE value survives, so a truncated echo passes it, and truncating is exactly what
a model does to a long token it quotes back. A partial echo there does not merely print —
`planTriageWriteback` writes `reasoning` into a suppression grant's `justification`, so it lands
at rest. `RAW_RUN_LEN` is the same number the `no-echo` helpers use, but they sit across a
package wall and are INDEPENDENT copies: neither pins the other, and each is held by its own
suite. The product side's pin is DERIVED (it measures the shortest run the boundary really
refuses, and carries a calibration case so a constant cannot stand in for a measurement), so it
goes red on the first character of drift in either direction.

`safeMaskedMatch` is the deliberate exception and must stay whole-value. It verifies a preview
built to REVEAL a fragment on purpose, so a surviving run is the feature rather than the leak:
`maskMatch`'s email branch discloses the whole domain, which is a run far past the window, and
tightening it in step with its two siblings would collapse every email preview to `'***'`. The
reason is stated at the function and pinned by a case that fails if somebody tightens it.

**Older assertions are a backlog, not a clean tree.** `plugins/claude-code` still carries around
twenty whole-value raw-value assertions in files this convention has not reached —
`history/`, `journey/`, `remediation/`, `render.test.ts`, `triage/plan-file.test.ts`,
`hooks/pointer-substitution.test.ts` and `backfill.test.ts` among them. `plugins/codex` carries
the same backlog in its counterparts of those files — the helper reached its hook and
remediation-render assertions, not `history/`, `triage/judge.test.ts` or
`remediation/redact.test.ts`. Do not read the rule above as a claim that either package is
clean. Two shapes are genuinely **exempt** and stay
whole-value: an assertion on a masked preview (`writeback.test.ts` on `maskedValue`,
`triage/surfaced-secrets.test.ts` on `maskedToken`), because that fragment is revealed on
purpose; and the deliberate **control** assertions inside each `no-echo.test.ts`, which exist
to show the whole-value form would have passed.

**Share it inside a package, copy it across a wall — and a copy takes the suite with it.**
All eight packages import a `test/helpers/no-echo.ts` with its own tests in `no-echo.test.ts`:
each case drives the helper with an output that leaks a run, and asserts both that the helper
refuses it **and** that the whole-value form it replaced would have passed. That second half is
what shows the assertion is _stronger_ rather than merely also-red, and it is why raising the
run length or emptying the loop cannot go unnoticed — widening `ECHO_RUN` leaves every
**caller** green, so the helper's own suite is the only thing that goes red. `web-ui` is the
worked example of that failure: its copy was inline with no suite, and all 86 of its action
tests passed with `ECHO_RUN` set to 64. A package wall blocks the import, not the pattern, so a
further package copies **both** files — including the `expect(value).toBeDefined()` guard,
without which an `undefined` message satisfies the loop vacuously.

**A masked-preview control calls the product's mask, never a hand-rolled one.** A locally built
literal asserts that a string the test constructed lacks a run of another string the test
constructed — true by construction, and it stays true however `maskMatch` changes. Each
`no-echo.test.ts` that has a masked-preview case calls `maskMatch` itself
(`@akasecurity/plugin-sdk` re-exports it, so the plugin crosses no package wall), which is what
makes widening its generic branch go red where the reason is written down.

`packages/persistence` and `packages/remote` are the two copies with **no** masked-preview
case, and neither is an omission to fix: neither package has a masking surface. For
`persistence` there is a second reason — `@akasecurity/detections`, which owns `maskMatch`,
depends ON it, so importing it even as a dev dependency would make a cycle out of a test
fixture. Its fixture is a generated base64 vault key instead, which is what that package
actually has to keep out of an error; `remote`'s is the userinfo of a refused endpoint, which
is what that package has to keep out of a `RemoteEndpointRefused` message.

**Capture the error outside the `catch`.** This shape passes while the function under test
stops throwing entirely:

```ts
try {
  parse(input);
  throw new Error('expected parse to throw'); // caught by its own catch, below
} catch (err) {
  expect((err as Error).message).not.toContain(RAW); // asserts on THAT message
}
```

The guard error carries no secret, so the absence check is satisfied by the test's own
throw. Use `errorFrom(() => parse(input))` (the plugin's helper) or the CLI's
`.then(() => undefined, (e) => e as Error)`, then assert what the error **says** before
asserting what it **omits** — a never-thrown error arrives as `undefined` and `toBeDefined()`
catches it. Naming the expected refusal is also the positive control: without it a case
proves only that _some_ error said nothing, not that the guarded branch was the one reached.

**Never point it at bytes that can come back empty.** Every `not.toContain` passes on `''`,
and `toBeDefined()` does not catch that: it catches a never-thrown error arriving as
`undefined`, while a Prompter's `output()` returns `string` and is never undefined, so the
guard is **inert on stdout**. Where a path prints nothing at all, assert that —
`expect(io.output()).toBe('')` — which goes red on anything printed there, raw or not.
Where it does print, pin a **positive control** on the same bytes first.

This applies to a **raw value**, in an **error** and on whatever further surface a suite
binds below. At-rest and grant-shape assertions stay whole-value, because `maskMatch`
deliberately keeps a fragment visible and that fragment is stored on purpose; and an
assertion that some non-secret string is absent — an internal error-class name, say — is a
different property that `expectNoEchoOf` does not express. Drive the window with a
**high-entropy** fixture: against an English-phrase literal an eight-character window
collides with ordinary output text instead of catching a leak. High-entropy does **not**
mean credential-shaped — this repo is public, and a fixture that looks like a real secret
does not belong in it. Where a suite needs both (`cli/test/commands/exception-reveal.test.ts`
tokenizes a value the engine never scans), a random-looking string that matches no rule
satisfies them together; where the value must match a rule, take it from that rule's own
`examples` so no secret-shaped literal is written by hand.

The CLI's `exception` suites bind it **wider than an error** — to their **stdout**
assertions too, because a CLI's terminal output is where a leaked value gets scrolled,
pasted into a bug report and captured by CI logs. That is safe rather than fragile **for
the values those suites use**: what they print of a blocked **generic** secret is
`maskMatch`'s first-and-last preview (`A******E`) — two characters, sitting in two runs of
**one**. The RUN is the quantity that matters, not the count: the window slides over
**contiguous** slices, so two characters that are never adjacent cannot fill one of any
width. **It does not generalize to every value `maskMatch` handles.** The
email branch reveals the first local character plus the **whole domain**
(`user@example.com` → `u***@example.com`), and a single-character local part returns the
input unchanged — both fill the window on purpose. A surface printing a pii/email preview is
out of scope for the stdout half, not a leak it found; `no-echo.test.ts` pins both branches
so that boundary is written down rather than re-derived.

**Two different things are pinned there, and only one of them is the margin.** The
acceptance case (`refuses(maskMatch(VALUE), VALUE)` is `false`) says the preview is safe
**today**; it cannot say how much room is left, because it fires only once the preview holds
a contiguous run of `ECHO_RUN` characters. So widening the generic branch to anything from
two revealed characters up to seven leaves it green — and that band is precisely where a
usability change lands ("show enough to tell two blocked secrets apart"). In that band the
only red is `packages/detections/test/mask.test.ts`, whose failure reads as _"you changed the
mask, update the expectation"_ and gives no signal that a downstream safety argument moved.
The **margin** is therefore pinned by its own case in `cli/test/helpers/no-echo.test.ts`,
which derives the longest revealed run from `maskMatch` and holds it at one: that goes red on
the **first** character of widening, where the reasoning is written down. Widening is a
deliberate act to be argued against the window — not a reason to loosen the callers back, and
not something raising `ECHO_RUN` can buy back, since the same file owns both numbers.

`exception.test.ts`'s masked-preview group is **derived from `maskMatch`** for the same reason
— the seeded ledger `maskedValue`, the grant-shape assertions over it, the stdout positive
control, and the two approve **selectors** that stand in for a value a user types. A
hand-written `'A******E'` on both sides of one of those is true by construction and moves with
nothing, which is the rule two paragraphs above, applied to a group rather than to a single
control. **That is a claim about that group, not about every preview in the package**: a
preview the CALLER supplies is a different thing, and `exception-reveal.test.ts`'s **vault**
seeds assert against its own `MASKED` constant on purpose, because a vault pointer's preview
is chosen at tokenize time rather than produced by `maskMatch`. **The line is drawn per ROW,
not per file.** The same file's `recordBlocked` seeds are `blocked_detections` rows, and
`packages/plugin-sdk/src/runtime.ts` masks the finding with `maskMatch` before recording one
— the only writer of that table — so those derive from `maskMatch` like any other product
mask. Derive from `maskMatch` where the product masks; derive from the raw value where the
caller does, and decide that per table rather than by which suite you are in.
`packages/detections/test/mask.test.ts` keeps its exact-string cases: they are the right pin
for the mask's own contract, and deliberately not a pin on the CLI's margin.

**Bind it per assertion, never per file.** `cli/test/commands/vault.test.ts` is the worked
example: its forged-pointer refusal pins absence like any other, but `aka vault show`'s
success path prints the raw value **on purpose** and asserts `output().startsWith(RAW)`, so
a run-by-run rule over that case would assert the opposite of the command's contract. Exempt
the case, not the file — a file-level exemption also disarms the refusal paths in it, which
are the ones a leak actually travels through.

Assert against the value **that call supplied**, never a module constant the case does not
send. A case driven with an inert literal and asserted against a shared `VALUE` cannot fail
however the branch is worded, so it stays green while the branch echoes the live value it
was handed. Name each case's own inputs. This is the same family as the two rules above: an
absence assertion is only worth its green if it could have gone red — so before trusting a
new one, break the property it claims to guard, re-run, and treat a still-green suite as a
defect in the test.
