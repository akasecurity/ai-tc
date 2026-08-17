// Pure logic for the required-check drift gate: reading CONTRIBUTING.md's
// gate table, reading a GraphQL status-check rollup, and comparing the two.
// The CLI entry (check-required.ts) owns all I/O — the `gh` spawn and the step
// summary — so the unit suite can drive every outcome from canned inputs.
//
// What this gate is for. Which checks branch protection actually requires is a
// repository SETTING: invisible in a diff, unchangeable from a PR, and — the
// part that makes a document insufficient — matched by NAME. Rename a job and
// protection goes on waiting for a name nothing emits any more, so the check
// silently stops being required with nothing anywhere going red. That is the
// failure mode this exists to catch, and it is why the comparison is exact in
// both directions rather than a floor: a floor catches the rename but lets the
// enforced set grow while the public record in CONTRIBUTING.md goes stale, and
// a stale record about what is enforced is the defect this replaced.

/** One row of CONTRIBUTING.md's "Checks that gate `main`" table. */
export interface GateRow {
  /** The check name GitHub reports, which is what protection matches on. */
  check: string;
  /** The workflow file the job lives in. */
  file: string;
  /** Whether the row claims branch protection currently requires it. */
  enforced: boolean;
}

/**
 * How a check name came back from the rollup. Three states rather than a
 * boolean, because "not reported" is not "not required": a job that did not run
 * on the PR being read contributes no context at all, and reading that absence
 * as `not required` turns a PR that skipped a job into a false regression
 * report. The caller decides what to do with it; the reader will not guess.
 */
export type LiveState = 'required' | 'not-required' | 'not-reported';

export class GateConfigError extends Error {}

const ENFORCED_MARK = '✅';
const NOT_ENFORCED_MARK = '⛔';

/**
 * The gate table, sliced to its own section first so a table further down the
 * file cannot contribute rows — the branch-freshness section carries one.
 *
 * Throws rather than returning empty. Every comparison below is over set
 * membership, and an empty intended set satisfies all of them: the live set
 * would match a pin of nothing, the outstanding list would be empty, and the
 * job would report a clean bill of health having read no table at all.
 */
export function parseGateTable(contributing: string): GateRow[] {
  const section = /### Checks that gate `main`([\s\S]*?)```bash/.exec(contributing);
  if (section === null) {
    throw new GateConfigError(
      'CONTRIBUTING.md has no "### Checks that gate `main`" section ending in a fenced block',
    );
  }
  // `section[1]` is the capture group, which the null check above proves the
  // match has — but only at runtime; under `noUncheckedIndexedAccess` the type
  // is still `string | undefined`, so give it an empty default. Empty falls
  // through to the no-rows refusal below rather than to a silent pass.
  const body = section[1] ?? '';

  // Every line that LOOKS like a table row is counted first, and the parsed
  // rows are required to match that count exactly.
  //
  // Without this, a row the strict pattern cannot read is silently skipped —
  // and a skipped row is a check that vanishes from the comparison entirely
  // while the job still reports "match the record" and exits 0. An empty
  // Enforced cell is enough to do it, and the row most likely to be reformatted
  // is `No-network`, the one this gate exists for. Refusing is the only safe
  // reading: a table this reader cannot fully parse is a table it must not
  // draw conclusions from.
  const rowLike = [...body.matchAll(/^\|(?!\s*[-: ]+\|)(?!\s*Check\b).*\|$/gm)].length;

  const rows: GateRow[] = [];
  for (const [, check, file, mark] of body.matchAll(
    /^\| `([^`]+)`\s*\| `([^`]+)`\s*\| *(\S+) *\|$/gm,
  )) {
    if (mark !== ENFORCED_MARK && mark !== NOT_ENFORCED_MARK) {
      throw new GateConfigError(
        `${String(check)}: the Enforced cell is "${String(mark)}", which is neither ${ENFORCED_MARK} nor ${NOT_ENFORCED_MARK}`,
      );
    }
    // Every group in the pattern is mandatory, so a match has all three; the
    // fallbacks are what the compiler needs rather than a reachable state.
    rows.push({ check: check ?? '', file: file ?? '', enforced: mark === ENFORCED_MARK });
  }
  if (rows.length === 0) {
    throw new GateConfigError('the gate table parsed to no rows');
  }
  if (rows.length !== rowLike) {
    throw new GateConfigError(
      `the gate table has ${String(rowLike)} rows but only ${String(rows.length)} parsed — a row this reader cannot read is a check it would silently ignore`,
    );
  }
  return rows;
}

/** One `statusCheckRollup` context, in either of the two shapes it can take. */
export interface RollupContext {
  name?: string;
  context?: string;
  isRequired?: boolean;
}

/**
 * The live required set, as `name -> LiveState`.
 *
 * A CheckRun reports `name` and a StatusContext reports `context`; both carry
 * `isRequired`. A context with neither name is skipped rather than keyed on
 * `undefined`, which would collide every such context onto one entry.
 */
export function readRollup(contexts: RollupContext[]): Map<string, LiveState> {
  const live = new Map<string, LiveState>();
  for (const context of contexts) {
    const name = context.name ?? context.context;
    if (name === undefined || name === '') continue;
    // A matrix leg can report the same name twice across reruns. `required`
    // wins over `not-required` so a stale duplicate cannot mask an enforced
    // check — the direction that would report a regression that is not one.
    if (live.get(name) === 'required') continue;
    live.set(name, context.isRequired === true ? 'required' : 'not-required');
  }
  return live;
}

/** A pull request as the rollup query returns it. */
export interface PrNode {
  number: number;
  commits: {
    nodes: { commit: { statusCheckRollup: { contexts: { nodes: RollupContext[] } } | null } }[];
  };
}

export interface SelectedPr {
  number: number;
  contexts: RollupContext[];
}

/**
 * The newest pull request that reported any checks at all.
 *
 * Skipping the ones that reported none is load-bearing rather than tidy. A PR
 * can exist with an empty rollup — opened seconds ago, or every workflow
 * path-filtered out — and reading THAT one reports every check as unreported,
 * which this gate treats as a failure. So the wrong answer would be a loud one,
 * arriving daily, about nothing.
 *
 * The input is oldest-first, which is the only order the GraphQL connection
 * offers (`last: N` with an ascending sort), so the search runs from the end.
 */
export function selectPr(candidates: PrNode[]): SelectedPr | undefined {
  for (let i = candidates.length - 1; i >= 0; i--) {
    const pr = candidates[i];
    if (pr === undefined) continue;
    const contexts = pr.commits.nodes[0]?.commit.statusCheckRollup?.contexts.nodes ?? [];
    if (contexts.length > 0) return { number: pr.number, contexts };
  }
  return undefined;
}

/**
 * The pull requests out of a `gh api graphql` response body.
 *
 * Throws on a shape it does not recognise rather than returning `[]`. An empty
 * list is a legible state here — a repository with no pull requests — so a
 * failed parse that returned one would be reported as "nothing to read" and
 * exit on the could-not-read path with a message naming the wrong cause.
 */
export function parsePrResponse(stdout: string): PrNode[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(`gh did not return JSON: ${stdout.trim().slice(0, 400)}`);
  }
  // The cast admits `null` because `JSON.parse('null')` really returns it, and
  // the optional chain below is only sound while the type says so.
  const nodes = (
    parsed as { data?: { repository?: { pullRequests?: { nodes?: PrNode[] } } } } | null
  )?.data?.repository?.pullRequests?.nodes;
  if (!Array.isArray(nodes)) throw new Error('the GraphQL response carried no pull requests');
  return nodes;
}

/**
 * The rollup contexts out of the second query's response body.
 *
 * Throws on an unreadable shape for the same reason `parsePrResponse` does, and
 * with more at stake: an empty context list here compares against a table whose
 * every enforced row then reads as `not-reported`, so a silent `[]` turns a
 * parse failure into a report that two checks stopped gating.
 */
export function parseRollupResponse(stdout: string): RollupContext[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(`gh did not return JSON: ${stdout.trim().slice(0, 400)}`);
  }
  const nodes = (
    parsed as {
      data?: {
        repository?: {
          pullRequest?: {
            commits?: {
              nodes?: {
                commit: { statusCheckRollup: { contexts: { nodes: RollupContext[] } } | null };
              }[];
            };
          };
        };
      };
    } | null
  )?.data?.repository?.pullRequest?.commits?.nodes;
  if (!Array.isArray(nodes)) throw new Error('the GraphQL response carried no commit');
  const contexts = nodes[0]?.commit.statusCheckRollup?.contexts.nodes;
  if (!Array.isArray(contexts)) throw new Error('the GraphQL response carried no check rollup');
  return contexts;
}

/**
 * The first of two queries: which recent pull requests reported any checks.
 *
 * It deliberately does NOT ask for `isRequired`, and cannot. That field takes
 * `pullRequestNumber` as a required argument and there is no way to refer to
 * the enclosing node's own number, so asking for it inside a `pullRequests`
 * connection fails the whole query with "A pull request ID or pull request
 * number is required" — once per node. Hence two round trips: pick a pull
 * request here, then read its rollup by number below.
 */
export const prCandidatesQuery = (owner: string, repo: string, candidates: number): string =>
  `{repository(owner:"${owner}",name:"${repo}"){pullRequests(last:${String(candidates)},orderBy:{field:CREATED_AT,direction:ASC}){nodes{number commits(last:1){nodes{commit{statusCheckRollup{contexts(first:100){nodes{... on CheckRun{name} ... on StatusContext{context}}}}}}}}}}}`;

/** The second query: one pull request's rollup, with the required flag. */
export const rollupQuery = (owner: string, repo: string, prNumber: number): string =>
  `{repository(owner:"${owner}",name:"${repo}"){pullRequest(number:${String(prNumber)}){commits(last:1){nodes{commit{statusCheckRollup{contexts(first:100){nodes{... on CheckRun{name isRequired(pullRequestNumber:${String(prNumber)})} ... on StatusContext{context isRequired(pullRequestNumber:${String(prNumber)})}}}}}}}}}}`;

/** The `::error::` lines a drift produces, in the order they are printed. */
export function annotations(drift: Drift): string[] {
  return [
    ...drift.noLongerRequired.map(
      (row) => `${row.check} is recorded as enforced but branch protection does not require it`,
    ),
    ...drift.notReported.map(
      (row) => `${row.check} is recorded as enforced and reported no check to read`,
    ),
    ...drift.newlyRequired.map(
      (check) => `${check} is now required — flip its row to the enforced mark in CONTRIBUTING.md`,
    ),
    ...drift.untabled.map(
      (check) => `${check} is required and is not in CONTRIBUTING.md's gate table`,
    ),
  ];
}

export interface Drift {
  /** Recorded as enforced, live says it is not — a real regression. */
  noLongerRequired: GateRow[];
  /** Live says required, the table still records ⛔ — the record is stale. */
  newlyRequired: string[];
  /**
   * Recorded as enforced but absent from the rollup entirely. Ambiguous, never
   * silently a pass: the job may simply not have run on the PR that was read.
   */
  notReported: GateRow[];
  /** Recorded ⛔ and still ⛔ — the outstanding work, reported, never failed on. */
  outstanding: GateRow[];
  /** Required by protection but not in the table at all. */
  untabled: string[];
}

/**
 * Compare the recorded column against the live set.
 *
 * `untabled` is deliberately separate from `newlyRequired`: a required check
 * this table never listed is a different problem from one it listed as ⛔, and
 * collapsing them sends the reader to edit a row that does not exist.
 */
export function compare(rows: GateRow[], live: Map<string, LiveState>): Drift {
  const tabled = new Set(rows.map((row) => row.check));
  const noLongerRequired: GateRow[] = [];
  const notReported: GateRow[] = [];
  const newlyRequired: string[] = [];
  const outstanding: GateRow[] = [];

  for (const row of rows) {
    const state = live.get(row.check) ?? 'not-reported';
    if (row.enforced) {
      if (state === 'required') continue;
      if (state === 'not-reported') notReported.push(row);
      else noLongerRequired.push(row);
      continue;
    }
    if (state === 'required') newlyRequired.push(row.check);
    else outstanding.push(row);
  }

  const untabled = [...live]
    .filter(([name, state]) => state === 'required' && !tabled.has(name))
    .map(([name]) => name)
    .sort();

  return { noLongerRequired, newlyRequired, notReported, outstanding, untabled };
}

/**
 * Whether the drift is a failure. Everything except `outstanding` is — the six
 * rows that are honestly not required yet are the state this gate ships in, and
 * failing on them from day one would make it a permanently red job, which is a
 * job people mute rather than one they act on.
 */
export const isFailure = (drift: Drift): boolean =>
  drift.noLongerRequired.length > 0 ||
  drift.newlyRequired.length > 0 ||
  drift.notReported.length > 0 ||
  drift.untabled.length > 0;

const list = (names: string[]): string => names.map((name) => `\`${name}\``).join(', ');

/** The Markdown the job writes to its step summary — and, on failure, the reason. */
export function buildSummary(drift: Drift, prNumber: number): string {
  const lines = ['# Required checks', ''];
  lines.push(`Read from \`isRequired\` against PR #${String(prNumber)}.`, '');

  if (drift.noLongerRequired.length > 0) {
    lines.push(
      `## A check stopped being required (${String(drift.noLongerRequired.length)})`,
      '',
      `${list(drift.noLongerRequired.map((row) => row.check))} — CONTRIBUTING.md records these as enforced and branch protection does not require them.`,
      '',
      'Protection matches by NAME, so the usual cause is a renamed job: the old name is still',
      'configured, nothing emits it any more, and the check silently stopped gating. Either',
      'restore the name, or update the setting AND the table together.',
      '',
    );
  }

  if (drift.notReported.length > 0) {
    lines.push(
      `## A check recorded as enforced was not reported (${String(drift.notReported.length)})`,
      '',
      `${list(drift.notReported.map((row) => row.check))} — absent from this PR's checks entirely, so whether protection requires it could not be read.`,
      '',
      'Not treated as a pass: a job that did not run contributes no context, which is',
      'indistinguishable from one that was removed. Re-run against a PR where every workflow ran.',
      '',
    );
  }

  if (drift.untabled.length > 0) {
    lines.push(
      `## Required but not in the table (${String(drift.untabled.length)})`,
      '',
      `${list(drift.untabled)} — branch protection requires these and CONTRIBUTING.md does not list them.`,
      '',
      'Add a row, so the public record of what gates `main` is complete.',
      '',
    );
  }

  if (drift.newlyRequired.length > 0) {
    lines.push(
      `## Newly enforced — update the table (${String(drift.newlyRequired.length)})`,
      '',
      `${list(drift.newlyRequired)} — branch protection now requires these and the table still records ⛔.`,
      '',
      'This is the good direction. Flip those rows to ✅ in CONTRIBUTING.md and this goes green.',
      '',
    );
  }

  if (drift.outstanding.length > 0) {
    lines.push(
      `## Still not enforced (${String(drift.outstanding.length)})`,
      '',
      `${list(drift.outstanding.map((row) => row.check))} — these run on every PR and block nothing.`,
      '',
      'Reported rather than failed on: making a check required is a repository-settings change',
      'and cannot be done from a PR. Not a regression — the recorded state and the live state agree.',
      '',
    );
  }

  if (!isFailure(drift) && drift.outstanding.length === 0) {
    lines.push('Every check in the table is required, and nothing else is.', '');
  }
  return lines.join('\n');
}
