// CONTRIBUTING.md's "Checks that gate `<branch>`" tables, read once for every
// test that looks at them, so where a section starts and ends is decided here.
// Nothing here asserts: a caller builds `it.each` lists from these in a
// `describe` body, where an assertion is a collection error rather than a test
// failure. A section that cannot be found reads as null.

/**
 * The branches CONTRIBUTING.md keeps a gate table for, in document order.
 * @param {string} contributing
 */
export const gateBranches = (contributing) =>
  [...contributing.matchAll(/^### Checks that gate `([^`]+)`$/gm)].map(([, branch]) => branch);

/**
 * One branch's section, from its heading under "## Pull requests" to the next
 * ```` ```bash ```` fence, or null. Two `indexOf` calls rather than a lazy
 * `HEADING([\s\S]*?)```bash` pattern, which backtracks quadratically.
 * @param {string} contributing
 * @param {string} branch
 */
export function gateSection(contributing, branch) {
  const heading = `### Checks that gate \`${branch}\``;
  const start = contributing.indexOf('## Pull requests');
  const from = start === -1 ? -1 : contributing.indexOf(heading, start);
  const end = from === -1 ? -1 : contributing.indexOf('```bash', from + heading.length);
  return end === -1 ? null : contributing.slice(from + heading.length, end);
}

/**
 * The rows of one branch's table — | `Check name` | `workflow.yml` | <mark> | —
 * with `rowLike` set to the number of lines that look like a row, or null.
 * @param {string} contributing
 * @param {string} branch
 */
export function gateRows(contributing, branch) {
  const body = gateSection(contributing, branch);
  if (body === null) return null;
  const rows = [...body.matchAll(/^\| `([^`]+)`\s*\| `([^`]+)`\s*\| *(\S+) *\|$/gm)].map(
    ([, check, file, enforced]) => ({ check, file, enforced }),
  );
  // The same completeness rule `parseGateTable` enforces, because this is a
  // SECOND reader of one document and the two must not disagree about how many
  // rows it has. Without it the pair diverges in the permissive direction: add
  // a ninth row whose Enforced cell does not parse and the gate refuses the
  // whole table (9 row-like, 8 parsed) while this file yields 8, satisfies its
  // `toHaveLength(8)` pin, and stays green — measured at 111 passed. The count
  // pin catches a REFORMATTED row and cannot catch an ADDED one.
  //
  // Duplicated rather than imported: `@akasecurity/required-checks-gate`
  // devDepends on this package, so taking the reverse edge makes turbo report
  // `x Cyclic dependency detected`. The guard travels with the copy instead.
  //
  // REPORTED, not asserted here. Collapsing a short count to `null` made
  // `requiredChecks()` throw in a describe body, which vitest reports as a
  // collection error — `Test Files 1 failed` with `Tests no tests`, taking
  // every other suite in this file down and reading as green to anything
  // grepping for a failed test. The count rides along and one named `it`
  // asserts it.
  rows.rowLike = body.split('\n').filter((line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith('|') || !trimmed.endsWith('|')) return false;
    if (/^[|\-: ]+$/.test(trimmed)) return false;
    return !trimmed.startsWith('| Check');
  }).length;
  return rows;
}
