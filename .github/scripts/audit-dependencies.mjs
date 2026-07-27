#!/usr/bin/env node
// CI gate over `pnpm audit`: fails when the lockfile carries a high or
// critical advisory without an unexpired waiver in .github/audit-waivers.json.
// Lower severities never block; they appear in the report only. The audit
// works from the lockfile alone, so no `pnpm install` is required first.
//
// Always writes audit-report.md to the current working directory — the
// workflow appends it to the run summary, and the scheduled run posts it to
// the advisory-tracking issue. The waiver format and process are documented
// in CONTRIBUTING.md ("Dependency advisories and waivers").
//
// Exit codes:
//   0 — no blocking advisories (clean, or every hit waived)
//   1 — at least one unwaived high/critical advisory
//   2 — the audit itself could not be completed (fail closed)

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const BLOCKING_SEVERITIES = new Set(['high', 'critical']);
const WAIVERS_PATH = fileURLToPath(new URL('../audit-waivers.json', import.meta.url));
const REPORT_PATH = 'audit-report.md';
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function loadWaivers() {
  const raw = JSON.parse(readFileSync(WAIVERS_PATH, 'utf8'));
  if (raw === null || typeof raw !== 'object' || !Array.isArray(raw.waivers)) {
    throw new Error('audit-waivers.json must be an object with a "waivers" array');
  }
  for (const waiver of raw.waivers) {
    if (typeof waiver.advisory !== 'string' || waiver.advisory.trim() === '') {
      throw new Error('every waiver needs an "advisory" (a GHSA or CVE id)');
    }
    if (typeof waiver.reason !== 'string' || waiver.reason.trim() === '') {
      throw new Error(`waiver ${waiver.advisory} needs a non-empty "reason"`);
    }
    if (
      typeof waiver.expires !== 'string' ||
      !ISO_DATE.test(waiver.expires) ||
      Number.isNaN(Date.parse(waiver.expires))
    ) {
      throw new Error(`waiver ${waiver.advisory} needs an "expires" date (YYYY-MM-DD)`);
    }
  }
  return raw.waivers;
}

// `pnpm audit` exits non-zero whenever it finds vulnerabilities, and it also
// reports transport failures as parseable JSON on stdout ({"error": {...}}) —
// so neither the exit status nor JSON.parse succeeding identifies a completed
// audit. A completed audit is JSON that carries an "advisories" object and no
// top-level "error"; anything else fails closed.
function runAudit() {
  const result = spawnSync('pnpm', ['audit', '--json'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`could not spawn pnpm: ${result.error.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    const detail = (result.stderr || result.stdout || '').trim().slice(0, 400);
    throw new Error(`pnpm audit did not return JSON (registry unreachable?): ${detail}`);
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    'error' in parsed ||
    !('advisories' in parsed)
  ) {
    const detail = parsed?.error
      ? `${parsed.error.code ?? ''} ${parsed.error.message ?? ''}`.trim()
      : 'output has no "advisories" field';
    throw new Error(`pnpm audit did not complete: ${detail.slice(0, 400)}`);
  }
  return parsed;
}

function waiverMatches(waiver, advisory) {
  const id = waiver.advisory.toUpperCase();
  if (id === (advisory.github_advisory_id ?? '').toUpperCase()) return true;
  return (advisory.cves ?? []).some((cve) => cve.toUpperCase() === id);
}

const mdEscape = (text) =>
  String(text ?? '')
    .replaceAll('|', '\\|')
    .replaceAll('\n', ' ');

function advisoryRow(advisory) {
  const id = advisory.github_advisory_id ?? String(advisory.id);
  const path = advisory.findings?.[0]?.paths?.[0] ?? '';
  return `| ${mdEscape(advisory.module_name)} | ${advisory.severity} | [${id}](${advisory.url}) | ${mdEscape(advisory.title)} | \`${mdEscape(path)}\` |`;
}

function buildReport({ counts, blocking, waived, stale, nonBlocking }) {
  const lines = ['# Dependency audit', ''];
  const totals = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([severity, n]) => `${n} ${severity}`)
    .join(', ');
  lines.push(`\`pnpm audit\` — gate: **high/critical** — found: ${totals || 'no advisories'}.`, '');

  if (blocking.length > 0) {
    lines.push(`## Blocking advisories (${blocking.length})`, '');
    lines.push(
      '| Package | Severity | Advisory | Title | Via |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const advisory of blocking) lines.push(advisoryRow(advisory));
    lines.push('');
    lines.push(
      'Fix by upgrading the dependency or raising its floor via `pnpm.overrides`; if no fixed',
      'release exists, add an expiring waiver — see CONTRIBUTING.md ("Dependency advisories and waivers").',
      '',
    );
  } else {
    lines.push('No blocking advisories.', '');
  }

  if (waived.length > 0) {
    lines.push(`## Waived (${waived.length})`, '');
    lines.push('| Package | Advisory | Expires | Reason |', '| --- | --- | --- | --- |');
    for (const { advisory, waiver } of waived) {
      const id = advisory.github_advisory_id ?? String(advisory.id);
      lines.push(
        `| ${mdEscape(advisory.module_name)} | [${id}](${advisory.url}) | ${waiver.expires} | ${mdEscape(waiver.reason)} |`,
      );
    }
    lines.push('');
  }

  if (stale.length > 0) {
    lines.push(`## Stale waivers (${stale.length}) — remove these`, '');
    for (const { waiver, why } of stale) {
      lines.push(`- \`${waiver.advisory}\` — ${why}`);
    }
    lines.push('');
  }

  if (nonBlocking.length > 0) {
    lines.push(`## Below the gate (${nonBlocking.length}, non-blocking)`, '');
    lines.push(
      '| Package | Severity | Advisory | Title | Via |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const advisory of nonBlocking) lines.push(advisoryRow(advisory));
    lines.push('');
  }

  return lines.join('\n');
}

function main() {
  let waivers;
  let audit;
  try {
    waivers = loadWaivers();
    audit = runAudit();
  } catch (error) {
    writeFileSync(
      REPORT_PATH,
      `# Dependency audit\n\n**Audit could not be completed.** ${error.message}\n`,
    );
    console.log(`::error::dependency audit could not be completed: ${error.message}`);
    process.exitCode = 2;
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  const isActive = (waiver) => waiver.expires >= today;
  const advisories = Object.values(audit.advisories ?? {});

  const blocking = [];
  const waived = [];
  const nonBlocking = [];
  for (const advisory of advisories) {
    if (!BLOCKING_SEVERITIES.has(advisory.severity)) {
      nonBlocking.push(advisory);
      continue;
    }
    const waiver = waivers.find((w) => isActive(w) && waiverMatches(w, advisory));
    if (waiver) waived.push({ advisory, waiver });
    else blocking.push(advisory);
  }

  const stale = waivers.flatMap((waiver) => {
    if (!isActive(waiver)) return [{ waiver, why: `expired ${waiver.expires}` }];
    if (!advisories.some((advisory) => waiverMatches(waiver, advisory))) {
      return [{ waiver, why: 'matches no current advisory — likely fixed' }];
    }
    return [];
  });

  const counts = audit.metadata?.vulnerabilities ?? {};
  writeFileSync(REPORT_PATH, buildReport({ counts, blocking, waived, stale, nonBlocking }) + '\n');

  for (const advisory of blocking) {
    const id = advisory.github_advisory_id ?? String(advisory.id);
    console.log(
      `::error::${advisory.severity} advisory ${id} in ${advisory.module_name} — ${advisory.title} (${advisory.url})`,
    );
  }
  for (const { waiver, why } of stale) {
    console.log(`::notice::stale audit waiver ${waiver.advisory} — ${why}`);
  }

  if (blocking.length > 0) {
    console.log(
      `Dependency audit failed: ${blocking.length} blocking advisor${blocking.length === 1 ? 'y' : 'ies'} (see audit-report.md).`,
    );
    process.exitCode = 1;
    return;
  }
  console.log(
    `Dependency audit passed: ${waived.length} waived, ${nonBlocking.length} below the gate.`,
  );
}

main();
