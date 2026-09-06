#!/usr/bin/env node
// The operator-facing CLI shim for the sanitiser. This file is deliberately
// thin: argv parsing, file I/O, approval-file reading and exit codes, and
// nothing else. Every sanitising decision lives in src/sanitize/ — a PURE,
// dependency-injected module this shim bundles and imports rather than
// reimplementing.
//
// It bundles rather than type-strip-imports src/sanitize/index.ts because
// that module's chain reaches @akasecurity/plugin-sdk/browser ->
// rule-packs.ts -> bundled-packs.generated.ts, which carries 101 JSON
// imports with no import attributes — raw Node refuses those at load
// (ERR_IMPORT_ATTRIBUTE_MISSING). esbuild resolves and inlines them at
// build time instead, so the bundle Node loads never names a bare JSON
// specifier.
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as esbuild from 'esbuild';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const REQUIRED_FLAGS = ['in', 'site', 'kind', 'direction', 'url', 'format', 'out'];
const VALID_KINDS = new Set(['conversation', 'account']);
const VALID_DIRECTIONS = new Set(['request', 'response']);
const VALID_FORMATS = new Set(['json', 'sse', 'ndjson', 'urlencoded', 'text']);

function usage(message) {
  process.stderr.write(`${message}\n`);
  process.stderr.write(
    'usage: sanitize-capture.mjs --in <path|-> --site <site> --kind <conversation|account> ' +
      '--direction <request|response> --url <url> --format <json|sse|ndjson|urlencoded|text> ' +
      '--out <path> [--survey] [--approved-keys <path>] [--approved-values <path>] ' +
      '[--allow-host <host>] [--force]\n',
  );
  process.exitCode = 2;
}

function parseArgs(argv) {
  const out = { allowHosts: [], survey: false, force: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--in':
        out.in = argv[(i += 1)];
        break;
      case '--site':
        out.site = argv[(i += 1)];
        break;
      case '--kind':
        out.kind = argv[(i += 1)];
        break;
      case '--direction':
        out.direction = argv[(i += 1)];
        break;
      case '--url':
        out.url = argv[(i += 1)];
        break;
      case '--format':
        out.format = argv[(i += 1)];
        break;
      case '--out':
        out.out = argv[(i += 1)];
        break;
      case '--survey':
        out.survey = true;
        break;
      case '--approved-keys':
        out.approvedKeysPath = argv[(i += 1)];
        break;
      case '--approved-values':
        out.approvedValuesPath = argv[(i += 1)];
        break;
      case '--allow-host':
        out.allowHosts.push(argv[(i += 1)]);
        break;
      case '--force':
        out.force = true;
        break;
      default:
        return { error: `unknown flag: ${arg}` };
    }
  }
  return { value: out };
}

// Thrown for a failure reading an operator-supplied INPUT (the capture, or an
// approval list) whose message must never carry the path — an operator's
// filename can itself disclose something (a project name, a person's name),
// and Node's own fs error text always embeds the path it failed on.
class InputReadError extends Error {
  constructor(what, code) {
    super(`could not read ${what} (${code})`);
  }
}

function errorCode(err) {
  return err !== null && typeof err === 'object' && 'code' in err ? String(err.code) : 'unknown';
}

function readInput(inPath) {
  try {
    if (inPath === '-') return readFileSync(0, 'utf8');
    return readFileSync(inPath, 'utf8');
  } catch (err) {
    throw new InputReadError('--in', errorCode(err));
  }
}

/** Line-delimited: blank lines and lines starting with # (after trim) are ignored. */
function parseApprovalFile(what, filePath) {
  if (filePath === undefined) return new Set();
  let text;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new InputReadError(what, errorCode(err));
  }
  const out = new Set();
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    out.add(line);
  }
  return out;
}

async function loadSanitizeModule() {
  const entry = join(root, 'src', 'sanitize', 'index.ts');
  const built = await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'esm',
    write: false,
    target: 'node20',
  });
  const outputFile = built.outputFiles[0];
  if (outputFile === undefined)
    throw new Error('esbuild produced no output for src/sanitize/index.ts');
  // A dev-only build artifact, never dist/ or native-host/ — both are shipped
  // outputs cli/scripts/bundle-extension.mjs copies into the CLI, and a
  // sanitiser bundle has no business riding along.
  const tmpDir = mkdtempSync(join(tmpdir(), 'aka-sanitize-'));
  const tmpFile = join(tmpDir, 'sanitize-bundle.mjs');
  writeFileSync(tmpFile, outputFile.text);
  return { tmpDir, moduleUrl: pathToFileURL(tmpFile).href };
}

function refuseIfExists(path, force) {
  if (existsSync(path) && !force) {
    usage(`refusing to overwrite existing file without --force: ${path}`);
    return false;
  }
  return true;
}

// The survey lists strings lifted VERBATIM out of the real capture: every
// candidate the detector did not flag, unpruned. It is raw capture content,
// not sanitised output, and the header says so in the file itself — the only
// place an operator is certain to read it.
const SURVEY_HEADER = [
  '# RAW CAPTURE CONTENT — every line below was lifted verbatim out of the',
  '# capture and is NOT sanitised. Prune it by hand before any of it becomes',
  '# an approvals file, and do not commit this file.',
].join('\n');

function writeSurveyFile(path, candidates, flagged) {
  const lines = [...new Set(candidates)].sort();
  for (const entry of flagged) {
    lines.push(`# [detected:${entry.ruleIds.join(', ')}] <withheld>`);
  }
  writeFileSync(path, `${SURVEY_HEADER}\n${lines.length > 0 ? `${lines.join('\n')}\n` : ''}`);
}

// The committed fixtures directory. A survey written here lands in the very
// directory the operator is about to `git add`, and .gitignore's allowlist
// there covers only the artifacts the bar reads — so refuse rather than trust
// the ignore rules to have been read.
const FIXTURE_ROOT = join(root, 'test', 'fixtures');

function isInsideFixtureRoot(outPath) {
  const rel = relative(FIXTURE_ROOT, resolve(outPath));
  return rel === '' || (!rel.startsWith('..') && !rel.startsWith('/'));
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if ('error' in parsed) {
    usage(parsed.error);
    return;
  }
  const args = parsed.value;

  const missing = REQUIRED_FLAGS.filter((flag) => args[flag] === undefined);
  if (missing.length > 0) {
    usage(`missing required flag(s): ${missing.map((f) => `--${f}`).join(', ')}`);
    return;
  }
  if (!VALID_KINDS.has(args.kind)) {
    usage(`--kind must be one of ${[...VALID_KINDS].join('/')}`);
    return;
  }
  if (!VALID_DIRECTIONS.has(args.direction)) {
    usage(`--direction must be one of ${[...VALID_DIRECTIONS].join('/')}`);
    return;
  }
  if (!VALID_FORMATS.has(args.format)) {
    usage(`--format must be one of ${[...VALID_FORMATS].join('/')}`);
    return;
  }

  const outputPaths = args.survey ? [`${args.out}.keys.txt`, `${args.out}.values.txt`] : [args.out];
  if (args.survey && isInsideFixtureRoot(args.out)) {
    usage(
      'refusing to write a survey inside test/fixtures/: it carries raw capture content. ' +
        'Write it outside the repository and paste the pruned lines into the approvals files.',
    );
    return;
  }
  for (const path of outputPaths) {
    if (!refuseIfExists(path, args.force)) return;
  }

  let raw;
  let approvedKeys;
  let approvedValues;
  try {
    raw = readInput(args.in);
    approvedKeys = parseApprovalFile('--approved-keys', args.approvedKeysPath);
    approvedValues = parseApprovalFile('--approved-values', args.approvedValuesPath);
  } catch (err) {
    process.stderr.write(`${err instanceof InputReadError ? err.message : String(err)}\n`);
    process.exitCode = 1;
    return;
  }

  const { tmpDir, moduleUrl } = await loadSanitizeModule();
  try {
    const mod = await import(moduleUrl);
    const allowedHosts = [...mod.hostnamesForSite(args.site), ...args.allowHosts];
    const detect = mod.createDetector();

    const result = mod.sanitizeCapture({
      raw,
      url: args.url,
      site: args.site,
      kind: args.kind,
      direction: args.direction,
      format: args.format,
      allowedHosts,
      approvedKeys,
      approvedValues,
      detect,
    });

    // The survey is written BEFORE the refusal is acted on. A refused run is
    // exactly when the operator needs the candidate lists — the approvals
    // that would unblock it are built from them — and a survey that only
    // works once the run already succeeds cannot bootstrap anything.
    if (args.survey && result.report !== null) {
      writeSurveyFile(
        `${args.out}.keys.txt`,
        result.report.candidateKeys,
        result.report.flaggedKeys,
      );
      writeSurveyFile(
        `${args.out}.values.txt`,
        result.report.candidateValues,
        result.report.flaggedValues,
      );
      process.stderr.write(
        `survey written (RAW capture content — prune before use): ` +
          `${String(result.report.candidateKeys.length)} candidate key(s), ` +
          `${String(result.report.candidateValues.length)} candidate value(s), ` +
          `${String(result.report.flaggedKeys.length + result.report.flaggedValues.length)} flagged\n`,
      );
    }

    if (!result.ok) {
      process.stderr.write(`refused (${result.refusal}): ${result.error}\n`);
      process.exitCode = 1;
      return;
    }

    if (args.survey) return;

    writeFileSync(args.out, result.text);
    process.stderr.write(
      `sanitized fixture written to ${args.out}: ${String(result.report.leaves)} leaves scanned, ` +
        `${String(result.report.preservedKeys.length)} key(s) and ` +
        `${String(result.report.preservedValues.length)} value(s) preserved verbatim, ` +
        `${String(result.report.smallIntegersKept)} small integer(s) and ` +
        `${String(result.report.booleansKept)} boolean(s) kept verbatim\n`,
    );
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

try {
  await main();
} catch (err) {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exitCode = 1;
}
