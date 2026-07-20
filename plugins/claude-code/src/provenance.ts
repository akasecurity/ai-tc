// A fail-open npm build-provenance attestation verifier. Given an npm
// attestation report, it confirms the exact package@version binds to the
// expected repository and release workflow; any failure or timeout yields
// false, never throws. The plugin cannot import @akasecurity/local-ops, so
// this shells out to `npm` directly with the same fail-open child-process
// style as packages/local-ops/src/exec.ts. No fetch() — the only network
// access is the `npm` child process itself, which downloads and
// cryptographically verifies the Sigstore attestation bundle.
import { execFileSync } from 'node:child_process';

// The repository and release-workflow identity a genuine attestation for this
// plugin must bind to. An attestation missing either, or bound to any other
// value, is a failed check.
export const EXPECTED_REPOSITORY = 'https://github.com/akasecurity/ai-tc';
export const EXPECTED_WORKFLOW_PATH = '.github/workflows/release-plugin.yml';

// The SLSA provenance predicate type carried by an npm build-provenance
// attestation; its buildDefinition names the GitHub Actions workflow identity.
const SLSA_PROVENANCE_PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';

// Bounded budget for the whole check. When it elapses the child process is
// terminated and the check resolves to false — the wizard can never be
// blocked or delayed beyond this bound.
export const PROVENANCE_CHECK_TIMEOUT_MS = 2000;

export interface NpmRunResult {
  ok: boolean;
  stdout: string;
}

// Injected child-process seam: tests feed canned fixtures without spawning a
// real npm. The default runs the real `npm audit signatures` shell-out.
export type NpmRunner = (args: readonly string[]) => NpmRunResult;

// On Windows the global `npm` binary is `npm.cmd`; execFile refuses to spawn a
// `.cmd` without a shell (post CVE-2024-27980). Route through the shell there.
// The args are fixed flags with no shell metacharacters, so no quoting concern.
const USE_SHELL = process.platform === 'win32';

// Real subprocess runner. When the budget elapses the child is force-killed with
// SIGKILL (which a child cannot trap or ignore), so a hung shell-out is bounded
// hard. Never throws — a missing binary, non-zero exit, or timeout all resolve to
// `{ ok: false }`.
function runNpmAudit(args: readonly string[]): NpmRunResult {
  try {
    const stdout = execFileSync('npm', [...args], {
      encoding: 'utf8',
      timeout: PROVENANCE_CHECK_TIMEOUT_MS,
      killSignal: 'SIGKILL',
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: USE_SHELL,
    });
    return { ok: true, stdout: stdout.trim() };
  } catch (err: unknown) {
    const e = err as { stdout?: unknown; signal?: unknown; code?: unknown };
    // A timed-out or otherwise-killed child must fail open: its partial pre-kill
    // stdout is never a report, so a hung shell-out that printed a matching report
    // before the kill can never satisfy the check.
    const wasKilled = e.code === 'ETIMEDOUT' || typeof e.signal === 'string';
    // `npm audit signatures` exits non-zero when any entry is unverified but still
    // prints the JSON report to stdout — surface a normal-exit report so the parser
    // reads the verified set rather than treating a non-zero exit as no data.
    if (!wasKilled && typeof e.stdout === 'string' && e.stdout.trim() !== '') {
      return { ok: true, stdout: e.stdout.trim() };
    }
    return { ok: false, stdout: '' };
  }
}

export interface VerifyProvenanceInput {
  packageName: string;
  version: string;
}

// The `npm audit signatures --json --include-attestations` report shape: a
// `verified` array of packages whose Sigstore attestations npm has already
// validated, each carrying the decoded attestation bundles.
interface AttestationBundle {
  predicateType?: unknown;
  bundle?: {
    dsseEnvelope?: {
      payload?: unknown;
    };
  };
}

interface VerifiedEntry {
  name?: unknown;
  version?: unknown;
  attestationBundles?: unknown;
}

interface AuditSignaturesReport {
  verified?: unknown;
}

// The in-toto statement carried (base64) in a bundle's DSSE payload: it binds
// the attestation to an exact package (subject) and, for SLSA provenance, names
// the source repository + workflow that built it.
interface InTotoStatement {
  subject?: unknown;
  predicate?: {
    buildDefinition?: {
      externalParameters?: {
        workflow?: {
          repository?: unknown;
          path?: unknown;
        };
      };
    };
  };
}

// purl for an npm package: a leading scope `@` is percent-encoded to `%40`,
// the scope separator stays a literal `/`, e.g. `pkg:npm/%40akasecurity/x@1.0.0`.
function expectedSubjectPurl(packageName: string, version: string): string {
  return `pkg:npm/${packageName.replace(/^@/, '%40')}@${version}`;
}

// True only when the SLSA provenance attestation for the exact `packageName@version`
// binds to both EXPECTED_REPOSITORY and EXPECTED_WORKFLOW_PATH. Reads only npm's
// already-verified set, so a bundle appearing here has passed Sigstore validation.
function verifiedReportBindsExpectedIdentity(
  report: unknown,
  packageName: string,
  version: string,
): boolean {
  if (typeof report !== 'object' || report === null) return false;
  const verified = (report as AuditSignaturesReport).verified;
  if (!Array.isArray(verified)) return false;

  const entry = verified.find((candidate): candidate is VerifiedEntry => {
    if (typeof candidate !== 'object' || candidate === null) return false;
    const e = candidate as VerifiedEntry;
    return e.name === packageName && e.version === version;
  });
  if (!entry || !Array.isArray(entry.attestationBundles)) return false;

  const expectedSubject = expectedSubjectPurl(packageName, version);

  for (const rawBundle of entry.attestationBundles) {
    if (typeof rawBundle !== 'object' || rawBundle === null) continue;
    const bundle = rawBundle as AttestationBundle;
    if (bundle.predicateType !== SLSA_PROVENANCE_PREDICATE_TYPE) continue;

    const payload = bundle.bundle?.dsseEnvelope?.payload;
    if (typeof payload !== 'string') continue;

    let statement: InTotoStatement;
    try {
      statement = JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) as InTotoStatement;
    } catch {
      continue;
    }

    const subject = statement.subject;
    const boundToExactPackage =
      Array.isArray(subject) &&
      subject.some(
        (s) =>
          typeof s === 'object' && s !== null && (s as { name?: unknown }).name === expectedSubject,
      );
    if (!boundToExactPackage) continue;

    const workflow = statement.predicate?.buildDefinition?.externalParameters?.workflow;
    if (!workflow) continue;
    if (workflow.repository === EXPECTED_REPOSITORY && workflow.path === EXPECTED_WORKFLOW_PATH) {
      return true;
    }
  }

  return false;
}

// Verify that the EXACT executing `packageName@version` carries a Sigstore
// provenance attestation binding it to EXPECTED_REPOSITORY and
// EXPECTED_WORKFLOW_PATH. Fail-open everywhere: offline, npm missing, a
// non-zero exit with no report, unparseable output, a timed-out hung child, or
// any thrown error all resolve to false — never a throw.
export function verifyProvenance(
  input: VerifyProvenanceInput,
  runNpm: NpmRunner = runNpmAudit,
): boolean {
  try {
    const result = runNpm(['audit', 'signatures', '--json', '--include-attestations']);
    if (!result.ok || result.stdout.trim() === '') return false;
    const parsed: unknown = JSON.parse(result.stdout);
    return verifiedReportBindsExpectedIdentity(parsed, input.packageName, input.version);
  } catch {
    return false;
  }
}
