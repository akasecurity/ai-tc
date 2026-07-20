import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  EXPECTED_REPOSITORY,
  EXPECTED_WORKFLOW_PATH,
  PROVENANCE_CHECK_TIMEOUT_MS,
  verifyProvenance,
} from '../src/provenance.ts';

const PACKAGE_NAME = '@akasecurity/ai-tc-claude-code';
const VERSION = '0.8.2';
const SUBJECT_PURL = `pkg:npm/%40akasecurity/ai-tc-claude-code@${VERSION}`;

// Encodes an in-toto statement the way npm's registry does — base64 inside a
// DSSE envelope — so fixtures exercise the exact bytes the parser decodes.
const encodePayload = (statement: unknown): string =>
  Buffer.from(JSON.stringify(statement), 'utf8').toString('base64');

// Builds an `npm audit signatures --json --include-attestations` report for a
// single verified package. `workflow` seeds the SLSA provenance predicate's
// buildDefinition; `subjectPurl` seeds the attestation subject binding.
const buildReport = (opts: {
  name?: string;
  version?: string;
  subjectPurl?: string;
  workflow?: { repository: string; path: string } | null;
  includeSlsa?: boolean;
}): string => {
  const {
    name = PACKAGE_NAME,
    version = VERSION,
    subjectPurl = SUBJECT_PURL,
    workflow = { repository: EXPECTED_REPOSITORY, path: EXPECTED_WORKFLOW_PATH },
    includeSlsa = true,
  } = opts;

  const attestationBundles: unknown[] = [
    // The npm publish-attestation bundle carries the subject but no workflow —
    // present in real reports and correctly ignored by the parser.
    {
      predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
      bundle: {
        dsseEnvelope: {
          payload: encodePayload({
            predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
            subject: [{ name: subjectPurl, digest: { sha512: 'deadbeef' } }],
          }),
        },
      },
    },
  ];

  if (includeSlsa) {
    attestationBundles.push({
      predicateType: 'https://slsa.dev/provenance/v1',
      bundle: {
        dsseEnvelope: {
          payload: encodePayload({
            predicateType: 'https://slsa.dev/provenance/v1',
            subject: [{ name: subjectPurl, digest: { sha512: 'deadbeef' } }],
            predicate:
              workflow === null
                ? { buildDefinition: { externalParameters: {} } }
                : {
                    buildDefinition: {
                      externalParameters: {
                        workflow: {
                          ref: 'refs/heads/main',
                          repository: workflow.repository,
                          path: workflow.path,
                        },
                      },
                    },
                  },
          }),
        },
      },
    });
  }

  return JSON.stringify({
    invalid: [],
    missing: [],
    verified: [{ name, version, registry: 'https://registry.npmjs.org/', attestationBundles }],
  });
};

describe('verifyProvenance', () => {
  it('returns true for a matching attestation bound to the expected repository + workflow', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, (args) => {
      expect(args).toEqual(['audit', 'signatures', '--json', '--include-attestations']);
      return { ok: true, stdout: buildReport({}) };
    });
    expect(result).toBe(true);
  });

  it('returns false when the exact package@version is not in the verified set', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
      ok: true,
      stdout: JSON.stringify({ invalid: [], missing: [], verified: [] }),
    }));
    expect(result).toBe(false);
  });

  it('returns false when the verified entry carries no SLSA provenance attestation', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
      ok: true,
      stdout: buildReport({ includeSlsa: false }),
    }));
    expect(result).toBe(false);
  });

  it('returns false when the attestation binds to a different repository', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
      ok: true,
      stdout: buildReport({
        workflow: {
          repository: 'https://github.com/someone-else/unrelated',
          path: EXPECTED_WORKFLOW_PATH,
        },
      }),
    }));
    expect(result).toBe(false);
  });

  it('returns false when the attestation binds to a different workflow path', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
      ok: true,
      stdout: buildReport({
        workflow: { repository: EXPECTED_REPOSITORY, path: '.github/workflows/unrelated.yml' },
      }),
    }));
    expect(result).toBe(false);
  });

  it('returns false when the SLSA subject does not bind the exact package@version', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
      ok: true,
      stdout: buildReport({ subjectPurl: 'pkg:npm/%40akasecurity/ai-tc-claude-code@9.9.9' }),
    }));
    expect(result).toBe(false);
  });

  it('returns false when the matching identity is present but under a different version', () => {
    const result = verifyProvenance({ packageName: PACKAGE_NAME, version: '9.9.9' }, () => ({
      ok: true,
      stdout: buildReport({}),
    }));
    expect(result).toBe(false);
  });

  it('returns false when the runner reports unavailable (offline)', () => {
    expect(
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
        ok: false,
        stdout: '',
      })),
    ).toBe(false);
  });

  it('returns false when the runner reports ok but empty stdout', () => {
    expect(
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
        ok: true,
        stdout: '',
      })),
    ).toBe(false);
  });

  it('returns false on unparseable output rather than throwing', () => {
    expect(
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => ({
        ok: true,
        stdout: 'not json at all {{{',
      })),
    ).toBe(false);
  });

  it('returns false when the injected runner itself throws', () => {
    expect(
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }, () => {
        throw new Error('spawn exploded');
      }),
    ).toBe(false);
  });
});

// Places a fake `npm` first on PATH (mirroring the journey harness's writeFakeJudge
// pattern) so the REAL default runner is exercised end-to-end — real execFileSync,
// real stdout capture, real base64/JSON parse — without spawning a live npm.
const withFakeNpmOnPath = <T>(script: string, fn: () => T): T => {
  const binDir = mkdtempSync(join(tmpdir(), 'aka-provenance-bin-'));
  const npmPath = join(binDir, 'npm');
  writeFileSync(npmPath, script);
  chmodSync(npmPath, 0o755);
  // eslint-disable-next-line n/no-process-env -- test needs to prepend a fake npm onto the child's PATH
  const originalPath = process.env.PATH;
  // eslint-disable-next-line n/no-process-env -- test needs to prepend a fake npm onto the child's PATH
  process.env.PATH = `${binDir}:${originalPath ?? ''}`;
  try {
    return fn();
  } finally {
    // eslint-disable-next-line n/no-process-env -- restore the host PATH after the test
    process.env.PATH = originalPath;
    rmSync(binDir, { recursive: true, force: true });
  }
};

describe('verifyProvenance — real default runner against a fake npm on PATH', () => {
  it('returns true end-to-end when the real runner reads a matching verified report', () => {
    const report = buildReport({});
    const script = `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(report)});\n`;
    const result = withFakeNpmOnPath(script, () =>
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }),
    );
    expect(result).toBe(true);
  });

  it('returns true even when the fake npm exits non-zero but still prints the report', () => {
    // `npm audit signatures` exits 1 when any entry is unverified; the report is
    // still on stdout and the exact package@version must still be honored.
    const report = buildReport({});
    const script = `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(report)});\nprocess.exit(1);\n`;
    const result = withFakeNpmOnPath(script, () =>
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }),
    );
    expect(result).toBe(true);
  });

  it('terminates a non-terminating npm child and returns false within the timeout budget', () => {
    const script = '#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n';
    const start = Date.now();
    const result = withFakeNpmOnPath(script, () =>
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }),
    );
    const elapsed = Date.now() - start;
    expect(result).toBe(false);
    // Bounded, not indefinite — allow slack for spawn/teardown without waiting
    // anywhere near the length of an unbounded hang.
    expect(elapsed).toBeLessThan(PROVENANCE_CHECK_TIMEOUT_MS * 3);
  });

  it('returns false when a child prints a full matching report and then hangs', () => {
    // The report captured before the timeout kill must NOT count as success: a hung
    // shell-out is failed-open regardless of what it printed before being killed.
    const report = buildReport({});
    const script = `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(report)});\nsetInterval(() => {}, 1000);\n`;
    const start = Date.now();
    const result = withFakeNpmOnPath(script, () =>
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }),
    );
    const elapsed = Date.now() - start;
    expect(result).toBe(false);
    expect(elapsed).toBeLessThan(PROVENANCE_CHECK_TIMEOUT_MS * 3);
  });

  it('hard-kills a SIGTERM-resistant npm child within the budget and returns false', () => {
    // A child that traps SIGTERM cannot outlast the bound — the runner force-kills
    // with SIGKILL, which cannot be trapped or ignored.
    const script =
      '#!/usr/bin/env node\nprocess.on("SIGTERM", () => {});\nsetInterval(() => {}, 1000);\n';
    const start = Date.now();
    const result = withFakeNpmOnPath(script, () =>
      verifyProvenance({ packageName: PACKAGE_NAME, version: VERSION }),
    );
    const elapsed = Date.now() - start;
    expect(result).toBe(false);
    expect(elapsed).toBeLessThan(PROVENANCE_CHECK_TIMEOUT_MS * 3);
  });
});
