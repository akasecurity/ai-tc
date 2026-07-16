import { describe, expect, it } from 'vitest';

import { renderMultiRepoSummary, renderWorktreeSummary } from '../src/render.ts';
import type { MultiRepoScanSummary, WorktreeScanSummary } from '../src/scan.ts';

function worktree(overrides: Partial<WorktreeScanSummary> = {}): WorktreeScanSummary {
  return {
    rootDir: '/repo',
    scanned: 3,
    skipped: 1,
    findings: 0,
    gitignoredFindings: 0,
    byRule: {},
    bySeverity: {},
    ...overrides,
  };
}

function multiRepo(overrides: Partial<MultiRepoScanSummary> = {}): MultiRepoScanSummary {
  return {
    repos: [],
    totalScanned: 0,
    totalSkipped: 0,
    totalFindings: 0,
    totalGitignoredFindings: 0,
    byRule: {},
    bySeverity: {},
    ...overrides,
  };
}

describe('renderWorktreeSummary', () => {
  it('renders the clean-scan shape', () => {
    const out = renderWorktreeSummary(worktree());
    expect(out).toContain('✓ Worktree scan complete');
    expect(out).toContain('Scanned   3 files');
    expect(out).toContain('Skipped   1 (already recorded)');
    expect(out).toContain('No code security issues detected.');
  });

  it('renders severity and rule tables when there are findings', () => {
    const out = renderWorktreeSummary(
      worktree({
        findings: 3,
        byRule: { 'code-flaws/sql-inject-concat': 2, 'code-flaws/xss-inner-html': 1 },
        bySeverity: { high: 2, medium: 1 },
      }),
    );
    expect(out).toContain('SEVERITY');
    expect(out).toContain('▓ high');
    expect(out).toContain('▒ medium');
    expect(out).toContain('RULE');
    expect(out).toContain('code-flaws/sql-inject-concat   2');
  });

  it('marks gitignored findings as informational', () => {
    const out = renderWorktreeSummary(
      worktree({ findings: 2, gitignoredFindings: 1, bySeverity: { high: 2 }, byRule: {} }),
    );
    expect(out).toContain("2 (1 in .gitignore'd files — informational)");
  });

  it('appends the host-supplied follow-up hint only when given', () => {
    const summary = worktree({ findings: 1, bySeverity: { low: 1 }, byRule: { 'x/y': 1 } });
    expect(
      renderWorktreeSummary(summary, { followUp: 'Run /findings to review details.' }),
    ).toContain('Run /findings to review details.');
    expect(renderWorktreeSummary(summary)).not.toContain('/findings');
  });
});

describe('renderMultiRepoSummary', () => {
  it('renders the no-repos shape', () => {
    expect(renderMultiRepoSummary(multiRepo())).toContain('No repositories found.');
  });

  it('renders a per-repo breakdown with basenames', () => {
    const out = renderMultiRepoSummary(
      multiRepo({
        repos: [
          {
            rootDir: '/home/dev/api',
            summary: worktree({ rootDir: '/home/dev/api', findings: 2, scanned: 5 }),
          },
          { rootDir: '/home/dev/web', summary: worktree({ rootDir: '/home/dev/web', scanned: 0 }) },
        ],
        totalScanned: 5,
        totalFindings: 2,
        bySeverity: { critical: 2 },
      }),
    );
    expect(out).toContain('✓ Multi-repo scan complete');
    expect(out).toContain('REPO');
    expect(out).toContain('api');
    // Repos with nothing scanned and no findings are omitted from the table.
    expect(out).not.toContain('web');
    expect(out).toContain('█ critical');
  });

  it('appends the follow-up hint only when given', () => {
    const summary = multiRepo({
      repos: [{ rootDir: '/r', summary: worktree({ findings: 1 }) }],
      totalFindings: 1,
      bySeverity: { low: 1 },
    });
    expect(renderMultiRepoSummary(summary, { followUp: 'See findings.' })).toContain(
      'See findings.',
    );
    expect(renderMultiRepoSummary(summary)).not.toContain('See findings.');
  });
});
