import type { FileSummary, HarnessSummary, ProjectSummary } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ProjectDetail } from '../../src/inventory/ProjectDetail.tsx';

const NOW = Date.parse('2026-10-15T12:00:00.000Z');

function project(blocked: number): ProjectSummary {
  return {
    id: 'proj-1',
    name: 'payments-api',
    repo: 'acme/payments-api',
    visibility: 'private',
    language: 'TypeScript',
    policyDefault: 'approved',
    updatedAt: '2026-10-15T11:58:00.000Z',
    accessCounts: { open: 3, approved: 0, blocked, total: 3 + blocked },
    findingsCount: 4,
  };
}

const BLOCKED: FileSummary = {
  path: 'src/config/aws.ts',
  name: 'aws.ts',
  origin: 'source',
  access: 'blocked',
  isCustom: false,
  findings: 1,
  blockedAt: '2026-10-15T11:00:00.000Z',
  note: 'AWS access key detected',
};

const HARNESS: HarnessSummary = {
  id: 'claudecode',
  label: 'Claude Code',
  kind: 'claude_code',
  version: '2.1.4',
  sessions: 1,
  assetCount: 0,
  flagCount: 0,
  projects: [project(0)],
  categories: [],
};

function render(blockedCount: number, blocked: FileSummary[], blockedError?: string): string {
  return renderToStaticMarkup(
    <ProjectDetail
      project={project(blockedCount)}
      blocked={blocked}
      blockedError={blockedError}
      harnesses={[HARNESS, { ...HARNESS, id: 'cursor', label: 'Cursor', projects: [] }]}
      onBack={() => undefined}
      backLabel="Projects"
      renderedAt={NOW}
      locale="en-US"
    />,
  );
}

describe('ProjectDetail', () => {
  it('lists the withheld files and the harnesses that loaded the project', () => {
    const html = render(1, [BLOCKED]);
    expect(html).toContain('src/config/aws.ts');
    expect(html).toContain('AWS access key detected');
    expect(html).toContain('Claude Code');
    expect(html).not.toContain('Cursor');
    expect(html).toContain('aria-label="Back to Projects"');
  });

  it('says how many more files are withheld than the auto-blocked list shows', () => {
    expect(render(3, [BLOCKED])).toContain('2 more withheld by the project&#x27;s policy');
    expect(render(2, [])).toContain('2 files are withheld by the project&#x27;s policy');
  });

  it('reports a failed withheld-files read instead of attributing the files to policy', () => {
    const html = render(3, [], 'Request failed (500)');
    expect(html).toContain('Couldn&#x27;t load the withheld files: Request failed (500)');
    expect(html).not.toContain('withheld by the project&#x27;s policy');
  });

  it('says every file is available when none are withheld', () => {
    expect(render(0, [])).toContain('Every file in this project is available to approved models.');
  });
});
