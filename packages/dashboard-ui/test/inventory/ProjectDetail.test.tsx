import type {
  FileSummary,
  HarnessSummary,
  ProjectSummary,
  SensitiveDataClass,
} from '@akasecurity/schema';
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

const SECRET: SensitiveDataClass = {
  category: 'secret',
  files: 2,
  severity: 'critical',
  lastDetectedAt: '2026-10-15T10:00:00.000Z',
};

function render(
  blockedCount: number,
  blocked: FileSummary[],
  blockedError?: string,
  sensitive: { items?: SensitiveDataClass[]; error?: string; refusal?: string } = {},
  machines?: number,
): string {
  return renderToStaticMarkup(
    <ProjectDetail
      project={{ ...project(blockedCount), ...(machines === undefined ? {} : { machines }) }}
      blocked={blocked}
      blockedError={blockedError}
      sensitiveData={sensitive.items ?? []}
      sensitiveDataError={sensitive.error}
      sensitiveDataRefusal={sensitive.refusal}
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

  it('labels the findings stat with its 30-day window', () => {
    expect(render(0, [])).toContain('Findings · 30d');
  });

  it('lists the categories of sensitive data, with their files, severity and age', () => {
    const html = render(0, [], undefined, {
      items: [SECRET, { ...SECRET, category: 'pii', files: 1, severity: 'medium' }],
    });
    expect(html).toContain('Sensitive data present');
    expect(html).toContain('Secret');
    expect(html).toContain('2 files');
    expect(html).toContain('PII');
    expect(html).toContain('1 file<');
    expect(html).toContain('critical');
    expect(html).toContain('2 hours ago');
  });

  it('says a category found in no file was found in prompts and output', () => {
    const html = render(0, [], undefined, { items: [{ ...SECRET, files: 0 }] });
    expect(html).toContain('In prompts &amp; output');
    expect(html).not.toContain('0 files');
  });

  it('says when the project has no sensitive data in the window', () => {
    expect(render(0, [])).toContain('No sensitive data found in the last 30 days.');
  });

  it('reports a failed sensitive-data read instead of saying there is none', () => {
    const html = render(0, [], undefined, { error: 'Request failed (500)' });
    expect(html).toContain('Couldn&#x27;t load the sensitive data: Request failed (500)');
    expect(html).not.toContain('No sensitive data found');
  });

  it('shows the refusal in place of the sensitive data when the viewer may not read it', () => {
    const html = render(0, [], undefined, { items: [SECRET], refusal: 'Not allowed.' });
    expect(html).toContain('Not allowed.');
    expect(html).not.toContain('2 files');
    expect(html).not.toContain('No sensitive data found');
  });

  it('shows the endpoints the project was seen on when the store records them', () => {
    const html = render(0, [], undefined, {}, 7);
    expect(html).toContain('Endpoints seen on');
    expect(html).toMatch(/>7<\/div><div[^>]*>Endpoints seen on/);
    expect(render(0, [], undefined, {}, 100)).toMatch(/>100\+<\/div><div[^>]*>Endpoints seen on/);
  });

  it('shows no endpoint figure when the store or the reader has none', () => {
    expect(render(0, [])).not.toContain('Endpoints seen on');
  });

  it('says every file is available when none are withheld', () => {
    expect(render(0, [])).toContain('Every file in this project is available to approved models.');
  });
});
