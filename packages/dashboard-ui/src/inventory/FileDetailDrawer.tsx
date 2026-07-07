'use client';

// The per-file detail body rendered inside the right-edge Sheet: LLM-access
// radio options, "why this default" rationale, related findings & metadata.
// Backed by GET /v1/inventory/projects/:id/files; the access picker writes back
// through PUT .../files/access.
import type { AccessLevel, FileDetail } from '@akasecurity/schema';
import { SheetHeader, SheetTitle } from '@akasecurity/ui-kit';

import { MetaItem } from '../shared/DetailFields.tsx';
import { OriginTag, RadioCardList, Section, VisBadge } from './chips.tsx';
import { ACCESS, ACCESS_ORDER, fmtDateTime, originMeta, rationale } from './data.ts';
import { Ico } from './Ico.tsx';

export function FileDetailDrawer({
  file,
  onChange,
}: {
  file: FileDetail;
  onChange: (v: AccessLevel) => void;
}) {
  const om = originMeta[file.origin];
  const project = file.project;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <SheetHeader className="flex-row items-center gap-2.5 py-4 px-5">
        <span className="grid size-7.5 shrink-0 place-items-center rounded-lg bg-surface-2 text-text-2">
          <Ico name="file" className="size-4.5" />
        </span>
        <SheetTitle className="min-w-0 truncate font-mono text-sm">{file.name}</SheetTitle>
      </SheetHeader>

      <div className="mt-1 flex min-h-0 flex-1 flex-col gap-4.5 overflow-y-auto border-t border-border py-4 px-5">
        <div>
          <div className="break-all font-mono text-xs text-text-3">
            {project.repo} › {file.path}
          </div>
          <div className="mt-2 flex items-center gap-2">
            <OriginTag origin={file.origin} />
            <VisBadge v={project.visibility} />
            {file.findings > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-sev-critical-fill px-2 py-0.5 text-xs font-semibold text-sev-critical">
                <Ico name="alert" className="size-3" />
                {file.findings} finding{file.findings === 1 ? '' : 's'}
              </span>
            )}
          </div>
        </div>

        <Section label="LLM access">
          <RadioCardList
            order={ACCESS_ORDER}
            meta={ACCESS}
            value={file.access}
            onChange={onChange}
            accentOf={(a) => a.bar}
          />
        </Section>

        <div className="flex gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
          <Ico name={om.icon} className="size-4.5 shrink-0 text-text-2" />
          <div>
            <div className="mb-0.5 text-xs font-semibold">Why this default</div>
            <div className="text-xs leading-relaxed text-text-2">
              {rationale(project, file.origin)}
            </div>
          </div>
        </div>

        {file.findingsRefs.length > 0 && (
          <Section label="Related findings">
            <div className="flex flex-col gap-1.5">
              {file.findingsRefs.map((ref) => (
                <button
                  key={ref.id}
                  type="button"
                  className="flex w-full cursor-pointer items-center gap-2.5 rounded-lg border border-border bg-primary-tint px-3 py-2.5 text-left"
                >
                  <Ico name="alert" className="size-4 shrink-0 text-sev-critical" />
                  <span className="flex-1 text-xs font-medium text-text">
                    {ref.title || file.note}
                  </span>
                  <span className="text-xs text-primary">Open in Findings</span>
                  <Ico name="chevron-right" className="size-4 text-text-3" />
                </button>
              ))}
            </div>
          </Section>
        )}

        <div className="grid grid-cols-2 gap-x-3 gap-y-3.5">
          <MetaItem label="Repository">
            <span className="font-mono text-xs">{project.repo}</span>
          </MetaItem>
          <MetaItem label="Visibility">
            {project.visibility === 'public' ? 'Public' : 'Private'}
          </MetaItem>
          <MetaItem label="Origin">{om.label}</MetaItem>
          <MetaItem label="Set by">
            {file.isCustom ? <span className="text-primary">You</span> : 'Default policy'}
          </MetaItem>
          <MetaItem label="Language">{project.language}</MetaItem>
          <MetaItem label="Last activity">
            {fmtDateTime(file.blockedAt ?? project.updatedAt)}
          </MetaItem>
        </div>
      </div>
    </div>
  );
}
