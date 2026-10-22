'use client';
import {
  CREDENTIAL_OWNER_MAX_LENGTH,
  ROTATION_POLICY_MAX_DAYS,
  ROTATION_POLICY_MIN_DAYS,
} from '@akasecurity/schema';
import { Button, Input } from '@akasecurity/ui-kit';
import { useEffect, useId, useRef, useState } from 'react';

import { RefusalReason, refusedControlProps } from '../shared/Refusal.tsx';
import type { CredentialRotationInput } from './types.ts';

const SAVE_FAILED = "Couldn't save the rotation details.";
const REFUSED = "You can't edit this credential's rotation details.";
const DAY_MS = 86_400_000;

interface Draft {
  owner: string;
  lastRotated: string;
  policy: string;
}

function draftOf(current: CredentialRotationInput): Draft {
  return {
    owner: current.owner ?? '',
    lastRotated: current.lastRotated?.slice(0, 10) ?? '',
    policy: current.rotationPolicyDays === null ? '' : String(current.rotationPolicyDays),
  };
}

/** The input a draft saves as, or why it cannot be saved. */
function parseDraft(
  draft: Draft,
  renderedAt: number,
): { input: CredentialRotationInput } | { problem: string } {
  const owner = draft.owner.trim();
  if (owner.length > CREDENTIAL_OWNER_MAX_LENGTH) {
    return { problem: `Owners are limited to ${String(CREDENTIAL_OWNER_MAX_LENGTH)} characters.` };
  }
  const policyText = draft.policy.trim();
  let policy: number | null = null;
  if (policyText !== '') {
    policy = /^\d+$/.test(policyText) ? Number(policyText) : Number.NaN;
    if (!(policy >= ROTATION_POLICY_MIN_DAYS && policy <= ROTATION_POLICY_MAX_DAYS)) {
      return {
        problem: `A rotation policy is a whole number of days from ${String(ROTATION_POLICY_MIN_DAYS)} to ${String(ROTATION_POLICY_MAX_DAYS)}.`,
      };
    }
  }
  const date = draft.lastRotated;
  if (date !== '') {
    const at = Date.parse(`${date}T00:00:00.000Z`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(at)) {
      return { problem: 'Enter the last rotation as a date.' };
    }
    // One day of slack for a reader ahead of UTC.
    if (at > renderedAt + DAY_MS) return { problem: 'The last rotation cannot be in the future.' };
  }
  return {
    input: {
      owner: owner === '' ? null : owner,
      lastRotated: date === '' ? null : date,
      rotationPolicyDays: policy,
    },
  };
}

/** Owner, last rotation and rotation policy, as an administrator enters them. */
export function RotationEditor({
  current,
  onSave,
  error,
  refusal: rawRefusal,
  renderedAt,
}: {
  current: CredentialRotationInput;
  onSave: (input: CredentialRotationInput) => Promise<void>;
  error: string | undefined;
  refusal: string | undefined;
  renderedAt: number;
}) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);
  const reasonId = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const refusal =
    rawRefusal === undefined ? undefined : rawRefusal.trim() === '' ? REFUSED : rawRefusal;
  if (refusal !== undefined && draft !== null) setDraft(null);
  const editing = draft !== null;
  const wasEditing = useRef(false);

  useEffect(() => {
    if (wasEditing.current && !editing) trigger.current?.focus();
    wasEditing.current = editing;
  }, [editing]);

  const close = () => {
    setDraft(null);
  };

  if (refusal !== undefined) {
    return (
      <div className="flex flex-col items-start gap-1">
        <Button
          ref={trigger}
          variant="outline"
          size="sm"
          {...refusedControlProps(reasonId, refusal, 'hover:bg-surface')}
        >
          Edit rotation
        </Button>
        <RefusalReason id={reasonId} dataSlot="credential-rotation-reason">
          {refusal}
        </RefusalReason>
      </div>
    );
  }
  if (draft === null) {
    return (
      <Button
        ref={trigger}
        variant="outline"
        size="sm"
        onClick={() => {
          setFailed(false);
          setDraft(draftOf(current));
        }}
      >
        Edit rotation
      </Button>
    );
  }

  const parsed = parseDraft(draft, renderedAt);
  const save = async (input: CredentialRotationInput) => {
    setSaving(true);
    try {
      await onSave(input);
      close();
    } catch {
      setFailed(true);
    } finally {
      setSaving(false);
    }
  };
  const field = (key: keyof Draft) => ({
    value: draft[key],
    disabled: saving,
    onChange: (e: { target: { value: string } }) => {
      setDraft({ ...draft, [key]: e.target.value });
    },
    onKeyDown: (e: { key: string }) => {
      if (e.key === 'Escape') close();
    },
  });

  return (
    <form
      className="flex flex-col gap-3 rounded-lg border border-border p-3"
      onSubmit={(e) => {
        e.preventDefault();
        if ('input' in parsed) void save(parsed.input);
      }}
    >
      <div className="grid gap-3 md:grid-cols-3">
        <label className="flex flex-col gap-1 text-xs font-semibold text-text-2">
          Owner
          <Input
            aria-label="Owner"
            autoFocus
            maxLength={CREDENTIAL_OWNER_MAX_LENGTH}
            placeholder="Team or person"
            {...field('owner')}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs font-semibold text-text-2">
          Last rotated
          <Input aria-label="Last rotated" type="date" {...field('lastRotated')} />
        </label>
        <label className="flex flex-col gap-1 text-xs font-semibold text-text-2">
          Rotation policy, in days
          <Input
            aria-label="Rotation policy in days"
            inputMode="numeric"
            placeholder="90"
            {...field('policy')}
          />
        </label>
      </div>
      <p className="text-xs text-text-3">
        Leave a field empty to clear it. With a policy and no rotation date, the policy counts from
        when the credential was first seen.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" size="sm" disabled={saving || !('input' in parsed)}>
          Save
        </Button>
        <Button type="button" variant="ghost" size="sm" disabled={saving} onClick={close}>
          Cancel
        </Button>
      </div>
      {failed ? (
        <p role="alert" className="text-xs text-sev-critical-ink">
          {error ?? SAVE_FAILED}
        </p>
      ) : (
        'problem' in parsed && (
          <p role="alert" className="text-xs text-sev-critical-ink">
            {parsed.problem}
          </p>
        )
      )}
    </form>
  );
}
