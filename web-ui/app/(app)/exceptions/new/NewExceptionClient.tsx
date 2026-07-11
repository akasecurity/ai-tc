'use client';

import type { AddExceptionRuleOption, AddExceptionSubmission } from '@akasecurity/dashboard-ui';
import { AddExceptionForm } from '@akasecurity/dashboard-ui';
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';

import { addException } from '../actions';

export function NewExceptionClient({ rules }: { rules: AddExceptionRuleOption[] }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();

  const submit = (submission: AddExceptionSubmission) => {
    startTransition(async () => {
      const result = await addException(submission);
      if (result.ok) {
        router.push('/exceptions');
      } else {
        setError(result.error ?? 'Could not create the exception.');
      }
    });
  };

  return <AddExceptionForm rules={rules} onSubmit={submit} busy={busy} error={error} />;
}
