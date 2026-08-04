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

  // A bare router.push, deliberately NOT the shared navigation transition: this
  // redirect is the tail of a write that already owns `busy` (which disables
  // the form), and it leaves the route, so the destination's loading boundary
  // is what covers it. Routing it through the shared transition would report a
  // second pending state for the same one action.
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
