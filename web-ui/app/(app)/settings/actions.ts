'use server';

import { applyOnboarding } from '@akasecurity/persistence';
import { HistoricalAccess, SimpleDetectionPolicy } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

// The web twin of the `/aka:setup` wizard's editable knobs, writing the same
// ~/.aka/settings/settings.json through the same shared writer (atomic
// tmp+rename, schema-validated merge). The plugin re-reads settings on every
// hook, so a save takes effect on the next capture — no restart.

export interface SaveSettingsResult {
  ok: boolean;
  error?: string;
}

// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function saveSettings(input: {
  policy: string;
  historicalAccess: string;
}): Promise<SaveSettingsResult> {
  const policy = SimpleDetectionPolicy.safeParse(input.policy);
  const historicalAccess = HistoricalAccess.safeParse(input.historicalAccess);
  if (!policy.success || !historicalAccess.success) {
    return { ok: false, error: 'Invalid settings value.' };
  }
  try {
    applyOnboarding({ policy: policy.data, historicalAccess: historicalAccess.data });
  } catch {
    return { ok: false, error: 'Could not write settings.json.' };
  }
  revalidatePath('/settings');
  return { ok: true };
}
