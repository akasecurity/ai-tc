import { defaultDataDir } from '@akasecurity/plugin-sdk';

// Every command accepts `--home <dir>` to point at an alternate AKA home (the
// ~/.aka base). Default is ~/.aka. NOT an env var — an explicit flag is testable
// and keeps the home path out of process.env.
export const HOME_OPTION = { home: { type: 'string' } } as const;

export function homeBase(home: string | undefined): string {
  return home ?? defaultDataDir();
}
