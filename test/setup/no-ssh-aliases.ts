// Declare, once per test file, that this machine defines no SSH `Host` aliases.
//
// `~/.ssh/config` is read to resolve an alias to the host it names, so that
// every clone of one repository reduces to one identity (see `ssh-hosts.ts`).
// It is an absolute path outside `~/.aka`, so the temp homes these suites build
// do not redirect it: without this pin, a project id and a scope key would
// depend on whose laptop the suite ran on. A developer whose config carries
// `Host github.com` would compute different keys than CI, which has no config
// — and CI would stay green while their machine failed, which is the direction
// that wastes the most time.
//
// The same shape, and the same reasoning, as `no-managed-settings.ts`: a
// process-wide pin rather than a per-call override, because the thing it
// describes — which aliases this machine defines — is process-wide. A suite
// that is ABOUT the parser drops the pin itself and points a mocked `homedir`
// at a temp config.
//
// ONE MODULE by relative path, never the package barrel, for the reason
// `no-managed-settings.ts` sets out at length: a setup file loads before every
// test file, so importing the barrel here would pre-cache modules that suites
// later try to mock.
import { UNSAFE_TEST_ONLY_setSshHostAliases } from '../../packages/persistence/src/ssh-hosts.ts';

UNSAFE_TEST_ONLY_setSshHostAliases(new Map());
