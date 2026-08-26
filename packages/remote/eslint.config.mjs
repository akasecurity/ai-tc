// @ts-check
import {
  base,
  drizzleWallRules,
  noDrizzleImports,
  rootConfigFiles,
} from '@akasecurity/eslint-config';

export default [
  ...base,
  ...noDrizzleImports,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  ...rootConfigFiles,
  {
    // THE ONE FILE IN THIS WORKSPACE THAT MAY REACH THE NETWORK.
    //
    // An attached machine talks to the deployment its own settings name, so the
    // request has to happen somewhere. Confining it to a single module — rather
    // than relaxing the ban for the package — is what keeps the exception
    // reviewable: everything else here builds and parses, and only this file
    // sends.
    //
    // `node:https` rather than `fetch`, for two reasons beyond the config
    // mechanism. Node's client does not follow redirects at all, so a
    // credential can never be replayed to whatever a `Location` header names —
    // a property of the transport rather than a flag a later edit can drop. And
    // the module bans (unlike the globals ban) take an `allow`, so this
    // exception is a config artifact the workspace's opt-out audits enumerate
    // instead of an inline directive that only a directive inventory can see.
    //
    // `node:http` rides along for loopback only, which is what makes a
    // deployment exercisable locally; `isSafeEndpoint` is what refuses it
    // anywhere else, and no allowance here can substitute for that check.
    //
    // Built through `drizzleWallRules` rather than `noNetworkImports` directly:
    // this entry SETS both rules and flat config replaces rather than merges,
    // so stating only the network side would silently drop the Drizzle wall for
    // this file while lint stayed green.
    files: ['src/http.ts'],
    rules: drizzleWallRules({ allow: ['node:http', 'node:https'] }),
  },
  {
    // The suite stands a real server on 127.0.0.1, because what it tests is a
    // transport: that a deadline fires, that an oversized body is refused, that
    // a 3xx comes back as a status rather than being followed. Those are socket
    // behaviours, and a mocked `node:https` would leave every one of them
    // unproven. Loopback is what the runtime no-network guard and the
    // egress-blocked CI job both permit.
    files: ['test/helpers/loopback.ts'],
    rules: drizzleWallRules({ allow: ['node:http'] }),
  },
];
