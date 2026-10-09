declare module 'aka:parsed-packs' {
  import type { ActionTaken, Rule } from '@akasecurity/schema';

  export const PARSED_DATA: {
    packs: readonly { packId: string; rules: Rule[] }[];
    // The action a fresh install enforces for each bundled rule id.
    actions: Readonly<Record<string, ActionTaken>>;
  };
}
