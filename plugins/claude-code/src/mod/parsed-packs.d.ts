declare module 'aka:parsed-packs' {
  import type { Rule } from '@akasecurity/schema';

  export const PARSED_PACKS: readonly { packId: string; rules: Rule[] }[];
}
