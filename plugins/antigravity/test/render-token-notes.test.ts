import { API_EQUIVALENT_LOWER_BOUND_NOTE, SPEND_LOWER_BOUND_NOTE } from '@akasecurity/schema';

import { describeTokenNotes } from '../../../test/helpers/token-notes.ts';
import { renderTokens } from '../src/render.ts';

describeTokenNotes(renderTokens, {
  spend: SPEND_LOWER_BOUND_NOTE,
  apiEquivalent: API_EQUIVALENT_LOWER_BOUND_NOTE,
});
