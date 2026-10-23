// The longest owner a credential may carry, measured after trimming. An input
// capped at this length caps the untrimmed text, which is the stricter of the two.
export const CREDENTIAL_OWNER_MAX_LENGTH = 120;

// A rotation policy is a whole number of days in this range.
export const ROTATION_POLICY_MIN_DAYS = 1;
export const ROTATION_POLICY_MAX_DAYS = 3650;
