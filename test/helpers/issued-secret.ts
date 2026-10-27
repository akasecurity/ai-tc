/**
 * A value the bundled `secrets/twilio-key` rule matches, shaped like an issued
 * token rather than a placeholder.
 *
 * A rule's own example is a placeholder (a repeating digit run), and a block on
 * a fabricated provider token is lowered to a warn, so a test asserting a block
 * or a redact carries this value instead. Its body mixes letter case and digits
 * with no run of consecutive characters. Spelled by joining so no
 * credential-shaped literal sits in the source.
 */
export const ISSUED_TWILIO_SID = ['AC', 'f3Kq9ZpL', '2xWm7RtB', '4vNc8YhD', '6jS1uGe5'].join('');
