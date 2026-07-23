// Provider recognition for the egress writer: a bundled table of known SaaS/API
// hosts and dependency-manifest SDK identifiers, plus host classification
// (provider / internal / external / ip) and the version material the scanner's
// ledger key is derived from.
//
// Pure like everything in @akasecurity/detections: no I/O, no Node-API imports.
import type {
  DestinationKind,
  EgressEcosystem,
  ProviderRegistryEntry,
  ShareTrustLevel,
} from '@akasecurity/schema';

// Bumped whenever the resolution/matching rules below change (not the registry
// data itself — that's covered by PROVIDER_REGISTRY being embedded verbatim).
const EXTRACTOR_VERSION = '1';

// One row per known provider. `hostSuffixes` are suffix-matched (see
// hostMatchesSuffix): 'stripe.com' matches 'api.stripe.com' but never
// 'evilstripe.com'. `sdks` lists only ecosystems the provider ships a real SDK
// for.
export const PROVIDER_REGISTRY: readonly ProviderRegistryEntry[] = [
  {
    id: 'stripe',
    name: 'Stripe',
    category: 'Payments',
    hostSuffixes: ['stripe.com'],
    apiBase: 'https://api.stripe.com',
    defaultDataClasses: ['pii', 'customer'],
    sdks: {
      npm: ['stripe'],
      pypi: ['stripe'],
      go: ['github.com/stripe/stripe-go'],
      maven: ['com.stripe'],
      rubygems: ['stripe'],
      composer: ['stripe/stripe-php'],
      nuget: ['Stripe.net'],
    },
  },
  {
    id: 'datadog',
    name: 'Datadog',
    category: 'Observability',
    hostSuffixes: ['datadoghq.com', 'datadoghq.eu'],
    apiBase: 'https://api.datadoghq.com',
    defaultDataClasses: ['telemetry', 'logs', 'metrics'],
    sdks: {
      npm: ['dd-trace', '@datadog/browser-logs'],
      pypi: ['datadog', 'ddtrace'],
      go: ['github.com/DataDog/dd-trace-go'],
      maven: ['com.datadoghq'],
      rubygems: ['ddtrace', 'dogapi'],
      nuget: ['Datadog.Trace'],
    },
  },
  {
    id: 'newrelic',
    name: 'New Relic',
    category: 'Observability',
    hostSuffixes: ['newrelic.com', 'nr-data.net'],
    apiBase: 'https://api.newrelic.com',
    defaultDataClasses: ['telemetry', 'logs', 'metrics'],
    sdks: {
      npm: ['newrelic'],
      pypi: ['newrelic'],
      go: ['github.com/newrelic/go-agent'],
      maven: ['com.newrelic.agent.java'],
      rubygems: ['newrelic_rpm'],
      nuget: ['NewRelic.Agent'],
    },
  },
  {
    id: 'sentry',
    name: 'Sentry',
    category: 'Error tracking',
    hostSuffixes: ['sentry.io'],
    apiBase: 'https://sentry.io',
    defaultDataClasses: ['source', 'telemetry'],
    sdks: {
      npm: ['@sentry/node', '@sentry/react', '@sentry/nextjs'],
      pypi: ['sentry-sdk'],
      go: ['github.com/getsentry/sentry-go'],
      maven: ['io.sentry'],
      rubygems: ['sentry-ruby'],
      cargo: ['sentry'],
      composer: ['sentry/sentry'],
      nuget: ['Sentry'],
    },
  },
  {
    id: 'openai',
    name: 'OpenAI',
    category: 'LLM provider',
    hostSuffixes: ['openai.com'],
    apiBase: 'https://api.openai.com',
    defaultDataClasses: ['pii', 'source'],
    sdks: {
      npm: ['openai'],
      pypi: ['openai'],
      go: ['github.com/sashabaranov/go-openai'],
      maven: ['com.openai'],
      rubygems: ['ruby-openai'],
      cargo: ['async-openai'],
      composer: ['openai-php/client'],
      nuget: ['OpenAI'],
    },
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    category: 'LLM provider',
    hostSuffixes: ['anthropic.com'],
    apiBase: 'https://api.anthropic.com',
    defaultDataClasses: ['pii', 'source'],
    sdks: {
      npm: ['@anthropic-ai/sdk'],
      pypi: ['anthropic'],
      go: ['github.com/anthropics/anthropic-sdk-go'],
      nuget: ['Anthropic.SDK'],
    },
  },
  {
    id: 'aws',
    name: 'Amazon Web Services',
    category: 'Cloud platform',
    hostSuffixes: ['amazonaws.com'],
    apiBase: 'https://s3.amazonaws.com',
    defaultDataClasses: ['secrets', 'customer'],
    sdks: {
      npm: ['@aws-sdk/client-s3', 'aws-sdk'],
      pypi: ['boto3'],
      go: ['github.com/aws/aws-sdk-go', 'github.com/aws/aws-sdk-go-v2'],
      maven: ['com.amazonaws', 'software.amazon.awssdk'],
      rubygems: ['aws-sdk-s3'],
      cargo: ['aws-sdk-s3'],
      nuget: ['AWSSDK.S3'],
    },
  },
  {
    id: 'gcp',
    name: 'Google Cloud',
    category: 'Cloud platform',
    hostSuffixes: ['googleapis.com'],
    apiBase: 'https://storage.googleapis.com',
    defaultDataClasses: ['customer', 'logs'],
    sdks: {
      npm: ['@google-cloud/storage'],
      pypi: ['google-cloud-storage'],
      go: ['cloud.google.com/go'],
      maven: ['com.google.cloud'],
      rubygems: ['google-cloud-storage'],
      nuget: ['Google.Cloud.Storage.V1'],
    },
  },
  {
    id: 'azure',
    name: 'Microsoft Azure',
    category: 'Cloud platform',
    hostSuffixes: ['azure.com', 'windows.net'],
    apiBase: 'https://management.azure.com',
    defaultDataClasses: ['customer', 'logs'],
    sdks: {
      npm: ['@azure/storage-blob'],
      pypi: ['azure-storage-blob'],
      go: ['github.com/Azure/azure-sdk-for-go'],
      maven: ['com.azure'],
      rubygems: ['azure-storage-blob'],
      nuget: ['Azure.Storage.Blobs'],
    },
  },
  {
    id: 'slack',
    name: 'Slack',
    category: 'Notifications',
    hostSuffixes: ['slack.com'],
    apiBase: 'https://slack.com/api',
    defaultDataClasses: ['logs'],
    sdks: {
      npm: ['@slack/web-api'],
      pypi: ['slack-sdk'],
      go: ['github.com/slack-go/slack'],
      maven: ['com.slack.api'],
      rubygems: ['slack-ruby-client'],
      composer: ['slack-php/slack-api'],
      nuget: ['SlackNet'],
    },
  },
  {
    id: 'segment',
    name: 'Segment',
    category: 'Analytics',
    hostSuffixes: ['segment.io', 'segment.com'],
    apiBase: 'https://api.segment.io',
    defaultDataClasses: ['customer'],
    sdks: {
      npm: ['@segment/analytics-node', 'analytics-node'],
      pypi: ['segment-analytics-python'],
      go: ['github.com/segmentio/analytics-go'],
      maven: ['com.segment.analytics.java'],
      rubygems: ['analytics-ruby'],
      nuget: ['Analytics'],
    },
  },
  {
    id: 'twilio',
    name: 'Twilio',
    category: 'Communications',
    hostSuffixes: ['twilio.com'],
    apiBase: 'https://api.twilio.com',
    defaultDataClasses: ['pii', 'customer'],
    sdks: {
      npm: ['twilio'],
      pypi: ['twilio'],
      go: ['github.com/twilio/twilio-go'],
      maven: ['com.twilio.sdk'],
      rubygems: ['twilio-ruby'],
      composer: ['twilio/sdk'],
      nuget: ['Twilio'],
    },
  },
  {
    id: 'sendgrid',
    name: 'SendGrid',
    category: 'Email',
    hostSuffixes: ['sendgrid.com'],
    apiBase: 'https://api.sendgrid.com',
    defaultDataClasses: ['pii'],
    sdks: {
      npm: ['@sendgrid/mail'],
      pypi: ['sendgrid'],
      go: ['github.com/sendgrid/sendgrid-go'],
      maven: ['com.sendgrid'],
      rubygems: ['sendgrid-ruby'],
      composer: ['sendgrid/sendgrid'],
      nuget: ['SendGrid'],
    },
  },
  {
    id: 'mailgun',
    name: 'Mailgun',
    category: 'Email',
    hostSuffixes: ['mailgun.net'],
    apiBase: 'https://api.mailgun.net',
    defaultDataClasses: ['pii'],
    sdks: {
      npm: ['mailgun.js'],
      pypi: ['mailgun'],
      rubygems: ['mailgun-ruby'],
      composer: ['mailgun/mailgun-php'],
      nuget: ['Mailgun'],
    },
  },
  {
    id: 'mixpanel',
    name: 'Mixpanel',
    category: 'Analytics',
    hostSuffixes: ['mixpanel.com'],
    apiBase: 'https://api.mixpanel.com',
    defaultDataClasses: ['customer', 'telemetry'],
    sdks: {
      npm: ['mixpanel'],
      pypi: ['mixpanel'],
      rubygems: ['mixpanel-ruby'],
      nuget: ['Mixpanel'],
    },
  },
  {
    id: 'amplitude',
    name: 'Amplitude',
    category: 'Analytics',
    hostSuffixes: ['amplitude.com'],
    apiBase: 'https://api2.amplitude.com',
    defaultDataClasses: ['customer', 'telemetry'],
    sdks: {
      npm: ['@amplitude/analytics-node'],
      pypi: ['amplitude-analytics'],
      nuget: ['Amplitude'],
    },
  },
  {
    id: 'posthog',
    name: 'PostHog',
    category: 'Analytics',
    hostSuffixes: ['posthog.com'],
    apiBase: 'https://us.i.posthog.com',
    defaultDataClasses: ['customer', 'telemetry'],
    sdks: {
      npm: ['posthog-node', 'posthog-js'],
      pypi: ['posthog'],
      go: ['github.com/posthog/posthog-go'],
      rubygems: ['posthog-ruby'],
      composer: ['posthog/posthog-php'],
      nuget: ['PostHog'],
    },
  },
  {
    id: 'honeycomb',
    name: 'Honeycomb',
    category: 'Observability',
    hostSuffixes: ['honeycomb.io'],
    apiBase: 'https://api.honeycomb.io',
    defaultDataClasses: ['telemetry', 'metrics'],
    sdks: {
      npm: ['libhoney'],
      pypi: ['libhoney'],
      go: ['github.com/honeycombio/libhoney-go'],
      rubygems: ['libhoney'],
    },
  },
  {
    id: 'grafana',
    name: 'Grafana Cloud',
    category: 'Observability',
    hostSuffixes: ['grafana.net'],
    apiBase: 'https://grafana.net',
    defaultDataClasses: ['logs', 'metrics'],
    sdks: {
      npm: ['@grafana/faro-web-sdk'],
    },
  },
  {
    id: 'splunk',
    name: 'Splunk',
    category: 'Observability',
    hostSuffixes: ['splunkcloud.com', 'splunk.com'],
    apiBase: 'https://http-inputs.splunkcloud.com',
    defaultDataClasses: ['logs'],
    sdks: {
      npm: ['splunk-logging'],
      pypi: ['splunk-sdk'],
      maven: ['com.splunk'],
      nuget: ['Splunk.Logging.Common'],
    },
  },
  {
    id: 'pagerduty',
    name: 'PagerDuty',
    category: 'Incident response',
    hostSuffixes: ['pagerduty.com'],
    apiBase: 'https://api.pagerduty.com',
    defaultDataClasses: ['logs'],
    sdks: {
      npm: ['@pagerduty/pdjs'],
      pypi: ['pdpyras'],
      go: ['github.com/PagerDuty/go-pagerduty'],
      rubygems: ['pagerduty'],
    },
  },
  {
    id: 'github',
    name: 'GitHub',
    category: 'Developer platform',
    hostSuffixes: ['github.com', 'githubusercontent.com'],
    apiBase: 'https://api.github.com',
    defaultDataClasses: ['source'],
    sdks: {
      npm: ['@octokit/rest', 'octokit'],
      pypi: ['pygithub'],
      go: ['github.com/google/go-github'],
      maven: ['org.kohsuke.github-api'],
      rubygems: ['octokit'],
      cargo: ['octocrab'],
      composer: ['knplabs/github-api'],
      nuget: ['Octokit'],
    },
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    category: 'Developer platform',
    hostSuffixes: ['gitlab.com'],
    apiBase: 'https://gitlab.com/api',
    defaultDataClasses: ['source'],
    sdks: {
      npm: ['@gitbeaker/rest'],
      pypi: ['python-gitlab'],
      go: ['gitlab.com/gitlab-org/api/client-go'],
      rubygems: ['gitlab'],
      nuget: ['GitLabApiClient'],
    },
  },
  {
    id: 'auth0',
    name: 'Auth0',
    category: 'Identity',
    hostSuffixes: ['auth0.com'],
    apiBase: 'https://login.auth0.com',
    defaultDataClasses: ['pii'],
    sdks: {
      npm: ['auth0'],
      pypi: ['auth0-python'],
      go: ['github.com/auth0/go-auth0'],
      maven: ['com.auth0'],
      rubygems: ['auth0'],
      composer: ['auth0/auth0-php'],
      nuget: ['Auth0.ManagementApi'],
    },
  },
  {
    id: 'okta',
    name: 'Okta',
    category: 'Identity',
    hostSuffixes: ['okta.com', 'oktapreview.com'],
    apiBase: 'https://login.okta.com',
    defaultDataClasses: ['pii'],
    sdks: {
      npm: ['@okta/okta-sdk-nodejs'],
      pypi: ['okta'],
      go: ['github.com/okta/okta-sdk-golang'],
      maven: ['com.okta.sdk'],
      nuget: ['Okta.Sdk'],
    },
  },
  {
    id: 'clerk',
    name: 'Clerk',
    category: 'Identity',
    hostSuffixes: ['clerk.com', 'clerk.dev'],
    apiBase: 'https://api.clerk.com',
    defaultDataClasses: ['pii'],
    sdks: {
      npm: ['@clerk/backend', '@clerk/nextjs'],
      pypi: ['clerk-backend-api'],
      go: ['github.com/clerk/clerk-sdk-go'],
    },
  },
  {
    id: 'supabase',
    name: 'Supabase',
    category: 'Backend platform',
    hostSuffixes: ['supabase.co', 'supabase.com'],
    apiBase: 'https://api.supabase.com',
    defaultDataClasses: ['pii', 'customer'],
    sdks: {
      npm: ['@supabase/supabase-js'],
      pypi: ['supabase'],
      cargo: ['postgrest'],
    },
  },
  {
    id: 'firebase',
    name: 'Firebase',
    category: 'Backend platform',
    hostSuffixes: ['firebaseio.com', 'firebase.google.com'],
    apiBase: 'https://firebaseio.com',
    defaultDataClasses: ['customer'],
    sdks: {
      npm: ['firebase', 'firebase-admin'],
      pypi: ['firebase-admin'],
      go: ['firebase.google.com/go'],
      maven: ['com.google.firebase'],
    },
  },
  {
    id: 'mongodb-atlas',
    name: 'MongoDB Atlas',
    category: 'Database SaaS',
    hostSuffixes: ['mongodb.net', 'mongodb.com'],
    apiBase: 'https://cloud.mongodb.com',
    defaultDataClasses: ['customer'],
    sdks: {
      npm: ['mongodb'],
      pypi: ['pymongo'],
      go: ['go.mongodb.org/mongo-driver'],
      maven: ['org.mongodb'],
      rubygems: ['mongo'],
      cargo: ['mongodb'],
      nuget: ['MongoDB.Driver'],
    },
  },
  {
    id: 'planetscale',
    name: 'PlanetScale',
    category: 'Database SaaS',
    hostSuffixes: ['psdb.cloud', 'planetscale.com'],
    apiBase: 'https://api.planetscale.com',
    defaultDataClasses: ['customer'],
    sdks: {
      npm: ['@planetscale/database'],
      go: ['github.com/planetscale/planetscale-go'],
    },
  },
  {
    id: 'algolia',
    name: 'Algolia',
    category: 'Search SaaS',
    hostSuffixes: ['algolia.net', 'algolianet.com'],
    apiBase: 'https://algolia.net',
    defaultDataClasses: ['customer'],
    sdks: {
      npm: ['algoliasearch'],
      pypi: ['algoliasearch'],
      go: ['github.com/algolia/algoliasearch-client-go'],
      maven: ['com.algolia'],
      rubygems: ['algolia'],
      composer: ['algolia/algoliasearch-client-php'],
      nuget: ['Algolia.Search'],
    },
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    category: 'CDN / edge',
    hostSuffixes: ['cloudflare.com', 'workers.dev'],
    apiBase: 'https://api.cloudflare.com',
    defaultDataClasses: ['logs'],
    sdks: {
      npm: ['cloudflare'],
      pypi: ['cloudflare'],
      go: ['github.com/cloudflare/cloudflare-go'],
      nuget: ['CloudFlare.Client'],
    },
  },
  {
    id: 'huggingface',
    name: 'Hugging Face',
    category: 'LLM provider',
    hostSuffixes: ['huggingface.co'],
    apiBase: 'https://api-inference.huggingface.co',
    defaultDataClasses: ['source'],
    sdks: {
      npm: ['@huggingface/inference'],
      pypi: ['huggingface-hub', 'transformers'],
      rubygems: ['hugging-face'],
    },
  },
  {
    id: 'cohere',
    name: 'Cohere',
    category: 'LLM provider',
    hostSuffixes: ['cohere.com', 'cohere.ai'],
    apiBase: 'https://api.cohere.com',
    defaultDataClasses: ['pii', 'source'],
    sdks: {
      npm: ['cohere-ai'],
      pypi: ['cohere'],
      go: ['github.com/cohere-ai/cohere-go'],
    },
  },
  {
    id: 'mistral',
    name: 'Mistral AI',
    category: 'LLM provider',
    hostSuffixes: ['mistral.ai'],
    apiBase: 'https://api.mistral.ai',
    defaultDataClasses: ['pii', 'source'],
    sdks: {
      npm: ['@mistralai/mistralai'],
      pypi: ['mistralai'],
      go: ['github.com/gage-technologies/mistral-go'],
    },
  },
];

// The scanner's ledger key material: this changes whenever the registry data
// or the resolution rules change, forcing a one-time re-extraction.
export const EGRESS_VERSION_MATERIAL = `${EXTRACTOR_VERSION}\n${JSON.stringify(PROVIDER_REGISTRY)}`;

export interface HostResolution {
  kind: DestinationKind;
  trust: ShareTrustLevel;
  name: string;
  category: string;
  entry: ProviderRegistryEntry | null;
}

// TLDs — plus the single-label rule below — that mark a host as internal
// without any caller-supplied hint.
const INTERNAL_TLDS = ['internal', 'local', 'corp', 'lan', 'intranet', 'home.arpa'];

// Non-provider hosts excluded from resolution entirely: loopback/reserved
// name suffixes (RFC 2606/6761-style) and the schema/XML-namespace hosts that
// show up as URL-shaped literals in source but name no real destination.
const EXCLUDED_HOST_SUFFIXES = [
  'localhost',
  'test',
  'example',
  'invalid',
  'example.com',
  'example.org',
  'example.net',
  'w3.org',
  'schemas.openxmlformats.org',
  'schemas.microsoft.com',
  'schemas.android.com',
  'maven.apache.org',
];

// Exact match or dotted-suffix match — 'stripe.com' matches 'api.stripe.com'
// but never 'evilstripe.com' (no dot boundary).
function hostMatchesSuffix(host: string, suffix: string): boolean {
  return host === suffix || host.endsWith(`.${suffix}`);
}

/** True when `host` is a syntactically valid dotted-quad IPv4 literal. */
export function isValidIPv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

/**
 * True when a valid IPv4 literal falls in a private, loopback, link-local, or
 * reserved/multicast range (0.*, 10.*, 127.*, 169.254.*, 172.16-31.*,
 * 192.168.*, >=224.*). Callers must confirm `isValidIPv4` first.
 */
export function isPrivateOrReservedIPv4(host: string): boolean {
  const octets = host.split('.').map(Number);
  const a = octets[0];
  const b = octets[1];
  if (a === undefined || b === undefined) return false;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

// Strips the brackets a URL authority wraps an IPv6 literal in ('[::1]' ->
// '::1'), strips a zone index ('fe80::1%eth0' -> 'fe80::1' — RFC 4007 scopes
// the zone to a local interface name, so it carries no address-range
// information), and lowercases hex digits. Any other string is only
// lowercased.
function normalizeIPv6Literal(host: string): string {
  const unbracketed = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  const zoneIndex = unbracketed.indexOf('%');
  const unzoned = zoneIndex === -1 ? unbracketed : unbracketed.slice(0, zoneIndex);
  return unzoned.toLowerCase();
}

const IPV6_HEX_GROUP = /^[0-9a-f]{1,4}$/;

/**
 * True when `host` — optionally bracketed (e.g. '[::1]'), optionally
 * zone-indexed (e.g. 'fe80::1%eth0'), and case-insensitive — is a
 * syntactically valid IPv6 literal: colon-separated hex groups, with at most
 * one '::' run standing in for one or more omitted all-zero groups,
 * resolving to exactly 8 groups.
 */
export function isValidIPv6(host: string): boolean {
  const h = normalizeIPv6Literal(host);
  if (!h.includes(':')) return false;

  const collapsedHalves = h.split('::');
  if (collapsedHalves.length > 2) return false;

  const sides = collapsedHalves.length === 2 ? collapsedHalves : [h];
  const groups = sides.flatMap((side) => (side === '' ? [] : side.split(':')));
  if (!groups.every((g) => IPV6_HEX_GROUP.test(g))) return false;

  return collapsedHalves.length === 2 ? groups.length <= 7 : groups.length === 8;
}

/**
 * True when a valid IPv6 literal (optionally bracketed, optionally
 * zone-indexed) falls in the unspecified (::), loopback (::1), unique-local
 * (fc00::/7), link-local (fe80::/10), or multicast (ff00::/8) range — the
 * IPv6 counterparts of the IPv4 ranges above. The leading group is zero-padded
 * to 4 digits before the range test, so an abbreviated group such as 'fc'
 * (address 00fc::, not fc00::) is not mistaken for membership. Callers must
 * confirm `isValidIPv6` first.
 */
export function isPrivateOrReservedIPv6(host: string): boolean {
  const h = normalizeIPv6Literal(host);
  if (h === '::' || h === '::1') return true;
  const firstGroup = (h.split(':')[0] ?? '').padStart(4, '0');
  if (firstGroup.startsWith('fc') || firstGroup.startsWith('fd')) return true;
  if (firstGroup.startsWith('fe') && '89ab'.includes(firstGroup[2] ?? '')) return true;
  if (firstGroup.startsWith('ff')) return true;
  return false;
}

const IPV4_MAPPED_IPV6 = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;

// Extracts the embedded dotted-quad from an IPv4-mapped IPv6 literal
// ('::ffff:127.0.0.1' -> '127.0.0.1', optionally bracketed/zone-indexed);
// null for any other string. The caller still validates the extracted
// address with `isValidIPv4` — a syntax match here does not imply the
// embedded octets are in range.
function ipv4MappedAddress(host: string): string | null {
  const match = IPV4_MAPPED_IPV6.exec(normalizeIPv6Literal(host));
  return match?.[1] ?? null;
}

/**
 * Classify one host: registry match → provider/recognized; a public IPv4 or
 * IPv6 literal (including an IPv4-mapped IPv6 literal, e.g. '::ffff:8.8.8.8')
 * → ip/ip; an internal signal (a single-label host with no colon, an
 * internal TLD, or a caller-supplied internalDomain) → internal/internal;
 * anything else public → external/unverified. Excluded hosts
 * (loopback/private/reserved, schema-identifier hosts) resolve to `null`. A
 * host containing ':' never qualifies for the single-label internal rule, so
 * an IPv6-shaped literal that fails every literal check above still resolves
 * external/unverified — never the trusted-internal fallback.
 */
export function resolveHost(
  host: string,
  opts?: { internalDomains?: string[] },
): HostResolution | null {
  const h = host.toLowerCase();

  if (isValidIPv4(h)) {
    if (isPrivateOrReservedIPv4(h)) return null;
    return { kind: 'ip', trust: 'ip', name: h, category: 'Unresolved host', entry: null };
  }

  if (isValidIPv6(h)) {
    if (isPrivateOrReservedIPv6(h)) return null;
    return { kind: 'ip', trust: 'ip', name: h, category: 'Unresolved host', entry: null };
  }

  const mappedIPv4 = ipv4MappedAddress(h);
  if (mappedIPv4 !== null && isValidIPv4(mappedIPv4)) {
    if (isPrivateOrReservedIPv4(mappedIPv4)) return null;
    return { kind: 'ip', trust: 'ip', name: h, category: 'Unresolved host', entry: null };
  }

  if (EXCLUDED_HOST_SUFFIXES.some((suffix) => hostMatchesSuffix(h, suffix))) return null;

  const entry = PROVIDER_REGISTRY.find((p) =>
    p.hostSuffixes.some((suffix) => hostMatchesSuffix(h, suffix)),
  );
  if (entry) {
    return {
      kind: 'provider',
      trust: 'recognized',
      name: entry.name,
      category: entry.category,
      entry,
    };
  }

  const internalDomains = opts?.internalDomains ?? [];
  const isInternal =
    (!h.includes('.') && !h.includes(':')) ||
    INTERNAL_TLDS.some((tld) => hostMatchesSuffix(h, tld)) ||
    internalDomains.some((domain) => hostMatchesSuffix(h, domain.toLowerCase()));
  if (isInternal) {
    return {
      kind: 'internal',
      trust: 'internal',
      name: h,
      category: 'Internal services',
      entry: null,
    };
  }

  return {
    kind: 'external',
    trust: 'unverified',
    name: h,
    category: 'External domain',
    entry: null,
  };
}

/**
 * Match one manifest dependency identifier against the registry for a single
 * ecosystem. Matching rule per ecosystem: exact for npm/rubygems/cargo/
 * composer; case-insensitive exact for nuget; PEP-503 normalized for pypi;
 * path-prefix ('/' boundary) for go; group-id prefix ('.' boundary) for maven.
 */
export function resolveSdk(ecosystem: EgressEcosystem, pkg: string): ProviderRegistryEntry | null {
  for (const entry of PROVIDER_REGISTRY) {
    const idents = entry.sdks[ecosystem];
    if (idents === undefined) continue;
    if (idents.some((ident) => sdkMatches(ecosystem, pkg, ident))) return entry;
  }
  return null;
}

function sdkMatches(ecosystem: EgressEcosystem, pkg: string, ident: string): boolean {
  switch (ecosystem) {
    case 'nuget':
      return pkg.toLowerCase() === ident.toLowerCase();
    case 'pypi':
      return normalizePypi(pkg) === normalizePypi(ident);
    case 'go':
      return pkg === ident || pkg.startsWith(`${ident}/`);
    case 'maven':
      return pkg === ident || pkg.startsWith(`${ident}.`);
    default:
      return pkg === ident;
  }
}

// PEP-503 normalization: lowercase, collapse runs of -._ to a single '-'.
function normalizePypi(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}
