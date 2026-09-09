// The projection lives in @akasecurity/persistence so the CLI and the dashboard
// share the one implementation; this module keeps the import site the attached
// gateway and the barrel already use.
export { hashProjectKey, toEgressIngestRequest } from '@akasecurity/persistence';
