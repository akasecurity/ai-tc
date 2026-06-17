// Pack-coordinate primitives. A detection-rule pack is addressed as
// `namespace/packId@version`, and `PublisherKind` records what kind of
// publisher a pack ships under (used by the detections library UI).
import { z } from 'zod';

// Publisher handle, e.g. 'aka'. Kebab-case, globally unique.
export const Namespace = z.string().regex(/^[a-z][a-z0-9-]*$/);
export type Namespace = z.infer<typeof Namespace>;

// Pack identifier within a namespace, e.g. 'secrets', 'core-pii'.
export const PackId = z.string().regex(/^[a-z][a-z0-9-]*$/);
export type PackId = z.infer<typeof PackId>;

// Simplified semver (major.minor.patch with optional prerelease).
export const SemVer = z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z-.]+)?$/);
export type SemVer = z.infer<typeof SemVer>;

export const PublisherKind = z.enum(['labs', 'user', 'org']);
export type PublisherKind = z.infer<typeof PublisherKind>;
