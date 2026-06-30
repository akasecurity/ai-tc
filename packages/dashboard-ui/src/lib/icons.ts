import type { FunctionComponent, SVGProps } from 'react';

// An icon is any component that renders an <svg> and forwards SVG props. The
// dashboard apps load their icon sets via their own bundler (Vite svgr, Next svgr,
// …); @akasecurity/dashboard-ui stays bundler-agnostic by typing icons structurally and
// taking them as props (e.g. StatTile) rather than importing concrete SVG assets.
export type IconComponent = FunctionComponent<SVGProps<SVGSVGElement>>;
