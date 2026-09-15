import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { DeploymentMetaItem } from '../../src/findings/DeploymentMetaItem.tsx';

const RENDERED_AT = Date.parse('2026-09-14T12:00:00.000Z');

describe('DeploymentMetaItem', () => {
  it('labels the state, explains it, and says which detection it describes', () => {
    const html = renderToStaticMarkup(
      <DeploymentMetaItem
        delivery={{ state: 'queued' }}
        deployment={{ canRetry: false }}
        renderedAt={RENDERED_AT}
      />,
    );
    expect(html).toContain('>Deployment<');
    expect(html).toContain('>Queued<');
    expect(html).toContain('Settings → Sync');
    expect(html).toContain('Based on its latest detection.');
  });

  it('spans both columns of the drawer’s field grid', () => {
    const html = renderToStaticMarkup(
      <DeploymentMetaItem
        delivery={{ state: 'local_scan' }}
        deployment={{ canRetry: true }}
        renderedAt={RENDERED_AT}
      />,
    );
    expect(html).toMatch(/^<div class="col-span-2">/);
    expect(html).toContain('>Local scan<');
  });
});
