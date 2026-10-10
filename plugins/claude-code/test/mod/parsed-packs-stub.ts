// @ts-expect-error build/engine.mjs is plain JavaScript
import { parseBundledPacks } from '../../build/engine.mjs';

const parse = parseBundledPacks as unknown as () => Promise<string>;

export const PARSED_DATA: unknown = JSON.parse(await parse());
