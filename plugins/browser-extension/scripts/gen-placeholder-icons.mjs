#!/usr/bin/env node
// Generates placeholder solid-color PNG icons (manifest.json references
// icons/icon{16,48,128}.png) so `pnpm build` + "Load unpacked" work without
// needing real artwork yet. Hand-rolled PNG encoding (IHDR/IDAT/IEND +
// zlib.crc32) rather than a new image-library dependency for three flat
// squares. Replace with real art before any public release — run this again
// only if the placeholder needs to change size/color in the meantime.
import { deflateSync, crc32 } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const iconsDir = join(root, 'icons');
mkdirSync(iconsDir, { recursive: true });

const COLOR = [0x25, 0x63, 0xeb]; // #2563eb, matches content.ts's "warn" banner tone

function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(body) >>> 0, 0);
  return Buffer.concat([len, body, crcBuf]);
}

function solidSquarePng(size, [r, g, b]) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); // width
  ihdr.writeUInt32BE(size, 4); // height
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type: RGB
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const stride = size * 3;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    const rowStart = y * (stride + 1);
    raw[rowStart] = 0; // filter type: none
    for (let x = 0; x < size; x++) {
      const p = rowStart + 1 + x * 3;
      raw[p] = r;
      raw[p + 1] = g;
      raw[p + 2] = b;
    }
  }

  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

for (const size of [16, 48, 128]) {
  const path = join(iconsDir, `icon${String(size)}.png`);
  writeFileSync(path, solidSquarePng(size, COLOR));
  process.stdout.write(`wrote ${path}\n`);
}
