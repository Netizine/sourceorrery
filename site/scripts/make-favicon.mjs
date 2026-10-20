// Rasterises public/favicon.svg into public/favicon.png, the fallback for
// browsers that do not load SVG favicons (Safari, at the time of writing).
//
// The SVG moves its planets along their orbits with SMIL animation and keeps
// a parked copy of each one for `prefers-reduced-motion`. A static renderer
// ignores the animation and would draw the moving planets at the origin, so
// the script switches the SVG to its reduced-motion layout before rendering.
//
//   node scripts/make-favicon.mjs
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(siteRoot, 'public', 'favicon.svg');
const target = path.join(siteRoot, 'public', 'favicon.png');
const size = 128;

const svg = await readFile(source, 'utf8');
if (!svg.includes('</style>')) throw new Error(`${source}: expected a <style> block to extend`);
const still = svg.replace('</style>', '.moving { display: none; } .resting { display: inline; }</style>');

await sharp(Buffer.from(still)).resize(size, size).png().toFile(target);
console.log(`${path.relative(siteRoot, source)} -> ${path.relative(siteRoot, target)} (${size}x${size})`);
