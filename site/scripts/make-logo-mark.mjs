// Derives the square emblem used in the site header and favicon from the
// full brand logo (src/assets/logo.png, a copy of the repository's logo.png).
// The full logo carries a dark-navy wordmark that disappears on the dark
// theme, so the header shows the emblem and renders the name as text.
//
//   node scripts/make-logo-mark.mjs
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(siteRoot, 'src', 'assets', 'logo.png');
const mark = path.join(siteRoot, 'src', 'assets', 'logo-mark.png');
const favicon = path.join(siteRoot, 'public', 'favicon.png');

// The emblem occupies the top two thirds of the logo; the wordmark sits
// below a transparent gap. Find the opaque bounding box of that region so
// the faint glow around the orrery does not inflate the crop.
const { data, info } = await sharp(source).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
const { width, height } = info;
const limit = Math.round(height * 0.66);
let minX = width, maxX = 0, minY = height, maxY = 0;
for (let y = 0; y < limit; y++) {
	for (let x = 0; x < width; x++) {
		if (data[(y * width + x) * 4 + 3] > 64) {
			if (x < minX) minX = x;
			if (x > maxX) maxX = x;
			if (y < minY) minY = y;
			if (y > maxY) maxY = y;
		}
	}
}

const margin = 24;
const box = {
	left: Math.max(0, minX - margin),
	top: Math.max(0, minY - margin),
	width: Math.min(width, maxX + margin) - Math.max(0, minX - margin),
	height: Math.min(height, maxY + margin) - Math.max(0, minY - margin),
};
const side = Math.max(box.width, box.height);
const pad = {
	top: Math.floor((side - box.height) / 2),
	bottom: Math.ceil((side - box.height) / 2),
	left: Math.floor((side - box.width) / 2),
	right: Math.ceil((side - box.width) / 2),
	background: { r: 0, g: 0, b: 0, alpha: 0 },
};

// sharp runs resize before extend whatever the call order, so each step is
// its own pass: crop, pad to a square, then scale.
const cropped = await sharp(source).extract(box).png().toBuffer();
const square = await sharp(cropped).extend(pad).png().toBuffer();
await sharp(square).resize(512, 512).png().toFile(mark);
await sharp(square).resize(128, 128).png().toFile(favicon);
console.log(`emblem box ${JSON.stringify(box)} -> ${path.relative(siteRoot, mark)}, ${path.relative(siteRoot, favicon)}`);
