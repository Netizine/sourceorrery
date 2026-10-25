// Verifies that every internal link and asset reference in the built site
// resolves to a file in dist/, including `#fragment` targets. Runs after
// `astro build` (see package.json) and fails the build on the first broken
// link, so a renamed page or heading in docs/ cannot ship silently.
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { markdownLinks, SITE } from './llms-docs.mjs';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(siteRoot, 'dist');

async function* htmlFiles(dir) {
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) yield* htmlFiles(full);
		else if (entry.name.endsWith('.html')) yield full;
	}
}

async function exists(file) {
	try {
		return (await stat(file)).isFile();
	} catch {
		return false;
	}
}

/** Map a site pathname to the file Astro wrote for it, or null. */
async function resolvePathname(pathname) {
	const decoded = decodeURIComponent(pathname);
	const candidates = decoded.endsWith('/')
		? [path.join(dist, decoded, 'index.html')]
		: [path.join(dist, decoded), path.join(dist, `${decoded}.html`), path.join(dist, decoded, 'index.html')];
	for (const candidate of candidates) {
		if (await exists(candidate)) return candidate;
	}
	return null;
}

const idCache = new Map();
async function hasFragment(file, fragment) {
	if (!idCache.has(file)) {
		const html = await readFile(file, 'utf8');
		const ids = new Set();
		for (const match of html.matchAll(/\s(?:id|name)="([^"]+)"/g)) ids.add(match[1]);
		idCache.set(file, ids);
	}
	return idCache.get(file).has(decodeURIComponent(fragment));
}

const problems = [];
let checked = 0;

try {
	await stat(dist);
} catch {
	console.error(`check-links: ${dist} does not exist; run 'astro build' first`);
	process.exit(1);
}

for await (const file of htmlFiles(dist)) {
	const page = `/${path.relative(dist, file).split(path.sep).join('/')}`.replace(/index\.html$/, '');
	const html = await readFile(file, 'utf8');
	for (const match of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
		const raw = match[1];
		if (!raw) continue;
		// Browsers ignore leading whitespace and compare schemes case-insensitively.
		const scheme = raw.trim().match(/^([a-z][a-z0-9+.-]*):/i)?.[1].toLowerCase();
		if (scheme === 'javascript' || scheme === 'vbscript') {
			problems.push(`${page} -> ${raw}: a ${scheme}: URL runs script; the site must not contain one`);
			continue;
		}
		if (scheme || raw.startsWith('//')) continue; // external, data: or another scheme
		const url = new URL(raw, `https://sourceorrery.ai${page}`);
		checked += 1;
		const target = await resolvePathname(url.pathname);
		if (!target) {
			problems.push(`${page} -> ${raw}: no file for ${url.pathname}`);
			continue;
		}
		if (url.hash && url.hash !== '#' && !(await hasFragment(target, url.hash.slice(1)))) {
			problems.push(`${page} -> ${raw}: no element with id "${url.hash.slice(1)}"`);
		}
	}
}

// The LLM index and text references are build outputs too. Check their
// same-site absolute links, including HTML fragments, without fetching URLs.
async function* markdownFiles(dir) {
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) yield* markdownFiles(full);
		else if (entry.name.endsWith('.md')) yield full;
	}
}
const textFiles = [path.join(dist, 'llms.txt'), path.join(dist, 'llms-full.txt')];
for await (const file of markdownFiles(path.join(dist, 'llms'))) textFiles.push(file);
for (const file of textFiles) {
	const page = `/${path.relative(dist, file).split(path.sep).join('/')}`;
	for (const href of markdownLinks(await readFile(file, 'utf8'))) {
		const url = new URL(href, SITE + page);
		if (url.origin !== SITE) continue;
		checked += 1;
		const target = await resolvePathname(url.pathname);
		if (!target) problems.push(`${page} -> ${href}: no file for ${url.pathname}`);
		else if (url.hash && !(await hasFragment(target, url.hash.slice(1)))) {
			problems.push(`${page} -> ${href}: no element with id "${url.hash.slice(1)}"`);
		}
	}
}

if (problems.length) {
	console.error(`check-links: ${problems.length} broken internal link(s) after checking ${checked}:`);
	for (const problem of problems) console.error(`  ${problem}`);
	process.exit(1);
}
console.log(`check-links: ${checked} internal references OK`);
