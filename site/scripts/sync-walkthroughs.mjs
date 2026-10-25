// Copies the screens the docs' walkthroughs show from the CLI's design
// snapshots into public/walkthrough/<look>/<state>.html, and records each
// screen's size in src/lib/walkthrough-sizes.json for the Walkthrough
// component. Run it after regenerating the snapshots:
//
//   cargo test -p sourceorrery-cli ui::snapshot -- --ignored
//   npm run walkthroughs
//
// The snapshots are drawn as a made-up person (alex); this script refuses a
// page that names anyone or anything else of the machine that drew it (its
// user, its host, a temporary folder, another home directory), since what it
// writes is published.

import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { looks, walkthroughs } from '../src/lib/walkthroughs.mjs';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(siteRoot, '..');
const source = process.env.SOURCEORRERY_UI_SNAPSHOTS ?? path.join(repoRoot, 'target', 'ui-snapshots');
const outDir = path.join(siteRoot, 'public', 'walkthrough');
const sizesFile = path.join(siteRoot, 'src', 'lib', 'walkthrough-sizes.json');

const PERSON = 'alex';

function escapeRegExp(text) {
	return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** What a published page must never contain, with the reason. */
function forbidden() {
	const rules = [
		[/\.tmp[A-Za-z0-9]{6}/, 'a temporary folder'],
		[/AppData[\\/]Local[\\/]Temp/i, 'a temporary folder'],
		[/(^|[\s'"(])\/tmp\//, 'a temporary folder'],
		// The person's own home is allowed, cut short or not.
		[new RegExp(`[A-Za-z]:\\\\Users\\\\(?!${PERSON}\\b)`, 'i'), 'another Windows home'],
		[new RegExp(`/(home|Users)/(?!${PERSON}\\b)[\\w.-]+`), 'another home directory'],
	];
	const user = os.userInfo().username;
	if (user && user.length >= 3 && user.toLowerCase() !== PERSON) {
		rules.push([new RegExp(escapeRegExp(user), 'i'), `this machine's user (${user})`]);
		// Windows also shows the 8.3 short form of a long user name.
		if (user.length > 8) {
			rules.push([new RegExp(`${escapeRegExp(user.slice(0, 6))}~\\d`, 'i'), "this machine's user (short name)"]);
		}
	}
	const host = os.hostname();
	if (host && host.length >= 3) rules.push([new RegExp(`\\b${escapeRegExp(host)}\\b`, 'i'), "this machine's name"]);
	return rules;
}

/**
 * The text a reader sees: tags out, entities back. One pass over the page
 * (a tag runs from `<` to the next `>`), with no regular expression to
 * backtrack; an unclosed `<` keeps what follows it, so the checks still see
 * that text.
 */
function visibleText(html) {
	let text = '';
	let tag = null;
	for (const ch of html) {
		if (tag === null) {
			if (ch === '<') tag = ch;
			else text += ch;
		} else {
			tag += ch;
			if (ch === '>') tag = null;
		}
	}
	if (tag !== null) text += tag;
	return text
		.replace(/&lt;/g, '<')
		.replace(/&gt;/g, '>')
		.replace(/&amp;/g, '&');
}

/** The snapshot page, set up to be framed: no margin round the terminal, not indexed. */
function embeddable(html, title) {
	return html
		.replace(/<title>[^<]*<\/title>/, `<title>${title}</title><meta name="robots" content="noindex">`)
		.replace(/body \{ margin: 0; padding: 24px;/, 'body { margin: 0; padding: 0;')
		.replace(/pre \{ margin: 0 0 8px;/, 'pre { margin: 0;');
}

/** Rows and columns of the terminal the page draws. */
function size(html) {
	const pre = html.match(/<pre style="[^"]*width:(\d+)ch"[^>]*>([\s\S]*?)<\/pre>/);
	if (!pre) throw new Error('no terminal <pre> in the page');
	const rows = pre[2].replace(/\n$/, '').split('\n').length;
	return { cols: Number(pre[1]), rows };
}

const rules = forbidden();
const sizes = {};
const problems = [];
let written = 0;
for (const look of looks) {
	const dir = path.join(outDir, look);
	await rm(dir, { recursive: true, force: true });
	await mkdir(dir, { recursive: true });
}
for (const [name, walkthrough] of Object.entries(walkthroughs)) {
	for (const slide of walkthrough.slides) {
		for (const look of looks) {
			const file = path.join(source, `${look}-${slide.state}.html`);
			let html;
			try {
				html = await readFile(file, 'utf8');
			} catch {
				problems.push(`${name}: no snapshot ${path.relative(repoRoot, file)}`);
				continue;
			}
			// What a reader sees, and the page as written: a name in a tag's
			// attribute is published too.
			const text = visibleText(html);
			for (const [rule, what] of rules) {
				if (rule.test(text) || rule.test(html)) problems.push(`${look}-${slide.state}: shows ${what}`);
			}
			const measured = size(html);
			const known = sizes[slide.state];
			if (known && (known.rows !== measured.rows || known.cols !== measured.cols)) {
				problems.push(`${slide.state}: the dark and light screens differ in size`);
			}
			sizes[slide.state] = measured;
			await writeFile(
				path.join(outDir, look, `${slide.state}.html`),
				embeddable(html, `${walkthrough.command} · ${slide.title}`)
			);
			written += 1;
		}
	}
}
if (problems.length > 0) {
	await rm(outDir, { recursive: true, force: true });
	console.error(`sync-walkthroughs: nothing published:\n  ${problems.join('\n  ')}`);
	process.exit(1);
}
await writeFile(sizesFile, `${JSON.stringify(sizes, null, '\t')}\n`);
const slides = Object.values(walkthroughs).reduce((n, w) => n + w.slides.length, 0);
console.log(`sync-walkthroughs: ${written} pages for ${slides} slides under public/walkthrough`);
// Anything else in public/walkthrough is left from an earlier list.
const stray = (await readdir(outDir)).filter((entry) => !looks.includes(entry));
if (stray.length > 0) console.warn(`sync-walkthroughs: not ours, left alone: ${stray.join(', ')}`);
