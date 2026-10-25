// Clean-text companions are built from the same pre-MDX sources as the site.
// No network access, rendered HTML scraping or additional dependencies.
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { llmsPath } from '../src/lib/llms-path.mjs';

export const SITE = 'https://sourceorrery.ai';

/** The lines of `text`, each with its newline; a last line without one is kept. */
function linesOf(text) {
	const lines = text.split('\n').map((line, i, all) => (i < all.length - 1 ? `${line}\n` : line));
	if (lines.at(-1) === '') lines.pop();
	return lines;
}

/** Apply a prose transform while preserving backtick/tilde code fences verbatim. */
export function transformProse(markdown, transform) {
	const output = [];
	let prose = [];
	let fence;
	const flush = () => { output.push(transform(prose.join(''))); prose = []; };
	for (const line of linesOf(markdown)) {
		const opening = line.match(/^ {0,3}(`{3,}|~{3,})/);
		if (fence) {
			output.push(line);
			if (new RegExp(`^ {0,3}${fence[0]}{${fence.length},}\\s*$`).test(line)) fence = undefined;
		} else if (opening) {
			flush();
			fence = opening[1];
			output.push(line);
		} else prose.push(line);
	}
	flush();
	return output.join('');
}

/** Sources already have site links rewritten by sync-docs; make them portable. */
export function cleanMarkdown(markdown, canonical) {
	return transformProse(markdown.replace(/\r\n/g, '\n'), (prose) => {
		const absolute = (href) => href.startsWith('/') || href.startsWith('#')
			? new URL(href, canonical).href : href;
		return prose.replace(/<!--[\s\S]*?-->/g, '')
			.replace(/(!?\[[^[\]\n]*\]\()([^\s)]+)(\))/g, (_, before, href, after) => `${before}${absolute(href)}${after}`)
			.replace(/^(\[[^\]\n]+\]:\s*)(\S+)/gm, (_, before, href) => `${before}${absolute(href)}`);
	}).trim() + '\n';
}

/** Only actual Markdown links outside fenced examples participate in the index. */
export function markdownLinks(markdown) {
	const links = [];
	transformProse(markdown, (prose) => {
		for (const match of prose.matchAll(/(?<!!)\[[^[\]\n]+\]\(([^\s)]+)\)/g)) links.push(match[1]);
		return prose;
	});
	return links;
}

export function buildLlmFiles({ index, overview, pages, release }) {
	const status = `Documentation version: ${release.version}${release.released ? '.' : ' (not released yet; package availability follows the installation guide).'}`;
	const files = new Map();
	const add = (file, content) => {
		if (files.has(file)) throw new Error(`Duplicate LLM documentation path: ${file}`);
		files.set(file, content);
	};
	const wrap = (markdown, canonical) => {
		const clean = cleanMarkdown(markdown, canonical);
		const heading = clean.indexOf('\n');
		if (!clean.startsWith('# ') || heading < 0) throw new Error(`Missing H1: ${canonical}`);
		return `${clean.slice(0, heading)}\n\n${status}\n\n${clean.slice(heading + 1).trim()}\n`;
	};
	add('llms/overview.md', wrap(overview, `${SITE}/llms/overview.md`));
	for (const { href, markdown } of pages) add(llmsPath(href).slice(1), wrap(markdown, SITE + href));
	const cleanIndex = cleanMarkdown(index, `${SITE}/llms.txt`);
	if (!/^# [^\n]+\n\n> [^\n]+/.test(cleanIndex)) throw new Error('LLM index needs an H1 followed by a summary blockquote');
	const sections = cleanIndex.indexOf('\n## ');
	if (sections < 0) throw new Error('LLM index needs file-list sections');
	add('llms.txt', `${cleanIndex.slice(0, sections).trimEnd()}\n\n${status}\n${cleanIndex.slice(sections)}`);
	const essential = index.split(/^## Optional\s*$/m)[0];
	const combined = [`# SourceOrrery documentation\n\n${status}\n\nGenerated from the current website documentation. [Concise index](${SITE}/llms.txt).\n`];
	const included = new Set();
	for (const href of markdownLinks(essential)) {
		const url = new URL(href);
		if (url.origin !== SITE || !url.pathname.startsWith('/llms/')) continue;
		const file = url.pathname.slice(1);
		if (!files.has(file)) throw new Error(`LLM index links to missing Markdown: ${href}`);
		if (included.has(file)) continue;
		included.add(file);
		combined.push(`\n---\n\nSource: ${href}\n\n${files.get(file)}`);
	}
	if (!included.size) throw new Error('LLM index has no essential Markdown references');
	add('llms-full.txt', combined.join(''));
	return files;
}

export async function writeLlmFiles(publicDir, files) {
	// This directory is reserved for generated text. Renamed/removed references
	// disappear on the next sync; unrelated public assets are never removed.
	for (const file of files.keys()) {
		if (!/^(?:llms(?:-full)?\.txt|llms\/(?:[a-z0-9-]+\/)*[a-z0-9-]+\.md)$/.test(file)) {
			throw new Error(`Invalid generated LLM path: ${file}`);
		}
	}
	await rm(path.join(publicDir, 'llms'), { recursive: true, force: true });
	for (const [file, content] of files) {
		const destination = path.join(publicDir, file);
		await mkdir(path.dirname(destination), { recursive: true });
		await writeFile(destination, content, 'utf8');
	}
}
