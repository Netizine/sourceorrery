import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);

function withoutMdxImports(markdown) {
	let fence;
	let inImport = false;
	return markdown.split('\n').filter((line) => {
		const marker = line.match(/^\s*(`{3,}|~{3,})/);
		if (marker) {
			if (!fence) fence = marker[1];
			else if (marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = undefined;
			return true;
		}
		if (fence) return true;
		if (inImport || /^import\s*(?:['"{*]|[A-Za-z_$][\w$]*(?:\s*,|\s+from\b))/.test(line)) {
			inImport = !/(?:from\s+|^import\s*)['"][^'"]+['"];?\s*$/.test(line);
			return false;
		}
		return true;
	}).join('\n');
}

/** An estimate of time to read the prose and examples, not time to complete a tutorial. */
export function readingTimeMinutes(markdown = '') {
	const body = markdown.replace(/^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/, '');
	const text = withoutMdxImports(body)
		.replace(/<!--[^]*?-->|\{\/\*[^]*?\*\/\}/g, ' ')
		.replace(/<\/?[A-Za-z][^>]*>/g, ' ')
		.replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/^\s*\[[^\]]+\]:\s*\S+.*$/gm, '')
		.replace(/^[ \t]*(?:`{3,}|~{3,}).*$/gm, '')
		.replace(/\[!(?:NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/g, '');
	const words = text.match(/[\p{L}\p{N}]+(?:['’.-][\p{L}\p{N}]+)*/gu)?.length ?? 0;
	return Math.max(1, Math.ceil(words / 200));
}

/** Use the committed source, never a copied page's filesystem timestamp. */
export async function gitModifiedTime(repositoryRoot, source, run = execute) {
	if (!source) return undefined;
	const relative = path.relative(repositoryRoot, path.resolve(repositoryRoot, source));
	if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) {
		return undefined;
	}
	try {
		const { stdout } = await run('git', ['log', '-1', '--format=%cI', '--', relative], {
			cwd: repositoryRoot,
			encoding: 'utf8',
			timeout: 5000,
			windowsHide: true,
		});
		const value = stdout.trim();
		if (!value) return undefined; // untracked source, source archive or missing history
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? undefined : date;
	} catch {
		// Source archives and machines without Git can still build the docs.
		// Omitting the date is more honest than displaying the build time.
		return undefined;
	}
}

export async function metadataForEntry(entry, siteRoot, lookup = gitModifiedTime) {
	const repositoryRoot = path.resolve(siteRoot, '..');
	const source = entry.data.sourceFile
		?? (entry.filePath ? path.relative(repositoryRoot, path.resolve(siteRoot, entry.filePath)) : undefined);
	return {
		readingTimeMinutes: readingTimeMinutes(entry.body),
		lastUpdated: (await lookup(repositoryRoot, source)) ?? false,
	};
}
