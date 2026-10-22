import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { markdownToHtml, mdxToJs } from 'satteri';
import { githubAlerts, calloutIcons } from '../plugins/github-alerts.mjs';
import { externalLinks } from '../plugins/external-links.mjs';
import { gitModifiedTime, metadataForEntry, readingTimeMinutes } from '../src/lib/doc-metadata.mjs';
import { withDocMetadata } from '../src/lib/docs-loader.mjs';

const siteRoot = path.resolve(import.meta.dirname, '..');
const repoRoot = path.resolve(siteRoot, '..');

test('Git timestamps query the source path as an argument, preserving spaces and shell characters', async () => {
	const source = 'docs/example $(literal).md';
	let call;
	const date = await gitModifiedTime(repoRoot, source, async (...args) => {
		call = args;
		return { stdout: '2026-10-20T12:34:56+01:00\n' };
	});
	assert.equal(date.toISOString(), '2026-10-20T11:34:56.000Z');
	assert.equal(call[0], 'git');
	assert.deepEqual(call[1], ['log', '-1', '--format=%cI', '--', path.normalize(source)]);
	assert.equal(call[2].cwd, repoRoot);
	assert.equal(call[2].shell, undefined);
});

test('missing or invalid Git history never falls back to the build time', async () => {
	for (const run of [async () => ({ stdout: '' }), async () => ({ stdout: 'invalid' }), async () => { throw new Error('no Git'); }]) {
		assert.equal(await gitModifiedTime(repoRoot, 'docs/guide.md', run), undefined);
	}
	assert.equal(await gitModifiedTime(repoRoot, '../outside.md', async () => assert.fail('must not read outside repository')), undefined);
});

test('generated and authored documentation resolve their own sources', async () => {
	const calls = [];
	const lookup = async (root, source) => { calls.push([root, source]); return undefined; };
	const generated = await metadataForEntry({ data: { sourceFile: 'crates/sourceorrery-core/src/error.rs' }, filePath: 'src/content/docs/reference/error-codes.md', body: 'A short guide.' }, siteRoot, lookup);
	await metadataForEntry({ data: {}, filePath: 'src/content/docs/getting-started.mdx', body: '' }, siteRoot, lookup);
	assert.equal(calls[0][1], 'crates/sourceorrery-core/src/error.rs');
	assert.equal(calls[1][1], path.join('site', 'src', 'content', 'docs', 'getting-started.mdx'));
	assert.equal(generated.lastUpdated, false);
	assert.equal(generated.readingTimeMinutes, 1);
});

test('reading estimate ignores metadata and markup but includes readable examples', () => {
	const prose = 'word '.repeat(201);
	assert.equal(readingTimeMinutes(`---\ntitle: ${'metadata '.repeat(300)}\n---\nimport { Widget } from './component';\n<!-- ${'comment '.repeat(300)} -->\n<Widget class="${'class '.repeat(300)}">${prose}</Widget>`), 2);
	assert.equal(readingTimeMinutes('```bash\n' + 'command '.repeat(201) + '\n```'), 2);
	assert.equal(readingTimeMinutes('```python\nimport os\n' + 'word '.repeat(201) + '\n```\nA sentence;'), 2);
	assert.equal(readingTimeMinutes('~~~bash\nexport HOME=/tmp/example\n' + 'word '.repeat(201) + '\n~~~\nA sentence;'), 2);
	assert.equal(readingTimeMinutes(''), 1);
});

test('loader refreshes metadata when cached content is unchanged', async () => {
	const entries = new Map([['example', {
		id: 'example', filePath: 'src/content/docs/example.md', body: 'word '.repeat(401),
		data: { title: 'Example', sourceFile: 'untracked-source.md', lastUpdated: new Date(0), readingTimeMinutes: 99 },
	}]]);
	let loaded = false;
	const loader = withDocMetadata({ name: 'fixture', async load() { loaded = true; } });
	await loader.load({
		config: { root: pathToFileURL(siteRoot + path.sep) },
		store: { entries: () => entries.entries(), set: (entry) => entries.set(entry.id, entry) },
	});
	assert.equal(loaded, true);
	assert.equal(entries.get('example').data.lastUpdated, false);
	assert.equal(entries.get('example').data.readingTimeMinutes, 3);
});

test('all GitHub alert variants retain inline formatting, links and multiple blocks', async () => {
	for (const [kind, variant] of Object.entries({ NOTE: 'note', TIP: 'tip', IMPORTANT: 'note', WARNING: 'caution', CAUTION: 'danger' })) {
		const source = `> [!${kind}]\n> Keep **values** out of [logs](/reference/cli/).\n>\n> - Check the \`manifest\`.\n> - Review permissions.`;
		const { html } = await markdownToHtml(source, { mdastPlugins: [githubAlerts()] });
		assert.match(html, new RegExp(`starlight-aside--${variant}`));
		assert.match(html, /<strong>values<\/strong>/);
		assert.match(html, /href="\/reference\/cli\/"/);
		assert.match(html, /<ul>/);
		assert.match(html, /<code>manifest<\/code>/);
		assert.match(html, /<svg[^>]+class="so-fa-icon starlight-aside__icon"/);
		assert.match(html, /<path[^>]+d="[^"]+"/);
		assert.match(html, /class="fa-secondary"/);
		assert.match(html, /class="fa-primary"/);
		assert.doesNotMatch(html, /<i(?:\s|>)|kit\.fontawesome\.com/);
		assert.doesNotMatch(html, /\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/);
	}
});

test('ordinary blockquotes and fenced alert examples are left intact; MDX alerts compile', async () => {
	const { html } = await markdownToHtml('> Ordinary quotation.\n\n```md\n> [!NOTE]\n> Example.\n```', { mdastPlugins: [githubAlerts()] });
	assert.match(html, /<blockquote>/);
	assert.doesNotMatch(html, /<aside/);
	assert.match(html, /\[!NOTE\]/);
	const { code } = await mdxToJs('> [!WARNING]\n> Never print the value.', { mdastPlugins: [githubAlerts()] });
	assert.match(code, /starlight-aside--caution/);
	assert.match(code, /Never print the value/);
	assert.match(code, /fa-secondary/);
	assert.match(code, /triangle-exclamation/);
});

test('external links get an accessible cue and retain existing rel tokens', async () => {
	const plugin = externalLinks({ site: 'https://sourceorrery.ai' });
	const { html } = await markdownToHtml('[External](https://example.com) [Same](https://sourceorrery.ai/sdks/) [Local](/sdks/) [Mail](mailto:test@example.com) [Network](//example.com/docs)\n\n<a href="https://example.net" rel="nofollow" aria-label="Registry">Package</a>', {
		features: { rawHtml: true }, hastPlugins: [plugin, plugin],
	});
	assert.equal((html.match(/so-external-icon/g) ?? []).length, 3);
	assert.equal((html.match(/target="_blank"/g) ?? []).length, 3);
	assert.equal((html.match(/<svg/g) ?? []).length, 3);
	assert.equal((html.match(/<path/g) ?? []).length, 6);
	assert.doesNotMatch(html, /<i(?:\s|>)|kit\.fontawesome\.com/);
	assert.match(html, /rel="nofollow noopener noreferrer"/);
	assert.match(html, /aria-label="Registry \(opens in a new tab\)"/);
	assert.match(html, /<a href="mailto:test@example.com">Mail<\/a>/);
	assert.match(html, /<a href="https:\/\/sourceorrery.ai\/sdks\/">Same<\/a>/);
});

test('MDX Markdown links and explicit anchor elements get external-link treatment', async () => {
	const { code } = await mdxToJs('[External](https://example.com)\n\n<a href="https://example.org" rel="nofollow">Registry</a>', { hastPlugins: [externalLinks({ site: 'https://sourceorrery.ai' })] });
	assert.equal((code.match(/so-external-icon/g) ?? []).length, 2);
	assert.match(code, /nofollow noopener noreferrer/);
	assert.match(code, /opens in a new tab/);
	assert.match(code, /fa-secondary/);
	assert.match(code, /fa-primary/);
});

test('native Starlight aside icons use local Kit SVGs without changing an existing alert icon', async () => {
	const { html } = await markdownToHtml('<aside class="starlight-aside starlight-aside--tip"><p><svg class="starlight-aside__icon"><path d="M0 0" /></svg>Tip</p><p>Read on.</p></aside>', { features: { rawHtml: true }, hastPlugins: [calloutIcons()] });
	assert.match(html, /data-icon="lightbulb"/);
	assert.match(html, /class="fa-secondary"/);
	assert.doesNotMatch(html, /M0 0|<i(?:\s|>)/);
	const important = await markdownToHtml('> [!IMPORTANT]\n> Check this.', { mdastPlugins: [githubAlerts()], hastPlugins: [calloutIcons(), calloutIcons()] });
	assert.match(important.html, /data-icon="circle-exclamation"/);
	assert.equal((important.html.match(/<svg/g) ?? []).length, 1);
});
