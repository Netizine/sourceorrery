import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildLlmFiles, cleanMarkdown, markdownLinks, SITE, writeLlmFiles } from './llms-docs.mjs';
import { llmsPath } from '../src/lib/llms-path.mjs';

const fixture = () => ({
	index: `# SourceOrrery\n\n> Project summary.\n\n## Guides\n\n- [CLI](${SITE}/llms/reference/cli/index.md)\n- [Overview](${SITE}/llms/overview.md)\n- [CLI again](${SITE}/llms/reference/cli/index.md)\n\n## Optional\n\n- [History](${SITE}/llms/history/index.md)\n`,
	overview: '# Overview\n\nProvision with the CLI; SDKs only read.\n',
	pages: [
		{ href: '/reference/cli/', markdown: '# CLI\n\nKeep values private. [Install](/getting-started/#install).\n' },
		{ href: '/history/', markdown: '# History\n\nOlder design.\n' },
	],
	release: { version: '0.3.0', released: false },
});

test('clean text removes presentation comments, keeps all tab content and makes links portable', () => {
	const source = '# Unicode λ\r\n\r\n<!-- tabs: os -->\r\n### Windows\r\nOne.\r\n### macOS\r\nTwo.\r\n<!-- /tabs -->\r\n<!-- walkthrough: setup -->\r\n<!-- multi\r\nline -->\r\n[CLI](/reference/cli/) [Here](#unicode)\r\n[ref]: /sdks/\r\n';
	const text = cleanMarkdown(source, `${SITE}/guides/test/`);
	assert.match(text, /# Unicode λ/);
	assert.match(text, /### Windows\nOne\.\n### macOS\nTwo\./);
	assert.doesNotMatch(text, /<!--|walkthrough|multi|\r/);
	assert.ok(text.includes(`[CLI](${SITE}/reference/cli/)`));
	assert.ok(text.includes(`[Here](${SITE}/guides/test/#unicode)`));
	assert.ok(text.includes(`[ref]: ${SITE}/sdks/`));
});

test('code, comments and links inside backtick and tilde fences are preserved verbatim', () => {
	for (const fence of ['```', '````', '~~~']) {
		const code = `${fence}xml\n<!-- keep this -->\n<PackageReference Version="0.3.0" />\n[example](/not-a-real-link/)\n\`\`\n${fence}\n`;
		const source = `[Before](/before/)\n\n${code}\n[After](#after)\n`;
		const text = cleanMarkdown(source, `${SITE}/guide/`);
		assert.ok(text.includes(code));
		assert.deepEqual(markdownLinks(text), [`${SITE}/before/`, `${SITE}/guide/#after`]);
	}
});

test('an unclosed fenced example stays code, including apparent links after it', () => {
	assert.deepEqual(markdownLinks('# Example\n\n```md\n[example](/missing/)\n'), []);
});

test('companion routes are deterministic and reject non-document paths', () => {
	assert.equal(llmsPath('/sdks/'), '/llms/sdks/index.md');
	assert.equal(llmsPath('/reference/error-codes/'), '/llms/reference/error-codes/index.md');
	for (const route of ['/../', '/reference//', '/file.md', 'relative/', '/foo/?x=1']) {
		assert.throws(() => llmsPath(route), /Invalid documentation route/);
	}
});

test('version and release status follow the workspace, with no fabricated release date', () => {
	for (const released of [false, true]) {
		const input = fixture();
		input.release = { version: '9.8.7', released };
		const files = buildLlmFiles(input);
		for (const text of files.values()) {
			assert.match(text, /Documentation version: 9\.8\.7/);
			assert.equal(text.includes('not released yet'), !released);
		}
	}
});

test('the index follows the llms.txt order: H1, summary, notes, then file-list sections', () => {
	const files = buildLlmFiles(fixture());
	const index = files.get('llms.txt');
	assert.match(index, /^# SourceOrrery\n\n> Project summary\.\n\nDocumentation version:/);
	assert.ok(index.indexOf('Documentation version:') < index.indexOf('## Guides'));
	const invalid = fixture();
	invalid.index = '# SourceOrrery\n\n## Guides\n';
	assert.throws(() => buildLlmFiles(invalid), /summary blockquote/);
});

test('the full file contains current essential sources once, keeping optional history separate', () => {
	const input = fixture();
	input.pages[0].markdown += '\nAn updated capability limit.\n';
	const files = buildLlmFiles(input);
	const full = files.get('llms-full.txt');
	assert.equal(full.match(/# CLI\n/g).length, 1);
	assert.match(full, /An updated capability limit/);
	assert.match(full, /Keep values private/);
	assert.match(full, /Provision with the CLI/);
	assert.doesNotMatch(full, /Older design/);
	assert.ok(files.get('llms/history/index.md').includes('Older design'));
	assert.deepEqual([...files], [...buildLlmFiles(input)]);
});

test('missing essential references and duplicate routes fail instead of publishing a partial corpus', () => {
	const input = fixture();
	input.pages.shift();
	assert.throws(() => buildLlmFiles(input), /missing Markdown/);
	const duplicate = fixture();
	duplicate.pages.push(duplicate.pages[0]);
	assert.throws(() => buildLlmFiles(duplicate), /Duplicate/);
});

test('regeneration removes stale generated references and preserves other public assets', async () => {
	const dir = await mkdtemp(path.join(os.tmpdir(), 'sourceorrery-llms-'));
	try {
		await mkdir(path.join(dir, 'llms'), { recursive: true });
		await writeFile(path.join(dir, 'llms/old.md'), 'stale');
		await writeFile(path.join(dir, 'favicon.svg'), 'unrelated asset');
		const files = buildLlmFiles(fixture());
		await writeLlmFiles(dir, files);
		await assert.rejects(readFile(path.join(dir, 'llms/old.md')), { code: 'ENOENT' });
		assert.equal(await readFile(path.join(dir, 'favicon.svg'), 'utf8'), 'unrelated asset');
		for (const [file, text] of files) assert.equal(await readFile(path.join(dir, file), 'utf8'), text);
		await assert.rejects(writeLlmFiles(dir, new Map([['../outside.md', 'invalid']])), /Invalid generated/);
		assert.equal(await readFile(path.join(dir, 'llms/overview.md'), 'utf8'), files.get('llms/overview.md'));
	} finally { await rm(dir, { recursive: true, force: true }); }
});
