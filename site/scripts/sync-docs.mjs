// Mirrors the repository's Markdown documentation into the Starlight content
// collection. `docs/` is the source of truth; everything this script writes
// is generated, gitignored and overwritten on every run (`npm run sync`,
// which also runs before `astro dev` and `astro build`).
//
// For each source page it:
//   - takes the title from the first H1 and removes that H1 from the body,
//   - derives a description from the first paragraph (or a configured one),
//   - rewrites relative links between docs to site URLs,
//   - turns `<!-- tabs -->` blocks into Starlight <Tabs> (see convertTabs).
//
// Pages carry no `editUrl`: the site has no "Edit page" link.
//
// It also generates two pages from other sources of truth:
//   - reference/error-codes from `SecretError::code` in sourceorrery-core,
//   - decisions/index listing the architecture decision records.
import { access, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(siteRoot, '..');
const outDir = path.join(siteRoot, 'src', 'content', 'docs');

const REPO_URL = 'https://github.com/Netizine/sourceorrery';
const BLOB_URL = `${REPO_URL}/blob/main/`;

/**
 * Pages copied from docs/. Keys are repository-relative source paths; `dest`
 * is relative to src/content/docs. Descriptions are optional overrides for
 * the one derived from the first paragraph.
 */
const PAGES = {
	'docs/architecture.md': {
		dest: 'architecture.md',
		description:
			'How SourceOrrery is put together: the Rust core that owns every semantic, the crypto wrappers, the encrypted SQLite vault, the CLI and the integration surface for other languages.',
	},
	'docs/threat-model.md': {
		dest: 'security/threat-model.md',
		description:
			'The three guarantees SourceOrrery keeps separate — at-rest protection, access control and agent isolation — with the adversaries, controls and known gaps of the CLI, the vault and the read-only SDKs.',
	},
	'docs/supply-chain.md': {
		dest: 'security/supply-chain.md',
		description:
			'How SourceOrrery is built and published: one release workflow, locked dependencies, trusted publishing and provenance, how to check what you installed, and what is not done yet.',
	},
	'docs/ai-agents.md': {
		dest: 'guides/ai-agents.md',
		description:
			'Skills that let Claude Code, Codex, Cursor, Copilot, Gemini CLI and seven other AI coding agents set up SourceOrrery and migrate a project off .env files without seeing a value.',
	},
	'docs/building.md': {
		dest: 'guides/building-from-source.md',
		description:
			'Build SourceOrrery from source: the tools to install on Windows, macOS and Linux, cloning, the CLI and the C ABI, the SDK test vault, each SDK and the conformance harness.',
	},
	'docs/cli.md': {
		dest: 'reference/cli.md',
		description:
			'Every sourceorrery command and option: vault, secret, audit, init, import, check, run, ui and completions, plus global options, unlocking and exit codes.',
	},
	'docs/vault-format.md': {
		dest: 'reference/vault-format.md',
		description:
			'Schema version 3 of the encrypted SQLite vault file: tables, key hierarchy, integrity tags, the audit chain, what is and is not encrypted, and compatibility rules.',
	},
	'docs/roadmap.md': {
		dest: 'roadmap.md',
		description:
			'Where SourceOrrery stands in 0.1.4: the local CLI, read-only SDKs, agent skills and supply-chain work, followed by the authenticated local broker and remote providers.',
	},
	'docs/release.md': {
		dest: 'reference/release.md',
		description:
			'How a release is cut: the manual workflow, what one run builds for six targets and ten languages, trusted publishing and the setup each registry needs, dry runs, and where each registry page gets its text.',
	},
	'docs/providers/index.md': {
		dest: 'providers/index.md',
		description:
			'Remote vaults: a secrets service of another vendor behind the same contract as a local vault, declared in sourceorrery.toml without a credential, opened by the CLI and every SDK with the same calls and error codes.',
	},
	'docs/providers/hashicorp-vault.md': {
		dest: 'providers/hashicorp-vault.md',
		description:
			'The HashiCorp Vault provider: a KV version 2 mount as a SourceOrrery vault, the credential sources it tries, how names, versions, properties and deletion map onto KV, and what differs from a local vault.',
	},
	'docs/providers/aws-secrets-manager.md': {
		dest: 'providers/aws-secrets-manager.md',
		description:
			'The AWS Secrets Manager provider: secrets under a prefix as a SourceOrrery vault, the default credential chain, how versions, tags and deletion map onto the service, and what differs from a local vault.',
	},
	'docs/rotation.md': {
		dest: 'guides/rotation.md',
		description:
			'Rotating a credential with sourceorrery secret rotate: issue, validate, activate and retire, the hook commands the manifest names, the grace period, what is recorded in the versions, and where it does not work.',
	},
	'docs/enterprise.md': {
		dest: 'guides/enterprise.md',
		description:
			'Identity, policy and revocation through the remote providers: who decides what, the workload identity set-up for GitHub Actions, Kubernetes and VMs, what a revocation reaches, and checking what an identity may read.',
	},
	'docs/sdks/index.md': {
		dest: 'sdks/index.md',
		description:
			'The read-only client for ten languages: what every SDK does, how it unlocks a vault, the typed errors with hints, and how values are guarded.',
	},
	'docs/sdks/python.md': {
		dest: 'sdks/python.md',
		description:
			'The read-only Python SDK: install it from PyPI, the release or source, open a vault, get a secret, handle typed errors with hints, load a project.',
	},
	'docs/sdks/javascript.md': {
		dest: 'sdks/javascript.md',
		description:
			'The read-only JavaScript and TypeScript SDK (@sourceorreryai/sdk): install it from npm, the release or source, open a vault, get a secret, handle typed errors with hints, load a project.',
	},
	'docs/sdks/rust.md': {
		dest: 'sdks/rust.md',
		description:
			'The read-only Rust client crate every SDK is built on: install it from crates.io, the tag or source, open a vault, get a secret, handle errors by kind, load a project.',
	},
	'docs/sdks/java.md': {
		dest: 'sdks/java.md',
		description:
			'The read-only Java SDK (Foreign Function and Memory API): install it from Maven Central, the release or source, open a vault, get a secret, handle typed exceptions, load a project.',
	},
	'docs/sdks/dotnet.md': {
		dest: 'sdks/dotnet.md',
		description:
			'The read-only .NET SDK: install it from NuGet, the release or source, open a vault, get a secret, handle typed exceptions, load a project.',
	},
	'docs/sdks/go.md': {
		dest: 'sdks/go.md',
		description:
			'The read-only Go SDK (cgo over the C ABI): install the module and the native library, or build from source, open a vault, get a secret, match errors by sentinel, load a project.',
	},
	'docs/sdks/c.md': {
		dest: 'sdks/c.md',
		description:
			'The read-only C ABI: install the archive from the release or build it from source, open a vault, get a secret, read the per-thread error state, load a project.',
	},
	'docs/sdks/cpp.md': {
		dest: 'sdks/cpp.md',
		description:
			'The header-only C++17 wrapper: install the archive from the release or build from source, open a vault, get a secret, catch typed errors, load a project.',
	},
	'docs/sdks/php.md': {
		dest: 'sdks/php.md',
		description:
			'The read-only PHP SDK (FFI): install the package from Packagist and the native library from the release or source, open a vault, get a secret, handle typed exceptions, load a project.',
	},
};

/** Directories whose links map to a section of the site. */
const DIRECTORIES = {
	'docs/adr': '/decisions/',
	'docs/sdks': '/sdks/',
	'docs/providers': '/providers/',
};

const ADR_SOURCE_DIR = 'docs/adr';
const ADR_DEST_DIR = 'decisions';

const GENERATED_IGNORE = path.join(outDir, '.gitignore');

async function main() {
	const adrFiles = (await readdir(path.join(repoRoot, ADR_SOURCE_DIR)))
		.filter((name) => /^\d{4}-.*\.md$/.test(name))
		.sort();
	for (const name of adrFiles) {
		PAGES[`${ADR_SOURCE_DIR}/${name}`] = { dest: `${ADR_DEST_DIR}/${name}`, adr: true };
	}

	await removePreviousOutput();

	const written = [];
	const adrs = [];
	for (const [source, page] of Object.entries(PAGES)) {
		const { dest, adr } = await syncPage(source, page);
		written.push(dest);
		if (adr) adrs.push(adr);
	}

	written.push(await writeDecisionsIndex(adrs));
	written.push(await writeErrorCodes());

	const ignore = [
		'# Generated by scripts/sync-docs.mjs from ../docs and the Rust sources.',
		'# Edit the sources, not these files.',
		...written.map((dest) => `/${dest}`),
		'',
	].join('\n');
	await writeFile(GENERATED_IGNORE, ignore);
	written.push('.gitignore');

	console.log(`sync-docs: wrote ${written.length} files under ${path.relative(siteRoot, outDir)}`);
}

/** Delete whatever the previous run generated, so renamed sources leave no stale pages. */
async function removePreviousOutput() {
	let previous;
	try {
		previous = await readFile(GENERATED_IGNORE, 'utf8');
	} catch {
		return;
	}
	for (const line of previous.split('\n')) {
		if (!line.startsWith('/')) continue;
		await rm(path.join(outDir, line.slice(1)), { force: true });
	}
}

async function syncPage(source, page) {
	const absolute = path.join(repoRoot, source);
	const raw = (await readFile(absolute, 'utf8')).replace(/\r\n/g, '\n');

	const h1 = raw.match(/^# (.+)$/m);
	if (!h1) throw new Error(`${source}: no H1 heading to use as the page title`);
	const title = plainText(h1[1]);
	const body = raw.slice(h1.index + h1[0].length).replace(/^\n+/, '');

	const description = page.description ?? deriveDescription(body, page);
	const { markdown: rewritten, tabs } = convertTabs(rewriteLinks(body, source), source);
	// A page with platform tabs needs MDX for the <Tabs> component; the rest stay Markdown.
	const dest = tabs ? page.dest.replace(/\.md$/, '.mdx') : page.dest;

	const frontmatter = {
		title,
		description,
		sourceFile: source,
	};
	let adr;
	if (page.adr) {
		const number = path.basename(source).slice(0, 4);
		const status = body.match(/\*\*Status:\*\*\s*([^·\n]+)/)?.[1].trim() ?? 'unknown';
		const date = body.match(/\*\*Date:\*\*\s*(\S+)/)?.[1] ?? '';
		frontmatter.sidebar = {
			label: title.replace(/^ADR \d{4}:\s*/, `${number}: `),
			order: Number(number),
		};
		adr = { number, title, status, date, href: destToHref(page.dest) };
	}

	const note = `Generated from ${source} by site/scripts/sync-docs.mjs. Edit the source file, not this copy.`;
	const output = [
		'---',
		yaml(frontmatter),
		'---',
		tabs ? `{/* ${note} */}` : `<!-- ${note} -->`,
		'',
		...(tabs ? ["import { Tabs, TabItem } from '@astrojs/starlight/components';", ''] : []),
		rewritten.trimEnd(),
		'',
	].join('\n');

	const destination = path.join(outDir, dest);
	await mkdir(path.dirname(destination), { recursive: true });
	await writeFile(destination, output);
	return { dest, adr };
}

/**
 * Platform tabs. In docs/ a block such as
 *
 *     <!-- tabs: os -->
 *     #### Windows
 *     ...
 *     #### macOS
 *     ...
 *     <!-- /tabs -->
 *
 * reads as ordinary headings on GitHub. On the site each heading becomes a
 * <TabItem> and the block a <Tabs>; the optional key after the colon is the
 * Starlight syncKey, so the platform chosen on one page is selected on every
 * page. The heading level is whatever the first heading in the block uses.
 * Fenced code inside a tab is left alone.
 */
const TABS_BLOCK = /^<!-- tabs(?::\s*([\w-]+))? -->[ \t]*\n([\s\S]*?)^<!-- \/tabs -->[ \t]*\n?/gm;

function convertTabs(markdown, source) {
	let tabs = false;
	const converted = markdown.replace(TABS_BLOCK, (match, syncKey, inner) => {
		tabs = true;
		const items = [];
		let fence = null;
		let level = null;
		for (const line of inner.split('\n')) {
			const fenceMatch = line.match(/^(`{3,}|~{3,})/);
			if (fenceMatch) {
				if (!fence) fence = fenceMatch[1];
				else if (line.startsWith(fence)) fence = null;
			}
			const heading = fence ? null : line.match(/^(#{2,6}) (.+?)\s*$/);
			if (heading && (level === null || heading[1].length === level)) {
				level = heading[1].length;
				items.push({ label: plainText(heading[2]), lines: [] });
				continue;
			}
			if (items.length === 0) {
				if (line.trim()) throw new Error(`${source}: text before the first heading of a tabs block`);
				continue;
			}
			items.at(-1).lines.push(line);
		}
		if (items.length === 0) throw new Error(`${source}: a tabs block needs a heading per tab`);
		const open = syncKey ? `<Tabs syncKey=${JSON.stringify(syncKey)}>` : '<Tabs>';
		const body = items.map(
			({ label, lines }) => `<TabItem label=${JSON.stringify(label)}>\n\n${lines.join('\n').trim()}\n\n</TabItem>`
		);
		return `${open}\n${body.join('\n')}\n</Tabs>\n`;
	});
	return { markdown: converted, tabs };
}

/** Rewrite relative Markdown links so they resolve on the site. Fenced code is left alone. */
function rewriteLinks(markdown, source) {
	const sourceDir = path.posix.dirname(source);
	return markdown
		.split(/(```[\s\S]*?```)/)
		.map((segment, index) => {
			if (index % 2 === 1) return segment; // fenced code block
			return segment.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)((?:\s+"[^"]*")?)\)/g, (match, bang, text, target, titlePart) => {
				if (bang) return match;
				if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#') || target.startsWith('/')) return match;
				const [targetPath, anchor] = splitAnchor(target);
				const repoPath = path.posix.normalize(path.posix.join(sourceDir, targetPath)).replace(/\/$/, '');
				const href = resolveRepoPath(repoPath, source);
				return `${bang}[${text}](${href}${anchor}${titlePart})`;
			});
		})
		.join('');
}

function resolveRepoPath(repoPath, source) {
	if (PAGES[repoPath]) return destToHref(PAGES[repoPath].dest);
	if (DIRECTORIES[repoPath]) return DIRECTORIES[repoPath];
	// Anything else in the repository (bindings/README.md, SECURITY.md, ...)
	// is linked on GitHub.
	console.warn(`sync-docs: ${source}: link to ${repoPath} is not on the site; pointing at GitHub`);
	return `${BLOB_URL}${repoPath}`;
}

function destToHref(dest) {
	const slug = dest.replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '');
	return slug ? `/${slug}/` : '/';
}

function splitAnchor(target) {
	const hash = target.indexOf('#');
	return hash === -1 ? [target, ''] : [target.slice(0, hash), target.slice(hash)];
}

/** First real paragraph of the body, as plain text, trimmed to a meta-description length. */
function deriveDescription(body, page) {
	let text = body;
	if (page.adr) {
		// The first paragraph of an ADR is its status line; describe the decision instead.
		const decision = body.match(/(?:^|\n)## Decision\n+([\s\S]*?)(?=\n## |$)/);
		if (decision) text = decision[1];
	}
	for (const block of text.split(/\n\s*\n/)) {
		let paragraph = block.trim();
		if (!paragraph) continue;
		if (/^(#|\||```|!\[)/.test(paragraph)) continue;
		if (/^\*[^*]+\*$/.test(paragraph)) continue; // italic subtitle line
		if (/^([-*]|\d+\.) /.test(paragraph)) {
			// A list: use its first item (ADR 0003's decision is a list).
			paragraph = paragraph.split(/\n(?=[-*] |\d+\. )/)[0].replace(/^([-*]|\d+\.) /, '');
		}
		return truncate(plainText(paragraph.replace(/\n/g, ' ')), 160);
	}
	throw new Error(`no paragraph found to derive a description from (${page.dest})`);
}

function plainText(markdown) {
	return markdown
		.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/`([^`]*)`/g, '$1')
		.replace(/\*\*([^*]+)\*\*/g, '$1')
		.replace(/\*([^*]+)\*/g, '$1')
		.replace(/\s+/g, ' ')
		.trim();
}

function truncate(text, max) {
	if (text.length <= max) return text;
	const cut = text.slice(0, max).replace(/\s+\S*$/, '');
	return `${cut}…`;
}

/** Minimal YAML emitter for the flat/nested string-and-number maps used here. */
function yaml(value, indent = '') {
	return Object.entries(value)
		.map(([key, item]) => {
			if (item && typeof item === 'object') return `${indent}${key}:\n${yaml(item, `${indent}  `)}`;
			return `${indent}${key}: ${typeof item === 'number' ? item : JSON.stringify(item)}`;
		})
		.join('\n');
}

async function writeDecisionsIndex(adrs) {
	const rows = adrs
		.sort((a, b) => a.number.localeCompare(b.number))
		.map((adr) => `| [${adr.number}](${adr.href}) | [${adr.title.replace(/^ADR \d{4}:\s*/, '')}](${adr.href}) | ${adr.status} | ${adr.date} |`);
	const dest = `${ADR_DEST_DIR}/index.md`;
	const output = [
		'---',
		yaml({
			title: 'Architecture decision records',
			sourceFile: ADR_SOURCE_DIR,
			description:
				'The decisions made so far, each with its context, the decision itself and its consequences.',
			sidebar: { label: 'Overview', order: 0 },
		}),
		'---',
		`<!-- Generated from ${ADR_SOURCE_DIR}/ by site/scripts/sync-docs.mjs. Add a record to that folder to list it here. -->`,
		'',
		'Each record states the context, the decision and its consequences. Records',
		'are numbered in the order they were accepted and are not rewritten once',
		'accepted; a later record supersedes an earlier one explicitly.',
		'',
		'| # | Decision | Status | Date |',
		'|---|----------|--------|------|',
		...rows,
		'',
		`The records live in [\`${ADR_SOURCE_DIR}/\`](${BLOB_URL}${ADR_SOURCE_DIR}) in the repository.`,
		'',
	].join('\n');
	await mkdir(path.join(outDir, ADR_DEST_DIR), { recursive: true });
	await writeFile(path.join(outDir, dest), output);
	return dest;
}

/**
 * The text of a Rust string literal's body: a backslash before a newline
 * removes the newline and the next line's leading whitespace, `\"` is a
 * quote and `\\` a backslash.
 */
function rustStringLiteral(body) {
	return body.replace(/\\\n\s*/g, '').replace(/\\(["\\])/g, '$1');
}

/** Build the error-code reference from the `SecretError` enum so it cannot drift. */
async function writeErrorCodes() {
	const source = 'crates/sourceorrery-core/src/error.rs';
	const rust = (await readFile(path.join(repoRoot, source), 'utf8')).replace(/\r\n/g, '\n');

	const enumBody = rust.match(/pub enum SecretError \{([\s\S]*?)\n\}/)?.[1];
	if (!enumBody) throw new Error(`${source}: could not find 'pub enum SecretError'`);
	const variants = [];
	// `#[error("...")]` as rustfmt writes it: the attribute may be broken
	// across lines around the string, and the string itself may contain
	// `\`-newline continuations, so whitespace is allowed around the literal
	// and an escape may be followed by any character, newline included.
	const variantRe =
		/((?:[ \t]*\/\/\/[^\n]*\n)+)[ \t]*#\[error\(\s*"((?:[^"\\]|\\[\s\S])*)"\s*\)\]\s*(\w+)/g;
	for (const match of enumBody.matchAll(variantRe)) {
		const doc = match[1]
			.split('\n')
			.map((line) => line.replace(/^\s*\/\/\/ ?/, '').trim())
			.filter(Boolean)
			.join(' ');
		variants.push({ name: match[3], doc, message: rustStringLiteral(match[2]) });
	}

	const codeBody = rust.match(/pub fn code\(&self\)[\s\S]*?match self \{([\s\S]*?)\n\s*\}/)?.[1];
	if (!codeBody) throw new Error(`${source}: could not find 'fn code'`);
	const codes = new Map();
	for (const match of codeBody.matchAll(/Self::(\w+)\s*(?:\{[^}]*\}|\([^)]*\))?\s*=>\s*"([a-z_]+)"/g)) {
		codes.set(match[1], match[2]);
	}

	const transientBody = rust.match(/pub fn is_transient\(&self\)[\s\S]*?matches!\(self,([\s\S]*?)\)\s*\n/)?.[1] ?? '';
	const transient = new Set([...transientBody.matchAll(/Self::(\w+)/g)].map((m) => m[1]));

	for (const variant of variants) {
		if (!codes.has(variant.name)) throw new Error(`${source}: variant ${variant.name} has no code in SecretError::code`);
	}
	for (const name of codes.keys()) {
		if (!variants.some((v) => v.name === name)) throw new Error(`${source}: code for ${name} has no documented variant`);
	}

	const rows = variants.map((variant) => {
		const code = codes.get(variant.name);
		const retry = transient.has(variant.name) ? 'yes' : '';
		return `| \`${code}\` | ${variant.doc} | \`${variant.message}\` | ${retry} |`;
	});

	const dest = 'reference/error-codes.md';
	const output = [
		'---',
		yaml({
			title: 'Error codes',
			sourceFile: source,
			description:
				'The stable, append-only error codes every SourceOrrery backend, SDK and the CLI report, generated from the SecretError type in sourceorrery-core.',
		}),
		'---',
		`<!-- Generated from ${source} by site/scripts/sync-docs.mjs. Edit the Rust source, not this copy. -->`,
		'',
		'Every failure a secret operation can report maps to one stable, `snake_case`',
		'code. Codes are a compatibility contract: they are **append-only**, never',
		'renamed and never reused. Messages are for humans and may change.',
		'',
		'Where you meet them:',
		'',
		'- The CLI exits with status `1` and, in `--output json` mode, prints',
		'  `{"error":{"code":"…","message":"…"}}` on stderr.',
		'- Audit rows record the code in their `detail` column, never a value.',
		'- SDKs map codes to typed errors, each carrying a hint that says what to do.',
		'',
		'Messages carry names, versions and timestamps only. No error ever contains',
		'a secret value.',
		'',
		'| Code | Meaning | Message format | Retry later? |',
		'|------|---------|----------------|--------------|',
		...rows,
		'',
		'*Retry later* marks codes for which `SecretError::is_transient` is true:',
		'calling again later could succeed without administrative action.',
		'',
		`Source of truth: [\`${source}\`](${BLOB_URL}${source}).`,
		'',
	].join('\n');
	await mkdir(path.join(outDir, 'reference'), { recursive: true });
	await writeFile(path.join(outDir, dest), output);
	return dest;
}

try {
	await access(path.join(repoRoot, 'docs'));
} catch {
	console.error(`sync-docs: ${path.join(repoRoot, 'docs')} not found; run from the sourceorrery checkout`);
	process.exit(1);
}
await main();
