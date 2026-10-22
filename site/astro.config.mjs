// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import { externalLinks } from './plugins/external-links.mjs';

const SITE_URL = 'https://sourceorrery.ai';
const GITHUB_URL = 'https://github.com/Netizine/sourceorrery';

// https://astro.build/config
export default defineConfig({
	site: SITE_URL,
	markdown: {
		// Every link that leaves the site opens in a new tab. Links in page
		// chrome (the GitHub icon, "Edit page", the hero) get the same
		// attributes in the component overrides below.
		processor: satteri({ hastPlugins: [externalLinks({ site: SITE_URL })] }),
	},
	integrations: [
		starlight({
			title: 'SourceOrrery',
			description: 'Secrets belong to the runtime, not the repository.',
			logo: {
				// The emblem in two tunings, one per theme; the name is rendered as text beside it.
				light: './src/assets/sourceorrery-light.svg',
				dark: './src/assets/sourceorrery-dark.svg',
				alt: 'SourceOrrery',
			},
			favicon: '/favicon.svg',
			head: [
				// Safari does not load SVG favicons; it takes this PNG (see scripts/make-favicon.mjs).
				{
					tag: 'link',
					attrs: { rel: 'icon', href: '/favicon.png', type: 'image/png', sizes: '128x128' },
				},
			],
			social: [{ icon: 'github', label: 'GitHub', href: GITHUB_URL }],
			// No "Edit page" link: without `editLink` here and with no `editUrl`
			// in any page's frontmatter (scripts/sync-docs.mjs writes none),
			// Starlight renders none.
			customCss: [
				// Self-hosted type: serif for text, a sans for interface labels, a mono for code.
				'@fontsource-variable/source-serif-4/opsz.css',
				'@fontsource-variable/source-serif-4/opsz-italic.css',
				'@fontsource-variable/inter',
				'@fontsource-variable/jetbrains-mono',
				'./src/styles/paper.css',
			],
			components: {
				Hero: './src/components/Hero.astro',
				// Starlight's own version, with the GitHub link opening in a new tab.
				SocialIcons: './src/components/SocialIcons.astro',
				// Starlight's footer plus the homepage's privacy note.
				Footer: './src/components/Footer.astro',
			},
			expressiveCode: {
				themes: ['github-light', 'github-dark-dimmed'],
				useStarlightUiThemeColors: true,
				styleOverrides: {
					borderRadius: '2px',
					borderWidth: '1px',
					codeFontFamily: "'JetBrains Mono Variable', ui-monospace, Consolas, monospace",
					codeFontSize: '0.9rem',
					codeLineHeight: '1.6',
					codePaddingBlock: '1rem',
					codePaddingInline: '1.25rem',
					// Paper-toned code backgrounds instead of the themes' own.
					codeBackground: ({ theme }) => (theme.type === 'dark' ? '#1e1c18' : '#edeae1'),
					frames: {
						shadowColor: 'transparent',
						editorTabBarBackground: ({ theme }) => (theme.type === 'dark' ? '#1a1916' : '#e6e2d8'),
						terminalTitlebarBackground: ({ theme }) => (theme.type === 'dark' ? '#1a1916' : '#e6e2d8'),
						terminalBackground: ({ theme }) => (theme.type === 'dark' ? '#1e1c18' : '#edeae1'),
					},
				},
			},
			lastUpdated: true,
			credits: false,
			sidebar: [
				{ label: 'Getting started', slug: 'getting-started' },
				{
					label: 'Guides',
					items: [
						{ label: 'Headless: WSL, Docker, CI', slug: 'guides/headless' },
						{ label: 'Building from source', slug: 'guides/building-from-source' },
					],
				},
				{
					label: 'SDKs',
					items: [
						{ label: 'Overview', slug: 'sdks' },
						{ label: 'Python', slug: 'sdks/python' },
						{ label: 'JavaScript / TypeScript', slug: 'sdks/javascript' },
						{ label: 'Rust', slug: 'sdks/rust' },
						{ label: 'Java', slug: 'sdks/java' },
						{ label: '.NET', slug: 'sdks/dotnet' },
						{ label: 'Go', slug: 'sdks/go' },
						{ label: 'C', slug: 'sdks/c' },
						{ label: 'C++', slug: 'sdks/cpp' },
						{ label: 'PHP', slug: 'sdks/php' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI', slug: 'reference/cli' },
						{ label: 'Vault format', slug: 'reference/vault-format' },
						{ label: 'Error codes', slug: 'reference/error-codes' },
						{ label: 'Releasing', slug: 'reference/release' },
					],
				},
				{
					label: 'Security',
					items: [
						{ label: 'Threat model', slug: 'security/threat-model' },
						{ label: 'Supply chain', slug: 'security/supply-chain' },
					],
				},
				{ label: 'Architecture', slug: 'architecture' },
				{ label: 'Roadmap', slug: 'roadmap' },
				{
					label: 'Decisions',
					items: [{ autogenerate: { directory: 'decisions' } }],
				},
			],
		}),
	],
});
