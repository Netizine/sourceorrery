// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const GITHUB_URL = 'https://github.com/Netizine/sourceorrery';

// https://astro.build/config
export default defineConfig({
	site: 'https://sourceorrery.ai',
	integrations: [
		starlight({
			title: 'SourceOrrery',
			description: 'Secrets belong to the runtime, not the repository.',
			logo: {
				src: './src/assets/logo-mark.png',
				alt: 'SourceOrrery',
			},
			favicon: '/favicon.png',
			social: [{ icon: 'github', label: 'GitHub', href: GITHUB_URL }],
			editLink: {
				// Pages synced from docs/ override this with their source file.
				baseUrl: `${GITHUB_URL}/edit/main/site/`,
			},
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
					items: [{ label: 'Headless: WSL, Docker, CI', slug: 'guides/headless' }],
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
					items: [{ label: 'Threat model', slug: 'security/threat-model' }],
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
