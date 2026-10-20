// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// TODO: confirm the repository URL once it is public. It is also hard-coded
// in scripts/sync-docs.mjs for edit links and links to files outside docs/.
const GITHUB_URL = 'https://github.com/sourceorrery/sourceorrery';

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
			customCss: ['./src/styles/custom.css'],
			credits: false,
			sidebar: [
				{ label: 'Getting started', slug: 'getting-started' },
				{
					label: 'Guides',
					items: [{ label: 'Headless: WSL, Docker, CI', slug: 'guides/headless' }],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI', slug: 'reference/cli' },
						{ label: 'Vault format', slug: 'reference/vault-format' },
						{ label: 'Error codes', slug: 'reference/error-codes' },
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
