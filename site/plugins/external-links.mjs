/**
 * Sätteri hast plugin: every link that leaves the site opens in a new tab.
 *
 * Runs on the rendered HTML of each Markdown and MDX page (Astro 7 renders
 * both through the processor configured in astro.config.mjs). A link is
 * external when its href has a scheme or is protocol-relative and its host
 * is not the site's own. `mailto:` and other non-web schemes are left alone.
 * Links in page chrome (the GitHub icon, "Edit page", the hero) are handled
 * by the component overrides in src/components.
 */
export function externalLinks({ site }) {
	const own = new URL(site).host;
	return () => ({
		name: 'external-links',
		element: {
			filter: ['a'],
			visit(node, ctx) {
				const href = node.properties?.href;
				if (typeof href !== 'string') return;
				if (!/^(https?:)?\/\//i.test(href)) return;
				let host;
				try {
					host = new URL(href, site).host;
				} catch {
					return;
				}
				if (host === own) return;
				ctx.setProperty(node, 'target', '_blank');
				ctx.setProperty(node, 'rel', 'noopener noreferrer');
			},
		},
	});
}
