import { iconHast } from '../src/lib/font-awesome.mjs';

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
	const isExternal = (href) => {
		if (typeof href !== 'string' || !/^(https?:)?\/\//i.test(href)) return false;
		try { return new URL(href, site).host !== own; } catch { return false; }
	};
	const relTokens = (rel) => [...new Set([
		...(Array.isArray(rel) ? rel : String(rel ?? '').split(/\s+/)).filter(Boolean),
		'noopener', 'noreferrer',
	])].join(' ');
	const additions = () => [iconHast('arrow-up-right-from-square', { className: 'so-external-icon' }), {
		type: 'element', tagName: 'span',
		properties: { class: 'sr-only', 'data-pagefind-ignore': true },
		children: [{ type: 'text', value: ' (opens in a new tab)' }],
	}];
	const visitJsx = (node) => {
		// Dynamic URLs and spread attributes are left to their owning components.
		if (node.attributes.some((attribute) => attribute.type !== 'mdxJsxAttribute')) return;
		const attrs = Object.fromEntries(node.attributes.map(({ name, value }) => [name, value]));
		if (!isExternal(attrs.href) || attrs['data-so-external']) return;
		const updates = { target: '_blank', rel: relTokens(typeof attrs.rel === 'string' ? attrs.rel : ''), 'data-so-external': 'true' };
		if (typeof attrs['aria-label'] === 'string') updates['aria-label'] = `${attrs['aria-label']} (opens in a new tab)`;
		return {
			...node,
			attributes: [
				...node.attributes.filter(({ name }) => !(name in updates)),
				...Object.entries(updates).map(([name, value]) => ({ type: 'mdxJsxAttribute', name, value })),
			],
			children: [...node.children, ...additions()],
		};
	};
	return () => ({
		name: 'external-links',
		element: {
			filter: ['a'],
			visit(node, ctx) {
				if (!isExternal(node.properties?.href) || node.properties?.['data-so-external']) return;
				ctx.setProperty(node, 'target', '_blank');
				ctx.setProperty(node, 'rel', relTokens(node.properties?.rel));
				ctx.setProperty(node, 'data-so-external', 'true');
				const label = node.properties?.['aria-label'] ?? node.properties?.ariaLabel;
				if (typeof label === 'string') ctx.setProperty(node, 'aria-label', `${label} (opens in a new tab)`);
				ctx.appendChild(node, additions());
			},
		},
		mdxJsxFlowElement: { filter: ['a'], visit: visitJsx },
		mdxJsxTextElement: { filter: ['a'], visit: visitJsx },
	});
}
