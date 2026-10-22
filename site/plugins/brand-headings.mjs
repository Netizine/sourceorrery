/** Apply the wordmark only to plain text in display headings, never prose or code. */
export function brandHeadings() {
	const span = (className, children) => ({
		type: 'element', tagName: 'span', properties: { class: className }, children,
	});
	const wordmark = () => ({
		...span('so-wordmark', [
			span('so-wordmark__source', [{ type: 'text', value: 'Source' }]),
			span('so-wordmark__orrery', [{ type: 'text', value: 'Orrery' }]),
		]),
		properties: { class: 'so-wordmark', translate: 'no' },
	});
	return () => ({
		name: 'sourceorrery-brand-headings',
		element: {
			filter: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
			visit(node) {
				// Preserve heading IDs, links, inline code and other authored markup.
				if (!node.children.some((child) => child.type === 'text' && /\bSourceOrrery\b/u.test(child.value))) return;
				return { ...node, children: node.children.flatMap((child) => child.type === 'text'
					? child.value.split(/(\bSourceOrrery\b)/u).filter(Boolean).map((part) => part === 'SourceOrrery' ? wordmark() : { type: 'text', value: part })
					: [child]) };
			},
		},
	});
}
