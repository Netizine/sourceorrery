import { iconHast } from '../src/lib/font-awesome.mjs';

const ALERTS = {
	NOTE: { title: 'Note', variant: 'note', icon: 'circle-info' },
	TIP: { title: 'Tip', variant: 'tip', icon: 'lightbulb' },
	IMPORTANT: { title: 'Important', variant: 'note', icon: 'circle-exclamation' },
	WARNING: { title: 'Warning', variant: 'caution', icon: 'triangle-exclamation' },
	CAUTION: { title: 'Caution', variant: 'danger', icon: 'octagon-exclamation' },
};

function element(tag, properties, children = []) {
	return { type: 'paragraph', data: { hName: tag, hProperties: properties }, children };
}

function iconMdast(name) {
	const toMdast = ({ tagName, properties, children }) => element(tagName, properties, children.map(toMdast));
	return toMdast(iconHast(name, { className: 'starlight-aside__icon' }));
}

/** Keep source documentation readable on GitHub and render semantic callouts on the site. */
export function githubAlerts() {
	return () => ({
		name: 'sourceorrery-github-alerts',
		blockquote(node) {
			const first = node.children[0];
			const text = first?.type === 'paragraph' && first.children[0];
			if (text?.type !== 'text') return;
			const match = text.value.match(/^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\](?:[ \t]*\n|$)/);
			if (!match) return;
			const { title, variant, icon } = ALERTS[match[1]];
			const remainingText = text.value.slice(match[0].length);
			const firstChildren = [
				...(remainingText ? [{ type: 'text', value: remainingText }] : []),
				...first.children.slice(1),
			];
			const content = [
				...(firstChildren.length ? [{ ...first, children: firstChildren }] : []),
				...node.children.slice(1),
			];
			return element('aside', {
				class: `starlight-aside starlight-aside--${variant}`,
				'aria-label': title,
			}, [
				element('p', { class: 'starlight-aside__title', 'aria-hidden': 'true' }, [
					iconMdast(icon),
					{ type: 'text', value: title },
				]),
				element('div', { class: 'starlight-aside__content' }, content),
			]);
		},
	});
}

/** Render local Kit SVGs for Starlight's native :::note/tip/caution/danger syntax. */
export function calloutIcons() {
	const icons = { note: 'circle-info', tip: 'lightbulb', caution: 'triangle-exclamation', danger: 'octagon-exclamation' };
	return () => ({
		name: 'sourceorrery-callout-icons',
		element: {
			filter: ['svg'],
			visit(node, context) {
				const classes = String(node.properties?.class ?? node.properties?.className ?? '');
				if (!classes.includes('starlight-aside__icon')) return;
				if (classes.includes('so-fa-icon')) return;
				const aside = context.parent(context.parent(node));
				const asideClasses = String(aside?.properties?.class ?? aside?.properties?.className ?? '');
				const variant = asideClasses.match(/starlight-aside--(note|tip|caution|danger)/)?.[1];
				if (!variant) return;
				return iconHast(icons[variant], { className: 'starlight-aside__icon' });
			},
		},
	});
}
