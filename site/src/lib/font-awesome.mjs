// Build-time only. SVG paths are emitted into HTML; no Kit script or icon
// library is sent to the browser. Revision 4 contains duotone thin, not light.
import { byPrefixAndName } from '@awesome.me/kit-515c69ad68/icons';

const prefixes = { duotone: 'fadt', brands: 'fab', kit: 'fak' };

/** Resolve an icon from the installed Kit, failing the build on a missing name. */
export function iconData(name, family = 'duotone') {
	const prefix = prefixes[family];
	const definition = byPrefixAndName[prefix]?.[name];
	if (!definition) throw new Error(`Font Awesome Kit is missing ${family}/${name}`);
	const [width, height, , , paths] = definition.icon;
	return {
		name: definition.iconName,
		prefix,
		width,
		height,
		paths: (Array.isArray(paths) ? paths : [paths]).map((d, index) => ({
			d,
			className: Array.isArray(paths) && index === 0 ? 'fa-secondary' : 'fa-primary',
		})).filter(({ d }) => d.length > 0),
	};
}

/** The Markdown compiler uses the same path data as the Astro component. */
export function iconHast(name, { family = 'duotone', className = '' } = {}) {
	const icon = iconData(name, family);
	return {
		type: 'element',
		tagName: 'svg',
		properties: {
			xmlns: 'http://www.w3.org/2000/svg',
			viewBox: `0 0 ${icon.width} ${icon.height}`,
			width: '1em', height: '1em', fill: 'currentColor',
			class: `so-fa-icon ${className}`.trim(),
			'aria-hidden': 'true', focusable: 'false',
			'data-prefix': icon.prefix, 'data-icon': icon.name,
		},
		children: icon.paths.map(({ d, className }) => ({
			type: 'element', tagName: 'path', properties: { d, class: className }, children: [],
		})),
	};
}
