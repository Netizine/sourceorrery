import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { metadataForEntry } from './doc-metadata.mjs';

/** Decorate Starlight's loader without changing its slugs, assets or live updates. */
export function withDocMetadata(loader) {
	return {
		...loader,
		name: 'sourceorrery-docs-with-metadata',
		async load(context) {
			const siteRoot = fileURLToPath(context.config.root);
			await loader.load({
				...context,
				async parseData(options) {
					const body = options.filePath ? await readFile(options.filePath, 'utf8') : '';
					const metadata = await metadataForEntry({ ...options, body }, siteRoot);
					return context.parseData({ ...options, data: { ...options.data, ...metadata } });
				},
			});
			// The glob loader reuses unchanged files. Git commits can change their
			// dates without changing their bytes, so refresh metadata on every load.
			for (const [, entry] of context.store.entries()) {
				const metadata = await metadataForEntry(entry, siteRoot);
				context.store.set({ ...entry, data: { ...entry.data, ...metadata } });
			}
		},
	};
}
