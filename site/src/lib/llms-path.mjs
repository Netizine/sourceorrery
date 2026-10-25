/** The clean Markdown companion for a generated documentation route. */
export function llmsPath(pathname) {
	if (!/^\/(?:[a-z0-9-]+\/)*$/.test(pathname)) throw new Error(`Invalid documentation route: ${pathname}`);
	return `/llms${pathname}index.md`;
}
