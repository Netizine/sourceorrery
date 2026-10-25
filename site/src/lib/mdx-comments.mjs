/**
 * MDX has no HTML comments. A Markdown page that becomes MDX (it has tabs
 * or a walkthrough) keeps its comment lines, such as the release-note
 * markers that scripts/release/docs-version.py writes, as MDX comments.
 * Only a line that is one whole comment outside a code fence changes;
 * comments inside code examples are content.
 */
export function htmlCommentsToMdx(markdown) {
	let fence;
	return markdown
		.split('\n')
		.map((line) => {
			const marker = line.match(/^\s*(`{3,}|~{3,})/);
			if (marker) {
				if (!fence) fence = marker[1];
				else if (marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = undefined;
				return line;
			}
			if (fence) return line;
			const comment = line.match(/^(\s*)<!--(.*?)-->\s*$/);
			return comment ? `${comment[1]}{/*${comment[2].replaceAll('*/', '* /')}*/}` : line;
		})
		.join('\n');
}
