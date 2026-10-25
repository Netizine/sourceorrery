import { readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * The version the documentation describes and whether it is released,
 * from the same sources as scripts/release/docs-version.py: the workspace
 * version in Cargo.toml, and a `## [X.Y.Z] - YYYY-MM-DD` heading in
 * CHANGELOG.md naming it once it is released.
 */
export function releaseVersion(repositoryRoot) {
	const cargo = readFileSync(path.join(repositoryRoot, 'Cargo.toml'), 'utf8');
	const section = cargo.match(/^\[workspace\.package\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m);
	const version = section?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
	if (!version) throw new Error('Cargo.toml: no [workspace.package] version');
	const changelog = readFileSync(path.join(repositoryRoot, 'CHANGELOG.md'), 'utf8');
	const released = changelog
		.split('\n')
		.some((line) => line.match(/^## \[([^\]]+)\] - \d{4}-\d{2}-\d{2}\s*$/)?.[1] === version);
	return { version, released };
}
