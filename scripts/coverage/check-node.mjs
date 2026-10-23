import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export function nodeCoverageProblems(repo, version = process.versions.node) {
  const problems = [];
  const [major, minor] = version.split('.').map(Number);
  if (!(major > 22 || major === 22 && minor >= 19)) {
    problems.push('Node >=22.19 is required; Node 24 is recommended.');
  }
  if (!existsSync(path.join(repo, 'scripts/coverage/node_modules/c8/bin/c8.js'))) {
    problems.push('Run npm ci --ignore-scripts --prefix scripts/coverage.');
  }
  const manifest = JSON.parse(readFileSync(path.join(repo, 'site/package.json'), 'utf8'));
  const missing = Object.keys(manifest.dependencies).filter((name) =>
    !existsSync(path.join(repo, 'site/node_modules', name, 'package.json')));
  if (missing.length) {
    problems.push(`Site dependencies missing: ${missing.join(', ')}. Run npm ci --ignore-scripts --prefix site using your existing Font Awesome npm authentication.`);
  }
  return problems;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const repo = fileURLToPath(new URL('../../', import.meta.url));
  const problems = nodeCoverageProblems(repo);
  for (const message of problems) console.error(message);
  process.exitCode = problems.length ? 2 : 0;
}
