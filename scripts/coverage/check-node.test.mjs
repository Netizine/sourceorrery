import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { nodeCoverageProblems } from './check-node.mjs';

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'sourceorrery-coverage-check-'));
  assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(root).startsWith('sourceorrery-coverage-check-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (name, value = '{}') => {
    const file = path.join(root, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, value);
  };
  write('site/package.json', JSON.stringify({ dependencies: { astro: '7', '@awesome.me/kit-example': '1' } }));
  write('scripts/coverage/node_modules/c8/bin/c8.js');
  write('site/node_modules/astro/package.json');
  return { root, write };
}

test('a partial site installation reports the missing private dependency before tests run', (t) => {
  const { root } = fixture(t);
  const problems = nodeCoverageProblems(root, '24.0.0');
  assert.equal(problems.length, 1);
  assert.match(problems[0], /@awesome\.me\/kit-example/);
  assert.match(problems[0], /npm ci --ignore-scripts --prefix site/);
});

test('an older Node runtime is rejected even when all dependencies exist', (t) => {
  const { root, write } = fixture(t);
  write('site/node_modules/@awesome.me/kit-example/package.json');
  assert.deepEqual(nodeCoverageProblems(root, '22.15.1'), ['Node >=22.19 is required; Node 24 is recommended.']);
  assert.deepEqual(nodeCoverageProblems(root, '22.19.0'), []);
  assert.deepEqual(nodeCoverageProblems(root, '24.19.0'), []);
});
