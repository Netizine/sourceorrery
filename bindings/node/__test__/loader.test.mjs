// The native addon comes only from this package's own install: a module
// another account planted in a parent directory's node_modules (on Windows,
// C:\node_modules is writable by every account) is never loaded, whatever
// name it takes. Needs no vault; the last test needs `npm run build`.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const pkgRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const TUPLE = {
  'win32-x64': 'win32-x64-msvc',
  'win32-arm64': 'win32-arm64-msvc',
  'darwin-x64': 'darwin-x64',
  'darwin-arm64': 'darwin-arm64',
  'linux-x64': 'linux-x64-gnu',
  'linux-arm64': 'linux-arm64-gnu',
}[`${process.platform}-${process.arch}`];
const BUILT = TUPLE && path.join(pkgRoot, `sourceorrery.${TUPLE}.node`);

/** A project in a fresh directory with this package installed, no addon. */
function project() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'so-loader-'));
  const sdk = path.join(root, 'proj', 'node_modules', '@sourceorreryai', 'sdk');
  fs.mkdirSync(path.join(sdk, 'lib'), { recursive: true });
  // The package as published, the napi-generated index.js included when a
  // build left one (it is shipped, and must stay unused).
  for (const file of ['package.json', 'index.js']) {
    if (fs.existsSync(path.join(pkgRoot, file))) {
      fs.copyFileSync(path.join(pkgRoot, file), path.join(sdk, file));
    }
  }
  for (const file of fs.readdirSync(path.join(pkgRoot, 'lib'))) {
    fs.copyFileSync(path.join(pkgRoot, 'lib', file), path.join(sdk, 'lib', file));
  }
  return { root, sdk };
}

function run(root, code) {
  return spawnSync(process.execPath, ['-e', code], {
    cwd: path.join(root, 'proj'),
    env: { PATH: process.env.PATH ?? '', SystemRoot: process.env.SystemRoot ?? '' },
    encoding: 'utf8',
  });
}

test('a module planted in a parent node_modules is never loaded', () => {
  const { root } = project();
  try {
    const marker = path.join(root, 'marker.txt');
    const planted = [
      'win32-x64-msvc',
      'win32-arm64-msvc',
      'win32-ia32-msvc',
      'darwin-x64',
      'darwin-arm64',
      'darwin-universal',
      'linux-x64-gnu',
      'linux-arm64-gnu',
      'linux-x64-musl',
      'wasm32-wasi',
    ].map((tuple) => `sdk-${tuple}`);
    for (const name of planted) {
      const dir = path.join(root, 'node_modules', '@sourceorreryai', name);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: `@sourceorreryai/${name}`, version: '0.0.0', main: 'index.js' }),
      );
      fs.writeFileSync(
        path.join(dir, 'index.js'),
        `require('fs').writeFileSync(${JSON.stringify(marker)}, ${JSON.stringify(name)});\n` +
          "module.exports = { SecretValue: class {}, contractVersion: () => 'planted' };\n",
      );
    }
    const out = run(root, "console.log(require('@sourceorreryai/sdk').contractVersion())");
    assert.notEqual(out.status, 0, out.stdout);
    assert.doesNotMatch(out.stdout, /planted/);
    assert.match(out.stderr, /Cannot load the native addon|has no native addon/);
    assert.equal(fs.existsSync(marker), false, 'a planted module ran');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the platform package installed beside the SDK is loaded', { skip: !BUILT || !fs.existsSync(BUILT) }, () => {
  const { root, sdk } = project();
  try {
    const beside = path.join(root, 'proj', 'node_modules', '@sourceorreryai', `sdk-${TUPLE}`);
    fs.mkdirSync(beside, { recursive: true });
    fs.copyFileSync(BUILT, path.join(beside, `sourceorrery.${TUPLE}.node`));
    const loader = JSON.stringify(path.join(sdk, 'lib', 'native.js'));
    const out = run(root, `console.log(typeof require(${loader}).contractVersion)`);
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), 'function');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
