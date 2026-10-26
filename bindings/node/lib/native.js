'use strict';
// The native addon, loaded only from this package's own install: the file a
// local `napi build` leaves in the package, or the platform package npm
// installs beside it (or inside it). Never a name Node would look for in
// every parent directory's node_modules, where another account may have
// put a module of its own (C:\node_modules), never a WASI package, never a
// path from the environment. Without the addon the require fails, naming
// the package to install.

const fs = require('node:fs');
const path = require('node:path');

/** The platforms the release publishes a package for, by platform-arch. */
const TUPLES = {
  'win32-x64': 'win32-x64-msvc',
  'win32-arm64': 'win32-arm64-msvc',
  'darwin-x64': 'darwin-x64',
  'darwin-arm64': 'darwin-arm64',
  'linux-x64': 'linux-x64-gnu',
  'linux-arm64': 'linux-arm64-gnu',
};

function load() {
  const tuple = TUPLES[`${process.platform}-${process.arch}`];
  if (!tuple) {
    throw new Error(
      `@sourceorreryai/sdk has no native addon for ${process.platform}-${process.arch}`,
    );
  }
  const file = `sourceorrery.${tuple}.node`;
  const pkg = `sdk-${tuple}`;
  // This file is <...>/@sourceorreryai/sdk/lib/native.js, by its real path
  // (also under pnpm, whose packages are symlinks).
  const root = path.join(__dirname, '..');
  const candidates = [
    path.join(root, file),
    path.join(root, '..', pkg, file),
    path.join(root, 'node_modules', '@sourceorreryai', pkg, file),
  ];
  let failure;
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) {
      continue;
    }
    try {
      return require(candidate);
    } catch (err) {
      failure ??= err;
    }
  }
  const err = new Error(
    `Cannot load the native addon @sourceorreryai/${pkg}: reinstall @sourceorreryai/sdk ` +
      'with optional dependencies (npm installs the one for this platform)',
  );
  if (failure) {
    err.cause = failure;
  }
  throw err;
}

module.exports = load();
