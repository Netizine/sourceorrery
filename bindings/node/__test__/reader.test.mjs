// The Node SDK against the vault created by scripts/ci/fixture-vault.sh.
// Run after `npm run build`:  eval "$(bash scripts/ci/fixture-vault.sh)" && npm test
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import util from 'node:util';

const require = createRequire(import.meta.url);
const sdk = require('../lib/index.js');
const {
  SecretReader,
  Project,
  SecretValue,
  loadProject,
  contractVersion,
  errorFor,
  SourceOrreryError,
  VaultNotFoundError,
  VaultLockedError,
  SecretNotFoundError,
  VersionNotFoundError,
  SecretDeletedError,
  PolicyError,
  SecretDisabledError,
  SecretExpiredError,
  SecretNotYetValidError,
  InvalidArgumentError,
  InvalidNameError,
  ManifestError,
  UnsupportedError,
  UnauthenticatedError,
  ProviderUnavailableError,
} = sdk;

const env = process.env;
const fixture = {
  home: env.SOURCEORRERY_HOME,
  passphrase: env.SOURCEORRERY_PASSPHRASE,
  vault: env.SOURCEORRERY_TEST_VAULT,
  manifest: env.SOURCEORRERY_TEST_MANIFEST,
  oldVersion: env.SOURCEORRERY_TEST_OLD_VERSION,
  latest: 'ci-secret-value',
  first: 'first-version',
};
const ready = Object.values(fixture).every(Boolean);
const skip = ready ? false : 'run scripts/ci/fixture-vault.sh first';

function withReader(fn) {
  const reader = new SecretReader(fixture.vault); // unlocks through SOURCEORRERY_PASSPHRASE
  try {
    return fn(reader);
  } finally {
    reader.close();
  }
}

test('contract version', () => {
  assert.equal(contractVersion(), '1');
});

test('get returns the newest accessible version', { skip }, () =>
  withReader((reader) => {
    const secret = reader.get('database-password');
    assert.equal(secret.value.exposeText(), fixture.latest);
    assert.deepEqual(secret.value.expose(), Buffer.from(fixture.latest));
    assert.equal(secret.value.length, fixture.latest.length);
    assert.equal(secret.properties.name, 'database-password');
    assert.equal(secret.properties.vault, fixture.vault);
    assert.equal(secret.properties.enabled, true);
    assert.equal(secret.properties.contentType, 'text/plain');
    assert.deepEqual(secret.properties.tags, { env: 'ci' });
    assert.ok(secret.properties.createdOn instanceof Date);
    assert.ok(secret.properties.createdOn.getTime() <= Date.now());
    assert.equal(secret.properties.reference, `sourceorrery://${fixture.vault}/database-password/${secret.properties.version}`);
    secret.close();
    assert.equal(secret.value.closed, true);
  }),
);

test('explicit versions and properties', { skip }, () =>
  withReader((reader) => {
    const old = reader.get('database-password', fixture.oldVersion);
    assert.equal(old.value.exposeText(), fixture.first);
    assert.equal(old.properties.version, fixture.oldVersion);
    assert.equal(reader.properties('database-password', fixture.oldVersion).version, fixture.oldVersion);
    assert.notEqual(reader.properties('database-password').version, fixture.oldVersion);
  }),
);

test('references resolve within the vault', { skip }, () =>
  withReader((reader) => {
    assert.equal(reader.resolve(`sourceorrery://${fixture.vault}/database-password`).value.exposeText(), fixture.latest);
    assert.equal(
      reader.resolve(`sourceorrery://${fixture.vault}/database-password/${fixture.oldVersion}`).value.exposeText(),
      fixture.first,
    );
    assert.throws(() => reader.resolve('sourceorrery://other-vault/database-password'), InvalidArgumentError);
    assert.throws(() => reader.resolve('not-a-reference'), (err) => err instanceof InvalidArgumentError && err.code === 'invalid_argument');
  }),
);

test('a disabled newest version falls back', { skip }, () =>
  withReader((reader) => {
    assert.equal(reader.get('rotated-key').value.exposeText(), 'old');
    const newest = reader.properties('rotated-key');
    assert.equal(newest.enabled, false);
    assert.throws(
      () => reader.get('rotated-key', newest.version),
      (err) => err instanceof SecretDisabledError && err instanceof PolicyError && err.code === 'disabled' && err.hint.includes('--enable'),
    );
  }),
);

test('policy errors explain themselves', { skip }, () =>
  withReader((reader) => {
    assert.throws(() => reader.get('expired-token'), (err) => err instanceof SecretExpiredError && err.hint.startsWith('Policy') && !err.transient);
    assert.throws(() => reader.get('future-token'), (err) => err instanceof SecretNotYetValidError && err.transient);
    assert.throws(() => reader.get('deleted-secret'), (err) => err instanceof SecretDeletedError && err.hint.includes('secret recover deleted-secret'));
  }),
);

test('missing secrets say how to store them', { skip }, () =>
  withReader((reader) => {
    assert.throws(
      () => reader.get('missing'),
      (err) =>
        err instanceof SecretNotFoundError &&
        err.code === 'not_found' &&
        err.detail === "secret 'missing' was not found" &&
        err.hint.includes(`sourceorrery secret set missing --vault ${fixture.vault}`) &&
        err.message.startsWith(`${err.detail}. `) &&
        err.name === 'SecretNotFoundError',
    );
    assert.throws(() => reader.get('database-password', 'deadbeef'), (err) => err instanceof VersionNotFoundError && err instanceof SecretNotFoundError);
    assert.throws(() => reader.get('bad_name'), InvalidNameError);
  }),
);

test('vault errors say how to fix them', { skip }, () => {
  assert.throws(
    () => new SecretReader('no-such-vault'),
    (err) => err instanceof VaultNotFoundError && err.hint.includes('sourceorrery vault create no-such-vault') && err.hint.includes(fixture.home),
  );
  assert.throws(
    () => new SecretReader(fixture.vault, { passphrase: 'wrong-passphrase', environment: false }),
    (err) =>
      err instanceof VaultLockedError &&
      err.hint.includes('passphrase option: tried') &&
      err.hint.includes('SOURCEORRERY_PASSPHRASE: not set') &&
      err.hint.includes(`--vault ${fixture.vault}`) &&
      !err.message.includes('wrong-passphrase'),
  );
  const reader = SecretReader.open(fixture.vault, { home: fixture.home, passphrase: Buffer.from(fixture.passphrase), environment: false });
  assert.equal(reader.vaultName, fixture.vault);
  assert.equal(reader.descriptor().name, fixture.vault);
  assert.ok(reader.descriptor().protectors.includes('passphrase'));
  reader.close();
  assert.equal(reader.closed, true);
  assert.throws(() => reader.get('database-password'), /closed/);
  reader.close();
});

test('secret values do not leak', { skip }, () =>
  withReader((reader) => {
    const secret = reader.get('database-password');
    const { value } = secret;
    assert.ok(value instanceof SecretValue);
    assert.equal(String(value), '[REDACTED]');
    assert.equal(`${value}`, '[REDACTED]');
    assert.equal(JSON.stringify({ value }), '{"value":"[REDACTED]"}');
    assert.equal(JSON.stringify(secret).includes(fixture.latest), false);
    assert.equal(util.inspect(value), 'SecretValue([REDACTED])');
    assert.equal(util.inspect(secret).includes(fixture.latest), false);
    assert.equal(util.inspect(reader), `SecretReader(vault='${fixture.vault}')`);
    value.close();
    assert.equal(value.closed, true);
    assert.equal(value.length, 0);
    assert.throws(() => value.expose(), /closed/);
    value.close();
    if (typeof Symbol.dispose === 'symbol') {
      const other = reader.get('database-password');
      other[Symbol.dispose]();
      assert.equal(other.value.closed, true);
    }
  }),
);

test('project load mirrors run', { skip }, () => {
  const project = Project.load(fixture.manifest);
  try {
    assert.equal(project.name, 'ci-project');
    assert.ok(project.manifestPath.endsWith('sourceorrery.toml'));
    assert.deepEqual([...project].map((s) => s.name).sort(), ['database-password', 'rotated-key']);
    assert.equal(project.env('DATABASE_PASSWORD').exposeText(), fixture.latest);
    assert.equal(project.env('ROTATED').exposeText(), 'old');
    assert.equal(project.get('missing-optional'), undefined, 'optional misses are skipped');
    assert.equal(project.get('expired-token'), undefined, 'optional policy refusals are skipped');
    const entry = project.get('rotated-key');
    assert.equal(entry.required, true);
    assert.equal(entry.env, 'ROTATED');
    assert.equal(entry.reference, `sourceorrery://${fixture.vault}/rotated-key`);
    assert.equal(project.size, 2);
  } finally {
    project.close();
  }
  assert.equal(project.env('ROTATED').closed, true);
  assert.equal(loadProject(fixture.manifest).name, 'ci-project');
  assert.throws(() => Project.load(`${fixture.manifest}.missing`), ManifestError);
  assert.throws(() => Project.load(fixture.manifest, { passphrase: 'wrong', environment: false }), VaultLockedError);
});

test('unknown codes keep their code', () => {
  const err = errorFor('brand_new_code', 'm', 'h');
  assert.equal(err.constructor, SourceOrreryError);
  assert.equal(err.code, 'brand_new_code');
  assert.equal(err.message, 'm. h');
});

test('provider codes map to typed errors', () => {
  const unauthenticated = errorFor('unauthenticated', 'm', 'h');
  assert.equal(unauthenticated.constructor, UnauthenticatedError);
  assert.equal(unauthenticated.code, 'unauthenticated');
  assert.equal(unauthenticated.name, 'UnauthenticatedError');
  assert.equal(unauthenticated.transient, false);
  const unavailable = errorFor('provider_unavailable', 'm', 'h');
  assert.equal(unavailable.constructor, ProviderUnavailableError);
  assert.equal(unavailable.code, 'provider_unavailable');
  assert.equal(unavailable.transient, true);
});

test('a remote vault in the manifest is opened at its provider', { skip }, () => {
  const manifest = join(mkdtempSync(join(tmpdir(), 'sourceorrery-sdk-')), 'sourceorrery.toml');
  writeFileSync(
    manifest,
    [
      '[project]',
      'name = "demo"',
      `vault = "${fixture.vault}"`,
      '',
      '[vaults.remote-x]',
      'provider = "hashicorp-vault"',
      'address = "https://vault.example.com:8200"',
      'mount = "secret"',
      '',
    ].join('\n'),
  );
  const options = { home: fixture.home, passphrase: fixture.passphrase, environment: false, manifest };

  // No provider is built in yet, so the remote vault is refused by name.
  assert.throws(
    () => new SecretReader('remote-x', options),
    (err) =>
      err instanceof UnsupportedError &&
      err.code === 'unsupported' &&
      err.detail.includes('HashiCorp Vault') &&
      err.hint.includes('HashiCorp Vault provider'),
  );

  // A vault without a `[vaults.<name>]` table is still the local file.
  const reader = SecretReader.open(fixture.vault, options);
  try {
    assert.equal(reader.get('database-password').value.exposeText(), fixture.latest);
  } finally {
    reader.close();
  }
});
