// Conformance runner for the Node.js SDK (tests/conformance/sdk/README.md).
//
//   node run.mjs <op> [key=value ...]
import { Project, SecretReader, SourceOrreryError } from '@sourceorrery/sdk';

const [op, ...rest] = process.argv.slice(2);
const kv = Object.fromEntries(
  rest.map((arg) => {
    const i = arg.indexOf('=');
    return [arg.slice(0, i), arg.slice(i + 1)];
  }),
);

function propertiesLines(p) {
  return [
    ['version', p.version],
    ['enabled', String(p.enabled)],
    ['content_type', p.contentType ?? ''],
    ['reference', p.reference],
    ...Object.entries(p.tags).map(([k, v]) => [`tag.${k}`, v]),
  ];
}

function secretLines(secret) {
  return [['value', secret.value.exposeText()], ...propertiesLines(secret.properties)];
}

function run() {
  const vault = kv.vault || process.env.SOURCEORRERY_TEST_VAULT || 'development';
  const options = {
    home: kv.home,
    passphrase: kv.passphrase,
    passphraseFile: kv.passphrase_file,
    environment: kv.environment !== 'false',
  };
  if (op === 'load') {
    const project = Project.load(kv.manifest, options);
    try {
      return [
        ['project.name', project.name],
        ['project.count', String(project.size)],
        ['project.names', [...project].map((s) => s.name).sort().join(',')],
        ...[...project].map((s) => [`secret.${s.env}`, s.value.exposeText()]),
      ];
    } finally {
      project.close();
    }
  }
  const reader = new SecretReader(vault, options);
  try {
    switch (op) {
      case 'open': {
        const d = reader.descriptor();
        return [['descriptor.name', d.name], ['descriptor.protectors', d.protectors.join(',')]];
      }
      case 'get':
        return secretLines(reader.get(kv.name, kv.version));
      case 'get-newest-explicit':
        return secretLines(reader.get(kv.name, reader.properties(kv.name).version));
      case 'properties':
        return propertiesLines(reader.properties(kv.name, kv.version));
      case 'resolve':
        return secretLines(reader.resolve(kv.reference));
      default:
        throw new Error(`unknown scenario op '${op}'`);
    }
  } finally {
    reader.close();
  }
}

let lines;
try {
  lines = [['outcome', 'ok'], ...run()];
} catch (err) {
  if (!(err instanceof SourceOrreryError)) throw err;
  lines = [
    ['outcome', 'error'],
    ['code', err.code],
    ['message', err.detail],
    ['hint', err.hint],
    ['transient', String(err.transient)],
    ['type', err.name],
  ];
}
for (const [key, value] of lines) process.stdout.write(`${key}\t${value}\n`);
