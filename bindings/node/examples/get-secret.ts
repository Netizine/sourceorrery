// Read one secret and report its size, never its value (TypeScript).
//
//   npm install @sourceorrery/sdk
//   export SOURCEORRERY_PASSPHRASE=...   # or rely on the OS credential store
//   node --experimental-strip-types get-secret.ts development database-password
//
// On Node 24+ (or with a bundler) `using reader = new SecretReader(vault)`
// closes the reader and zeroises values at the end of the block; the
// try/finally below is the equivalent that runs on Node 22.
import { SecretReader, SourceOrreryError, type Secret } from '@sourceorrery/sdk';

const [vault = 'development', name = 'database-password'] = process.argv.slice(2);

try {
  const reader = new SecretReader(vault);
  try {
    const secret: Secret = reader.get(name);
    try {
      console.log(`${name} version ${secret.properties.version} from vault ${vault}: ${secret.value.length} bytes`);
    } finally {
      secret.close();
    }
  } finally {
    reader.close();
  }
} catch (err: unknown) {
  if (err instanceof SourceOrreryError) {
    // err.code is stable; err.message is the detail plus a hint. No values.
    console.error(`error [${err.code}]: ${err.message}`);
    process.exit(1);
  }
  throw err;
}
