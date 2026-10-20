// Read one secret and report its size, never its value.
//
//   npm install @sourceorrery/sdk
//   export SOURCEORRERY_PASSPHRASE=...   # or rely on the OS credential store
//   node get-secret.mjs development database-password
import { SecretReader, SourceOrreryError } from '@sourceorrery/sdk';

const [vault = 'development', name = 'database-password'] = process.argv.slice(2);

try {
  const reader = new SecretReader(vault);
  try {
    const secret = reader.get(name);
    try {
      console.log(`${name} version ${secret.properties.version} from vault ${vault}: ${secret.value.length} bytes`);
    } finally {
      secret.close(); // zeroises the value
    }
  } finally {
    reader.close();
  }
} catch (err) {
  if (err instanceof SourceOrreryError) {
    // err.code is stable; err.message is the detail plus a hint. No values.
    console.error(`error [${err.code}]: ${err.message}`);
    process.exit(1);
  }
  throw err;
}
