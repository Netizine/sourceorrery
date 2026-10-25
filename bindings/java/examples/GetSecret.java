// Read one secret and report its size, never its value.
//
//   <dependency><groupId>ai.sourceorrery</groupId><artifactId>sourceorrery</artifactId></dependency>
//   export SOURCEORRERY_RECOVERY_KEY=...   # or rely on the OS credential store
//   java --enable-native-access=ALL-UNNAMED -cp sourceorrery.jar GetSecret.java development database-password
import ai.sourceorrery.Secret;
import ai.sourceorrery.SecretReader;
import ai.sourceorrery.SourceOrreryException;

public class GetSecret {
    public static void main(String[] args) {
        String vault = args.length > 0 ? args[0] : "development";
        String name = args.length > 1 ? args[1] : "database-password";
        try (SecretReader reader = SecretReader.open(vault);      // OS credential store, then the environment
             Secret secret = reader.get(name)) {                  // newest accessible version; closed = zeroised
            System.out.printf("%s version %s from vault %s: %d bytes%n",
                    name, secret.properties().version(), vault, secret.value().length());
        } catch (SourceOrreryException err) {
            // err.code() is stable; getMessage() is the detail plus a hint. No values.
            System.err.printf("error [%s]: %s%n", err.code(), err.getMessage());
            System.exit(1);
        }
    }
}
