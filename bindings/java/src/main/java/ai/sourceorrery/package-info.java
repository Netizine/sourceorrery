/**
 * Read secrets from a SourceOrrery vault. Secrets belong to the runtime,
 * not the repository.
 *
 * <pre>{@code
 * try (SecretReader reader = SecretReader.open("development");
 *      Secret secret = reader.get("database-password")) {
 *     connect(secret.value().exposeText());
 * }
 * }</pre>
 *
 * <p>The package only reads: there is no way to create, change or delete a
 * secret, and no protector or audit management. Vaults are created, and
 * secrets stored, with the {@code sourceorrery} command-line tool, which is
 * installed separately and need not be present where the application runs
 * (<a href="https://sourceorrery.ai/getting-started/">Getting started</a>,
 * <a href="https://sourceorrery.ai/sdks/java/">the Java guide</a>).
 *
 * <p>The package binds the read-only part
 * of the SourceOrrery C ABI through the Foreign Function and Memory API
 * (Java 22+); run with {@code --enable-native-access=ALL-UNNAMED} (or grant
 * it to the module) to silence the restricted-method warning.
 *
 * <p>Every failure is a {@link ai.sourceorrery.SourceOrreryException} (or a
 * subclass chosen by the stable code) with a {@code code}, a {@code detail}
 * and a {@code hint}; none of them ever contains a secret value.
 */
package ai.sourceorrery;
