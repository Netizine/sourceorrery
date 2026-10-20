package ai.sourceorrery;

/**
 * One secret resolved from {@code sourceorrery.toml}.
 *
 * @param name name as written in the manifest
 * @param env environment variable the manifest delivers it in
 * @param reference the reference that was resolved
 * @param required whether the manifest marks it required
 * @param properties metadata of the version that was read
 * @param value the value
 */
public record ProjectSecret(
        String name,
        String env,
        String reference,
        boolean required,
        SecretProperties properties,
        SecretValue value) {}
