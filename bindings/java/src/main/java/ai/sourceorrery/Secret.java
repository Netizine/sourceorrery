package ai.sourceorrery;

/**
 * A version's metadata and its value. Closing it zeroises the value.
 *
 * @param properties metadata
 * @param value the value
 */
public record Secret(SecretProperties properties, SecretValue value) implements AutoCloseable {
    @Override
    public void close() {
        value.close();
    }
}
