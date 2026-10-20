package ai.sourceorrery;

/** {@code storage} / {@code io}: the vault file could not be read. */
public class StorageException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public StorageException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
