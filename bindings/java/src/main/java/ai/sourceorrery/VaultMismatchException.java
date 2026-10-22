package ai.sourceorrery;

/**
 * {@code vault_mismatch}: the file found for the vault holds another vault
 * (renamed, copied or swapped in); move it back or restore it from a backup.
 */
public class VaultMismatchException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public VaultMismatchException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
