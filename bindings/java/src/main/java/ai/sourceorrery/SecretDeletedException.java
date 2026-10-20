package ai.sourceorrery;

/** {@code deleted}: the secret is soft-deleted; recover it before use. */
public class SecretDeletedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public SecretDeletedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
