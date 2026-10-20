package ai.sourceorrery;

/** {@code expired}: the version's expiry time has passed. */
public class SecretExpiredException extends PolicyException {
    private static final long serialVersionUID = 1L;

    public SecretExpiredException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
