package ai.sourceorrery;

/** {@code disabled}: the version is disabled. */
public class SecretDisabledException extends PolicyException {
    private static final long serialVersionUID = 1L;

    public SecretDisabledException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
