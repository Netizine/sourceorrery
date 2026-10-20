package ai.sourceorrery;

/** {@code not_found}: no secret with that name. */
public class SecretNotFoundException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public SecretNotFoundException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
