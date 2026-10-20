package ai.sourceorrery;

/** {@code not_yet_valid}: the version's activation time has not been reached. */
public class SecretNotYetValidException extends PolicyException {
    private static final long serialVersionUID = 1L;

    public SecretNotYetValidException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
