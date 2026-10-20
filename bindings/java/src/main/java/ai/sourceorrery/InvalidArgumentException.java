package ai.sourceorrery;

/** {@code invalid_argument}: a malformed reference, version or option. */
public class InvalidArgumentException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public InvalidArgumentException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
