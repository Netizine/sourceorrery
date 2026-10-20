package ai.sourceorrery;

/** {@code invalid_name}: a secret or vault name breaks the naming rules. */
public class InvalidNameException extends InvalidArgumentException {
    private static final long serialVersionUID = 1L;

    public InvalidNameException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
