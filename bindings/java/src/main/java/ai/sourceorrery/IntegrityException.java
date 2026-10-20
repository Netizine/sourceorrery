package ai.sourceorrery;

/** {@code crypto}: the vault file failed an integrity check. */
public class IntegrityException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public IntegrityException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
