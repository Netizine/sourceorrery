package ai.sourceorrery;

/** {@code unsupported}: no OS credential store here; use a passphrase. */
public class UnsupportedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public UnsupportedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
