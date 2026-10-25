package ai.sourceorrery;

/** {@code unsupported}: no OS credential store here (use the vault's recovery key), or a remote provider this build does not include. */
public class UnsupportedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public UnsupportedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
