package ai.sourceorrery;

/** {@code manifest}: sourceorrery.toml is missing or invalid. */
public class ManifestException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public ManifestException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
