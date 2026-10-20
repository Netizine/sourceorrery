package ai.sourceorrery;

/** {@code vault_not_found}: no vault file with that name in the home directory. */
public class VaultNotFoundException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public VaultNotFoundException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
