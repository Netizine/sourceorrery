package ai.sourceorrery;

/** {@code locked}: no protector or passphrase source could unlock the vault. */
public class VaultLockedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public VaultLockedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
