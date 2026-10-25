package ai.sourceorrery;

/** {@code locked}: neither this machine's key nor a recovery key could open the vault. */
public class VaultLockedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public VaultLockedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
