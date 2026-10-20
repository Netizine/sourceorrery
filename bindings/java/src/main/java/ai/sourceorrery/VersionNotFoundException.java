package ai.sourceorrery;

/** {@code version_not_found}: the secret exists but the version does not. */
public class VersionNotFoundException extends SecretNotFoundException {
    private static final long serialVersionUID = 1L;

    public VersionNotFoundException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
