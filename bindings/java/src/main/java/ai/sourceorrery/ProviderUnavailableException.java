package ai.sourceorrery;

/** {@code provider_unavailable}: the remote provider could not be reached; transient, so the call can be retried. */
public class ProviderUnavailableException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public ProviderUnavailableException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
