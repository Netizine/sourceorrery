package ai.sourceorrery;

/** A version refused by policy: disabled, not yet valid or expired. */
public class PolicyException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public PolicyException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
