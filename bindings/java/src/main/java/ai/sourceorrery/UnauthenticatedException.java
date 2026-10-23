package ai.sourceorrery;

/** {@code unauthenticated}: the remote provider refused the process's credentials; give it the ones its own tools expect. */
public class UnauthenticatedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public UnauthenticatedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
