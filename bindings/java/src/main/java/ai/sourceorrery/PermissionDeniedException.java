package ai.sourceorrery;

/** {@code permission_denied}: authenticated but not authorised. */
public class PermissionDeniedException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public PermissionDeniedException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
