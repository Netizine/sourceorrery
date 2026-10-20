package ai.sourceorrery;

/** {@code migration_required}: run {@code sourceorrery vault migrate <name>} first. */
public class MigrationRequiredException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public MigrationRequiredException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
