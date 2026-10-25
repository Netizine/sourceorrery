package ai.sourceorrery;

/**
 * {@code migration_required}: the vault was written by an earlier release, which this one
 * cannot read; recreate it with {@code sourceorrery setup}.
 */
public class MigrationRequiredException extends SourceOrreryException {
    private static final long serialVersionUID = 1L;

    public MigrationRequiredException(String message, String code, String hint) {
        super(message, code, hint);
    }
}
