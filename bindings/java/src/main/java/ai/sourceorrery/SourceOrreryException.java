package ai.sourceorrery;

/**
 * A failed read. {@link #code()} is the core's stable, append-only code,
 * {@link #detail()} says what went wrong and {@link #hint()} what to do about
 * it; {@link #getMessage()} is both joined. None of them ever contains a
 * secret value. Subclasses exist for every code this version knows; a code
 * added later maps to this class and keeps its code.
 */
public class SourceOrreryException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;
    private final String detail;
    private final String hint;

    public SourceOrreryException(String message, String code, String hint) {
        super(hint == null || hint.isEmpty() ? message : message + ". " + hint);
        this.detail = message;
        this.code = code;
        this.hint = hint == null ? "" : hint;
    }

    /** Stable code ({@code not_found}, {@code locked}, ...). */
    public String code() {
        return code;
    }

    /** What went wrong, without the hint. */
    public String detail() {
        return detail;
    }

    /** What to do about it; empty when nothing specific applies. */
    public String hint() {
        return hint;
    }

    /** True when retrying later could succeed without administrative action. */
    public boolean isTransient() {
        return "not_yet_valid".equals(code);
    }

    /** The exception for a stable code. */
    public static SourceOrreryException forCode(String code, String message, String hint) {
        return switch (code) {
            case "vault_not_found" -> new VaultNotFoundException(message, code, hint);
            case "locked" -> new VaultLockedException(message, code, hint);
            case "migration_required" -> new MigrationRequiredException(message, code, hint);
            case "vault_mismatch" -> new VaultMismatchException(message, code, hint);
            case "not_found" -> new SecretNotFoundException(message, code, hint);
            case "version_not_found" -> new VersionNotFoundException(message, code, hint);
            case "deleted" -> new SecretDeletedException(message, code, hint);
            case "disabled" -> new SecretDisabledException(message, code, hint);
            case "not_yet_valid" -> new SecretNotYetValidException(message, code, hint);
            case "expired" -> new SecretExpiredException(message, code, hint);
            case "crypto" -> new IntegrityException(message, code, hint);
            case "unsupported" -> new UnsupportedException(message, code, hint);
            case "invalid_argument" -> new InvalidArgumentException(message, code, hint);
            case "invalid_name" -> new InvalidNameException(message, code, hint);
            case "manifest" -> new ManifestException(message, code, hint);
            case "permission_denied" -> new PermissionDeniedException(message, code, hint);
            case "storage", "io" -> new StorageException(message, code, hint);
            default -> new SourceOrreryException(message, code, hint);
        };
    }
}
