package sourceorrery

import "errors"

// Error is a failed read. Code is the core's stable, append-only code,
// Message says what went wrong and Hint what to do about it. errors.Is
// matches the sentinels below by code.
type Error struct {
	Code    string
	Message string
	Hint    string
}

// Error returns the message followed by the hint.
func (e *Error) Error() string {
	if e.Hint == "" {
		return e.Message
	}
	return e.Message + ". " + e.Hint
}

// Transient reports whether retrying later could succeed without
// administrative action.
func (e *Error) Transient() bool { return e.Code == "not_yet_valid" }

// Policy reports whether a version was refused by policy (disabled, not yet
// valid or expired).
func (e *Error) Policy() bool {
	return e.Code == "disabled" || e.Code == "not_yet_valid" || e.Code == "expired"
}

// Is matches the sentinel errors by code, so errors.Is(err, ErrNotFound) works.
func (e *Error) Is(target error) bool {
	sentinel, ok := target.(*sentinelError)
	if !ok {
		return false
	}
	if sentinel == ErrPolicy {
		return e.Policy()
	}
	if sentinel == ErrStorage {
		return e.Code == "storage" || e.Code == "io"
	}
	return sentinel.code == e.Code
}

type sentinelError struct{ code string }

func (s *sentinelError) Error() string { return "sourceorrery: " + s.code }

var (
	// ErrNotFound: no secret with that name.
	ErrNotFound error = &sentinelError{"not_found"}
	// ErrVersionNotFound: the secret exists but the version does not.
	ErrVersionNotFound error = &sentinelError{"version_not_found"}
	// ErrDeleted: the secret is soft-deleted; recover it before use.
	ErrDeleted error = &sentinelError{"deleted"}
	// ErrDisabled: the version is disabled.
	ErrDisabled error = &sentinelError{"disabled"}
	// ErrNotYetValid: the version's activation time has not been reached.
	ErrNotYetValid error = &sentinelError{"not_yet_valid"}
	// ErrExpired: the version's expiry time has passed.
	ErrExpired error = &sentinelError{"expired"}
	// ErrPolicy matches ErrDisabled, ErrNotYetValid and ErrExpired.
	ErrPolicy error = &sentinelError{"policy"}
	// ErrInvalidName: a secret or vault name breaks the naming rules.
	ErrInvalidName error = &sentinelError{"invalid_name"}
	// ErrInvalidArgument: a malformed reference, version or option.
	ErrInvalidArgument error = &sentinelError{"invalid_argument"}
	// ErrPermissionDenied: authenticated but not authorised.
	ErrPermissionDenied error = &sentinelError{"permission_denied"}
	// ErrLocked: no protector or passphrase source could unlock the vault.
	ErrLocked error = &sentinelError{"locked"}
	// ErrVaultNotFound: no vault file with that name in the home directory.
	ErrVaultNotFound error = &sentinelError{"vault_not_found"}
	// ErrMigrationRequired: run `sourceorrery vault migrate <name>` first.
	ErrMigrationRequired error = &sentinelError{"migration_required"}
	// ErrManifest: sourceorrery.toml is missing or invalid.
	ErrManifest error = &sentinelError{"manifest"}
	// ErrCrypto: the vault file failed an integrity check.
	ErrCrypto error = &sentinelError{"crypto"}
	// ErrStorage matches the storage and io codes: the vault file could not be read.
	ErrStorage error = &sentinelError{"storage"}
	// ErrUnsupported: no OS credential store here; use a passphrase.
	ErrUnsupported error = &sentinelError{"unsupported"}
)

// AsError returns err as *Error when it is one.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
