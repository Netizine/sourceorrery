// The Go SDK against the vault created by scripts/ci/fixture-vault.sh.
package sourceorrery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	home, recoveryKey, vault, manifest, oldVersion string
}

const (
	latestValue = "ci-secret-value"
	firstValue  = "first-version"
)

func loadFixture(t *testing.T) fixture {
	t.Helper()
	get := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Skipf("%s is not set; run scripts/ci/fixture-vault.sh first", name)
		}
		return value
	}
	return fixture{
		home:        get("SOURCEORRERY_HOME"),
		recoveryKey: get("SOURCEORRERY_RECOVERY_KEY"),
		vault:       get("SOURCEORRERY_TEST_VAULT"),
		manifest:    get("SOURCEORRERY_TEST_MANIFEST"),
		oldVersion:  get("SOURCEORRERY_TEST_OLD_VERSION"),
	}
}

// Unlocks through SOURCEORRERY_RECOVERY_KEY from the environment, like the CLI.
func openReader(t *testing.T, fx fixture) *Reader {
	t.Helper()
	reader, err := Open(fx.vault, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { reader.Close() })
	return reader
}

func mustGet(t *testing.T, secret *Secret, err error) *Secret {
	t.Helper()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	t.Cleanup(secret.Close)
	return secret
}

func get(t *testing.T, reader *Reader, name string) *Secret {
	t.Helper()
	secret, err := reader.Get(name)
	return mustGet(t, secret, err)
}

func getVersion(t *testing.T, reader *Reader, name, version string) *Secret {
	t.Helper()
	secret, err := reader.GetVersion(name, version)
	return mustGet(t, secret, err)
}

func resolve(t *testing.T, reader *Reader, reference string) *Secret {
	t.Helper()
	secret, err := reader.Resolve(reference)
	return mustGet(t, secret, err)
}

func expectErr(t *testing.T, err error, sentinel error, code string, hintContains string) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	e, ok := AsError(err)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if e.Code != code {
		t.Fatalf("expected code %s, got %s (%v)", code, e.Code, err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("errors.Is(%v, %v) is false", err, sentinel)
	}
	if hintContains != "" && !strings.Contains(e.Hint, hintContains) {
		t.Fatalf("hint %q does not contain %q", e.Hint, hintContains)
	}
	return e
}

func TestContractVersion(t *testing.T) {
	if ContractVersion() != "2" || AbiVersion() != 2 {
		t.Fatalf("unexpected versions %s / %d", ContractVersion(), AbiVersion())
	}
}

func TestGetReturnsTheNewestAccessibleVersion(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	secret := get(t, reader, "database-password")
	if secret.Value.Text() != latestValue || string(secret.Value.Bytes()) != latestValue || secret.Value.Len() != len(latestValue) {
		t.Fatalf("unexpected value")
	}
	p := secret.Properties
	if p.Name != "database-password" || p.Vault != fx.vault || !p.Enabled || p.ContentType != "text/plain" || p.Tags["env"] != "ci" {
		t.Fatalf("unexpected properties %+v", p)
	}
	if p.CreatedOn.After(time.Now()) || p.CreatedOn.IsZero() {
		t.Fatalf("unexpected created_on %v", p.CreatedOn)
	}
	if p.Reference() != fmt.Sprintf("sourceorrery://%s/database-password/%s", fx.vault, p.Version) {
		t.Fatalf("unexpected reference %s", p.Reference())
	}
	secret.Close()
	if !secret.Value.Closed() || secret.Value.Len() != 0 || secret.Value.Bytes() != nil {
		t.Fatalf("value not closed")
	}
	secret.Close() // idempotent
}

func TestExplicitVersionsAndProperties(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	old := getVersion(t, reader, "database-password", fx.oldVersion)
	if old.Value.Text() != firstValue || old.Properties.Version != fx.oldVersion {
		t.Fatalf("unexpected old version")
	}
	props, err := reader.Properties("database-password", fx.oldVersion)
	if err != nil || props.Version != fx.oldVersion {
		t.Fatalf("properties: %v %+v", err, props)
	}
	newest, err := reader.Properties("database-password", "")
	if err != nil || newest.Version == fx.oldVersion {
		t.Fatalf("newest: %v %+v", err, newest)
	}
}

func TestReferencesResolveWithinTheVault(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	if resolve(t, reader, "sourceorrery://"+fx.vault+"/database-password").Value.Text() != latestValue {
		t.Fatalf("latest by reference")
	}
	if resolve(t, reader, "sourceorrery://"+fx.vault+"/database-password/"+fx.oldVersion).Value.Text() != firstValue {
		t.Fatalf("pinned by reference")
	}
	_, err := reader.Resolve("sourceorrery://other-vault/database-password")
	expectErr(t, err, ErrInvalidArgument, "invalid_argument", "")
	_, err = reader.Resolve("not-a-reference")
	expectErr(t, err, ErrInvalidArgument, "invalid_argument", "sourceorrery://vault/name")
}

func TestDisabledNewestVersionFallsBack(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	if get(t, reader, "rotated-key").Value.Text() != "old" {
		t.Fatalf("fallback")
	}
	newest, err := reader.Properties("rotated-key", "")
	if err != nil || newest.Enabled {
		t.Fatalf("newest should be disabled: %v %+v", err, newest)
	}
	_, err = reader.GetVersion("rotated-key", newest.Version)
	e := expectErr(t, err, ErrDisabled, "disabled", "--enable")
	if !e.Policy() || !errors.Is(err, ErrPolicy) {
		t.Fatalf("disabled is a policy error")
	}
}

func TestPolicyErrorsExplainThemselves(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	_, err := reader.Get("expired-token")
	e := expectErr(t, err, ErrExpired, "expired", "Policy")
	if e.Transient() {
		t.Fatalf("expired is not transient")
	}
	_, err = reader.Get("future-token")
	if e := expectErr(t, err, ErrNotYetValid, "not_yet_valid", ""); !e.Transient() {
		t.Fatalf("not_yet_valid is transient")
	}
	_, err = reader.Get("deleted-secret")
	expectErr(t, err, ErrDeleted, "deleted", "secret recover deleted-secret")
}

func TestMissingSecretsSayHowToStoreThem(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	_, err := reader.Get("missing")
	e := expectErr(t, err, ErrNotFound, "not_found", "sourceorrery secret set missing --vault "+fx.vault)
	if e.Message != "secret 'missing' was not found" || !strings.HasPrefix(err.Error(), e.Message+". ") {
		t.Fatalf("unexpected message %q / %q", e.Message, err.Error())
	}
	_, err = reader.GetVersion("database-password", "deadbeef")
	expectErr(t, err, ErrVersionNotFound, "version_not_found", "secret versions database-password")
	_, err = reader.Get("bad_name")
	expectErr(t, err, ErrInvalidName, "invalid_name", "")
}

func TestVaultErrorsSayHowToFixThem(t *testing.T) {
	fx := loadFixture(t)
	_, err := Open("no-such-vault", nil)
	e := expectErr(t, err, ErrVaultNotFound, "vault_not_found", "sourceorrery vault create no-such-vault")
	if !strings.Contains(e.Hint, fx.home) {
		t.Fatalf("hint should name the home directory: %s", e.Hint)
	}
	_, err = Open(fx.vault, &OpenOptions{RecoveryKey: []byte("wrong-recovery-key"), IgnoreEnvironment: true})
	e = expectErr(t, err, ErrLocked, "locked", "recovery_key option: tried")
	if !strings.Contains(e.Hint, "SOURCEORRERY_RECOVERY_KEY: not set") || !strings.Contains(e.Hint, "sourceorrery vault create "+fx.vault) || strings.Contains(err.Error(), "wrong-recovery-key") {
		t.Fatalf("unexpected locked error: %v", err)
	}
	reader, err := Open(fx.vault, &OpenOptions{Home: fx.home, RecoveryKey: []byte(fx.recoveryKey), IgnoreEnvironment: true})
	if err != nil {
		t.Fatalf("explicit open: %v", err)
	}
	descriptor, err := reader.Descriptor()
	if err != nil || descriptor.Name != fx.vault || len(descriptor.Protectors) == 0 || descriptor.Protectors[0] != "recovery" {
		t.Fatalf("descriptor: %v %+v", err, descriptor)
	}
	if reader.VaultName() != fx.vault {
		t.Fatalf("vault name")
	}
	reader.Close()
	if !reader.Closed() {
		t.Fatalf("closed")
	}
	if _, err := reader.Get("database-password"); err == nil {
		t.Fatalf("closed reader must fail")
	}
	reader.Close()
}

func TestSecretValuesDoNotLeak(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	secret := get(t, reader, "database-password")
	if secret.Value.String() != "[REDACTED]" || fmt.Sprint(secret.Value) != "[REDACTED]" || fmt.Sprintf("%v", secret.Value) != "[REDACTED]" {
		t.Fatalf("String must redact")
	}
	if !strings.Contains(fmt.Sprintf("%#v", secret.Value), "[REDACTED]") {
		t.Fatalf("GoString must redact")
	}
	encoded, err := json.Marshal(secret)
	if err != nil || strings.Contains(string(encoded), latestValue) || !strings.Contains(string(encoded), `"[REDACTED]"`) {
		t.Fatalf("json must redact: %v %s", err, encoded)
	}
	if strings.Contains(fmt.Sprintf("%+v", secret), latestValue) {
		t.Fatalf("%%+v must redact")
	}
}

func TestReaderIsSafeForConcurrentUse(t *testing.T) {
	fx := loadFixture(t)
	reader := openReader(t, fx)
	var wg sync.WaitGroup
	failures := make(chan error, 64)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				secret, err := reader.Get("database-password")
				if err != nil {
					failures <- err
					return
				}
				if secret.Value.Text() != latestValue {
					failures <- errors.New("wrong value")
				}
				secret.Close()
			}
			if _, err := reader.Get("missing"); !errors.Is(err, ErrNotFound) {
				failures <- fmt.Errorf("expected not_found, got %v", err)
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestProjectLoadMirrorsRun(t *testing.T) {
	fx := loadFixture(t)
	project, err := LoadProject(fx.manifest, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if project.Name != "ci-project" || !strings.HasSuffix(project.ManifestPath, "sourceorrery.toml") || len(project.Secrets) != 2 {
		t.Fatalf("unexpected project %+v", project)
	}
	if project.Env("DATABASE_PASSWORD").Text() != latestValue || project.Env("ROTATED").Text() != "old" {
		t.Fatalf("values")
	}
	if project.Get("missing-optional") != nil || project.Get("expired-token") != nil {
		t.Fatalf("optional misses must be skipped")
	}
	entry := project.Get("rotated-key")
	if entry == nil || !entry.Required || entry.Env != "ROTATED" || entry.Reference != "sourceorrery://"+fx.vault+"/rotated-key" {
		t.Fatalf("unexpected entry %+v", entry)
	}
	project.Close()
	if !project.Env("ROTATED").Closed() {
		t.Fatalf("close")
	}
	_, err = LoadProject(fx.manifest+".missing", nil)
	expectErr(t, err, ErrManifest, "manifest", "")
	_, err = LoadProject(fx.manifest, &OpenOptions{RecoveryKey: []byte("wrong"), IgnoreEnvironment: true})
	expectErr(t, err, ErrLocked, "locked", "")
}

func TestRemoteProviderCodesMapToSentinels(t *testing.T) {
	cases := []struct {
		code      string
		sentinel  error
		transient bool
	}{
		{"unauthenticated", ErrUnauthenticated, false},
		{"provider_unavailable", ErrProviderUnavailable, true},
	}
	for _, tc := range cases {
		err := &Error{Code: tc.code, Message: "m", Hint: "h"}
		if !errors.Is(err, tc.sentinel) || errors.Is(err, ErrUnsupported) || errors.Is(err, ErrPolicy) {
			t.Fatalf("%s: sentinel mismatch", tc.code)
		}
		if err.Transient() != tc.transient || err.Policy() {
			t.Fatalf("%s: transient=%v policy=%v", tc.code, err.Transient(), err.Policy())
		}
	}
}

func TestUnknownCodesKeepTheirCode(t *testing.T) {
	err := &Error{Code: "brand_new_code", Message: "m", Hint: "h"}
	if err.Error() != "m. h" || errors.Is(err, ErrNotFound) {
		t.Fatalf("unexpected %v", err)
	}
	if !errors.Is(&Error{Code: "io"}, ErrStorage) {
		t.Fatalf("io matches ErrStorage")
	}
}

// An SDK built against one C ABI version refuses a library built for another
// with a typed error (ADR 0007); the installed library matches.
func TestAbiMismatchIsATypedError(t *testing.T) {
	if err := abiError(AbiVersion()); err != nil {
		t.Fatalf("matching ABI version reported %v", err)
	}
	if err := requireAbi(); err != nil {
		t.Fatalf("the installed library was refused: %v", err)
	}
	err := abiError(AbiVersion() + 1)
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if typed.Code != "abi_mismatch" {
		t.Fatalf("code %q", typed.Code)
	}
	for _, want := range []string{fmt.Sprint(AbiVersion() + 1), fmt.Sprint(AbiVersion()), "sourceorrery-ffi"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q lacks %q", err.Error(), want)
		}
	}
}
