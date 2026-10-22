// Package sourceorrery reads secrets from a SourceOrrery vault.
// Secrets belong to the runtime, not the repository.
//
//	reader, err := sourceorrery.Open("development", nil)
//	if err != nil { ... }
//	defer reader.Close()
//	secret, err := reader.Get("database-password")
//	if err != nil { ... }
//	defer secret.Value.Close()
//	connect(secret.Value.Text())
//
// The package only reads: there is no way to create, change or delete a
// secret, and no protector or audit management. Vaults are created, and
// secrets stored, with the sourceorrery command-line tool, which is
// installed separately and need not be present where the program runs; see
// https://sourceorrery.ai/getting-started/ and the Go guide at
// https://sourceorrery.ai/sdks/go/.
//
// The package is a cgo binding over the read-only part of the SourceOrrery
// C ABI (sourceorrery.h, shipped in this directory); build with the
// `sourceorrery_ffi` library, from the sourceorrery-ffi archive on the
// GitHub release, on the linker path, for example:
//
//	CGO_LDFLAGS="-L/path/to/lib" go build ./...
//
// On Windows (MinGW-w64 gcc) the directory must hold sourceorrery_ffi.dll,
// which is linked directly, and the DLL must be on PATH at run time.
//
// Every failure is a *Error carrying the core's stable Code, a Message and a
// Hint that says what to do; errors.Is matches the sentinel errors in
// errors.go. None of them ever contains a secret value.
package sourceorrery

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo !windows LDFLAGS: -lsourceorrery_ffi
// On Windows the library is built with MSVC. MinGW's ld would pick the MSVC
// static archive (sourceorrery_ffi.lib) for -lsourceorrery_ffi and fail on
// its MSVC-only symbols, so the DLL is linked directly by file name.
#cgo windows LDFLAGS: -l:sourceorrery_ffi.dll
#include <stdlib.h>
#include "sourceorrery.h"
*/
import "C"

import (
	"encoding/json"
	"runtime"
	"time"
	"unsafe"
)

// OpenOptions says how to find and unlock a vault. The zero value reproduces
// the CLI: vaults under SOURCEORRERY_HOME, unlocked by the OS credential
// store, then SOURCEORRERY_PASSPHRASE, then SOURCEORRERY_PASSPHRASE_FILE.
type OpenOptions struct {
	// Home is the directory holding the vaults/ folder; empty honours SOURCEORRERY_HOME.
	Home string
	// Passphrase is tried before the environment sources. Wipe it after use.
	Passphrase []byte
	// PassphraseFile holds the passphrase; replaces SOURCEORRERY_PASSPHRASE_FILE.
	PassphraseFile string
	// IgnoreEnvironment skips SOURCEORRERY_PASSPHRASE and SOURCEORRERY_PASSPHRASE_FILE.
	IgnoreEnvironment bool
}

type readerOptionsJSON struct {
	Home           string `json:"home,omitempty"`
	PassphraseFile string `json:"passphrase_file,omitempty"`
	Environment    bool   `json:"environment"`
}

func (o *OpenOptions) json() []byte {
	opts := OpenOptions{}
	if o != nil {
		opts = *o
	}
	text, _ := json.Marshal(readerOptionsJSON{
		Home:           opts.Home,
		PassphraseFile: opts.PassphraseFile,
		Environment:    !opts.IgnoreEnvironment,
	})
	return text
}

func (o *OpenOptions) passphrase() []byte {
	if o == nil {
		return nil
	}
	return o.Passphrase
}

// SecretProperties is the metadata of one version. It never contains the value.
type SecretProperties struct {
	Vault         string            `json:"vault"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Enabled       bool              `json:"enabled"`
	ContentType   string            `json:"content_type,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	NotBefore     *time.Time        `json:"not_before,omitempty"`
	ExpiresOn     *time.Time        `json:"expires_on,omitempty"`
	CreatedOn     time.Time         `json:"created_on"`
	UpdatedOn     time.Time         `json:"updated_on"`
	RecoveryLevel string            `json:"recovery_level"`
}

// Reference is sourceorrery://vault/name/version for exactly this version.
func (p SecretProperties) Reference() string {
	return "sourceorrery://" + p.Vault + "/" + p.Name + "/" + p.Version
}

// Secret is a version's metadata and its value.
type Secret struct {
	Properties SecretProperties
	Value      *SecretValue
}

// Close zeroises the value.
func (s *Secret) Close() { s.Value.Close() }

// VaultDescriptor is a non-sensitive description of a vault.
type VaultDescriptor struct {
	Name          string    `json:"name"`
	ID            string    `json:"id"`
	Backend       string    `json:"backend"`
	Path          string    `json:"path,omitempty"`
	CreatedOn     time.Time `json:"created_on"`
	RecoveryLevel string    `json:"recovery_level"`
	RetentionDays uint32    `json:"retention_days"`
	Protectors    []string  `json:"protectors"`
}

// Reader is a read-only handle on one vault. It may be used from several
// goroutines at once. Close zeroises the vault key held in memory.
type Reader struct {
	handle *readerHandle
	vault  string
}

// readerHandle is a separate allocation so that a GC cleanup can own it:
// Close clears ptr, and the cleanup then has nothing left to free.
type readerHandle struct {
	ptr *C.so_reader
}

func (h *readerHandle) close() {
	if h.ptr != nil {
		C.so_reader_close(h.ptr)
		h.ptr = nil
	}
}

// Open opens vault with the given options (nil: the CLI's defaults). The
// unlock order is the OS credential store, opts.Passphrase,
// SOURCEORRERY_PASSPHRASE, then opts.PassphraseFile or
// SOURCEORRERY_PASSPHRASE_FILE. It never prompts.
func Open(vault string, opts *OpenOptions) (*Reader, error) {
	optionsJSON := opts.json()
	passphrase := opts.passphrase()
	var handle *C.so_reader
	err := call(func() C.so_status {
		return C.so_reader_open(
			bytesPtr([]byte(vault)), C.size_t(len(vault)),
			bytesPtr(optionsJSON), C.size_t(len(optionsJSON)),
			bytesPtr(passphrase), C.size_t(len(passphrase)),
			&handle)
	})
	if err != nil {
		return nil, err
	}
	reader := &Reader{handle: &readerHandle{ptr: handle}, vault: vault}
	runtime.AddCleanup(reader, (*readerHandle).close, reader.handle)
	return reader, nil
}

// VaultName is the name of the vault this reader is bound to.
func (r *Reader) VaultName() string { return r.vault }

// Get returns the newest accessible version of name: enabled and inside its
// not_before / expires_on window. When none is accessible the error explains
// why the newest version was refused.
func (r *Reader) Get(name string) (*Secret, error) { return r.get(name, "") }

// GetVersion returns exactly version of name, or a policy error if that
// version is disabled or outside its time window.
func (r *Reader) GetVersion(name, version string) (*Secret, error) {
	return r.get(name, version)
}

func (r *Reader) get(name, version string) (*Secret, error) {
	handle, err := r.require()
	if err != nil {
		return nil, err
	}
	var props, value C.so_bytes
	err = call(func() C.so_status {
		return C.so_reader_get(handle,
			bytesPtr([]byte(name)), C.size_t(len(name)),
			bytesPtr([]byte(version)), C.size_t(len(version)),
			&props, &value)
	})
	runtime.KeepAlive(r)
	if err != nil {
		return nil, err
	}
	return newSecret(&props, &value)
}

// Properties returns metadata of one version (version "": the newest).
// Policy is not applied, so disabled and expired versions can be inspected.
func (r *Reader) Properties(name, version string) (SecretProperties, error) {
	var properties SecretProperties
	handle, err := r.require()
	if err != nil {
		return properties, err
	}
	var props C.so_bytes
	err = call(func() C.so_status {
		return C.so_reader_properties(handle,
			bytesPtr([]byte(name)), C.size_t(len(name)),
			bytesPtr([]byte(version)), C.size_t(len(version)),
			&props)
	})
	runtime.KeepAlive(r)
	if err != nil {
		return properties, err
	}
	err = json.Unmarshal(takeBytes(&props), &properties)
	return properties, err
}

// Resolve resolves sourceorrery://vault/name[/version]; the reference must
// name this reader's vault.
func (r *Reader) Resolve(reference string) (*Secret, error) {
	handle, err := r.require()
	if err != nil {
		return nil, err
	}
	var props, value C.so_bytes
	err = call(func() C.so_status {
		return C.so_reader_resolve(handle,
			bytesPtr([]byte(reference)), C.size_t(len(reference)),
			&props, &value)
	})
	runtime.KeepAlive(r)
	if err != nil {
		return nil, err
	}
	return newSecret(&props, &value)
}

// Descriptor returns a non-sensitive description of the vault.
func (r *Reader) Descriptor() (VaultDescriptor, error) {
	var descriptor VaultDescriptor
	handle, err := r.require()
	if err != nil {
		return descriptor, err
	}
	var out C.so_bytes
	err = call(func() C.so_status { return C.so_reader_descriptor(handle, &out) })
	runtime.KeepAlive(r)
	if err != nil {
		return descriptor, err
	}
	err = json.Unmarshal(takeBytes(&out), &descriptor)
	return descriptor, err
}

// Close releases the vault. Idempotent. The reader must not be in use by
// another goroutine at the time of the call.
func (r *Reader) Close() error {
	r.handle.close()
	return nil
}

// Closed reports whether Close has run.
func (r *Reader) Closed() bool { return r.handle.ptr == nil }

func (r *Reader) require() (*C.so_reader, error) {
	if r.handle.ptr == nil {
		return nil, &Error{Code: "invalid_argument", Message: "reader is closed"}
	}
	return r.handle.ptr, nil
}

// SecretValue holds a value in native memory until Close zeroises it.
// Bytes and Text return copies the application owns. String and
// MarshalJSON print [REDACTED].
type SecretValue struct {
	// A separate allocation owned by the GC cleanup as well: so_bytes_free
	// resets it to the empty buffer, so a Close followed by the cleanup (or
	// the reverse) frees nothing twice.
	bytes *C.so_bytes
}

func newValue(bytes *C.so_bytes) *SecretValue {
	owned := new(C.so_bytes)
	*owned = *bytes
	*bytes = C.so_bytes{}
	value := &SecretValue{bytes: owned}
	runtime.AddCleanup(value, func(b *C.so_bytes) { C.so_bytes_free(b) }, owned)
	return value
}

// Bytes returns a copy of the value.
func (v *SecretValue) Bytes() []byte {
	if v.bytes.ptr == nil {
		return nil
	}
	copy := C.GoBytes(unsafe.Pointer(v.bytes.ptr), C.int(v.bytes.len))
	runtime.KeepAlive(v)
	return copy
}

// Text returns the value decoded as UTF-8 (a copy).
func (v *SecretValue) Text() string { return string(v.Bytes()) }

// Len is the length in bytes; 0 once closed.
func (v *SecretValue) Len() int { return int(v.bytes.len) }

// Closed reports whether Close has run.
func (v *SecretValue) Closed() bool { return v.bytes.ptr == nil }

// Close zeroises and frees the native bytes. Idempotent.
func (v *SecretValue) Close() {
	C.so_bytes_free(v.bytes)
	runtime.KeepAlive(v)
}

// String returns [REDACTED].
func (v *SecretValue) String() string { return "[REDACTED]" }

// MarshalJSON writes "[REDACTED]" so a value cannot leak through encoding/json.
func (v *SecretValue) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// GoString returns [REDACTED] for %#v.
func (v *SecretValue) GoString() string { return "sourceorrery.SecretValue{[REDACTED]}" }

func newSecret(props, value *C.so_bytes) (*Secret, error) {
	secret := &Secret{Value: newValue(value)}
	if err := json.Unmarshal(takeBytes(props), &secret.Properties); err != nil {
		secret.Value.Close()
		return nil, err
	}
	return secret, nil
}

// ContractVersion is the contract version of the core the loaded library implements.
func ContractVersion() string { return C.GoString(C.so_contract_version()) }

// AbiVersion is the version of the C ABI the loaded library was built with.
func AbiVersion() uint32 { return uint32(C.so_abi_version()) }

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// takeBytes copies a buffer out and frees it.
func takeBytes(b *C.so_bytes) []byte {
	if b.ptr == nil {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(b.ptr), C.int(b.len))
	C.so_bytes_free(b)
	return out
}

// call runs one C ABI call and reads its error state on the same OS thread:
// the state is per thread, and a goroutine may otherwise migrate between the
// call and the read.
func call(f func() C.so_status) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status := f()
	if status == C.SO_STATUS_OK {
		return nil
	}
	code := C.GoString(C.so_last_error_code())
	if code == "" {
		if status == C.SO_STATUS_PANIC {
			code = "internal"
		} else {
			code = "unknown"
		}
	}
	return &Error{
		Code:    code,
		Message: C.GoString(C.so_last_error_message()),
		Hint:    C.GoString(C.so_last_error_hint()),
	}
}
