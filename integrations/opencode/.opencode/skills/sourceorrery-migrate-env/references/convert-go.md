# Converting Go code

SDK: `go get github.com/netizine/sourceorrery/bindings/go@latest`. It is a
cgo binding: it needs a C compiler (gcc or clang; MinGW-w64 gcc on
Windows) and the native library from the `sourceorrery-ffi` archive of
the matching GitHub release, on the linker path (`CGO_LDFLAGS`) and at run
time (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH` or `PATH`):
https://sourceorrery.ai/sdks/go/

Projects built with `CGO_ENABLED=0` cannot use this SDK. Keep the
environment interface and provision variables at launch, using
`sourceorrery run --` on a compatible host or the deployment platform's
secret store. Do not assume the native CLI runs inside a `scratch` image.

## One package for every read

```go
// internal/secrets/secrets.go
package secrets

import (
	"fmt"
	"sync"

	sourceorrery "github.com/netizine/sourceorrery/bindings/go"
)

var (
	once    sync.Once
	project *sourceorrery.Project
	loadErr error
)

func load() (*sourceorrery.Project, error) {
	once.Do(func() { project, loadErr = sourceorrery.LoadProject("", nil) }) // nearest sourceorrery.toml
	return project, loadErr
}

// Get returns the value delivered as environment variable name.
func Get(name string) (string, error) {
	p, err := load()
	if err != nil {
		return "", err
	}
	value := p.Env(name)
	if value == nil {
		return "", fmt.Errorf("%s is not available from sourceorrery.toml", name)
	}
	return value.Text(), nil
}
```

## Replacements

| Before | After |
|--------|-------|
| `os.Getenv("DATABASE_URL")` | `secrets.Get("DATABASE_URL")`, handling the error |
| `v, ok := os.LookupEnv("X")` | `v, err := secrets.Get("X")`; `ok` is `err == nil` |
| `godotenv.Load()` | delete, once every key is covered |
| `envconfig.Process`, `viper.AutomaticEnv` | keep, and start under `sourceorrery run --`, or set the fields from `secrets.Get` |

Remove `github.com/joho/godotenv` with `go mod tidy` afterwards.

## Tests

`sourceorrery run -- go test ./...`, or let the code load the project.
