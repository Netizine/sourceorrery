// Read one secret and report its size, never its value.
//
//	go get github.com/Netizine/sourceorrery/bindings/go
//	export SOURCEORRERY_PASSPHRASE=...   # or rely on the OS credential store
//	CGO_LDFLAGS="-L/path/to/sourceorrery_ffi" go run . development database-password
package main

import (
	"errors"
	"fmt"
	"os"

	sourceorrery "github.com/Netizine/sourceorrery/bindings/go"
)

func main() {
	vault, name := "development", "database-password"
	if len(os.Args) > 1 {
		vault = os.Args[1]
	}
	if len(os.Args) > 2 {
		name = os.Args[2]
	}
	if err := run(vault, name); err != nil {
		var soErr *sourceorrery.Error
		if errors.As(err, &soErr) {
			// soErr.Code is stable; Error() is the message plus a hint. No values.
			fmt.Fprintf(os.Stderr, "error [%s]: %v\n", soErr.Code, err)
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func run(vault, name string) error {
	// Unlocked by the OS credential store, then SOURCEORRERY_PASSPHRASE,
	// then SOURCEORRERY_PASSPHRASE_FILE; never a prompt.
	reader, err := sourceorrery.Open(vault, nil)
	if err != nil {
		return err
	}
	defer reader.Close()

	secret, err := reader.Get(name) // newest accessible version
	if err != nil {
		return err
	}
	defer secret.Close() // zeroises the value

	fmt.Printf("%s version %s from vault %s: %d bytes\n", name, secret.Properties.Version, vault, secret.Value.Len())
	return nil
}
