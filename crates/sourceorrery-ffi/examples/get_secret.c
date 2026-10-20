/*
 * Read one secret through the read-only C ABI. This is the C SDK: it links
 * only so_reader_* functions, so a program built like this cannot write to
 * a vault.
 *
 * Build after `cargo build -p sourceorrery-ffi --release`, from the
 * repository root:
 *
 *   Linux / macOS:
 *     cc -Wall -Wextra -Werror -I crates/sourceorrery-ffi/include \
 *        crates/sourceorrery-ffi/examples/get_secret.c \
 *        -L target/release -lsourceorrery_ffi -o get_secret
 *   Windows (MSVC):
 *     cl /W4 /WX /I crates\sourceorrery-ffi\include crates\sourceorrery-ffi\examples\get_secret.c ^
 *        /link target\release\sourceorrery_ffi.dll.lib
 *
 * Run: get_secret [VAULT] [SECRET]. The vault is unlocked by the OS
 * credential store, then SOURCEORRERY_PASSPHRASE, then
 * SOURCEORRERY_PASSPHRASE_FILE; SOURCEORRERY_HOME selects the home
 * directory. Nothing printed here is ever the value.
 */
#include <stdio.h>
#include <string.h>

#include "sourceorrery.h"

static int fail(const char *what) {
    const char *hint = so_last_error_hint();
    fprintf(stderr, "%s failed [%s]: %s\n", what, so_last_error_code(), so_last_error_message());
    if (hint != NULL) {
        fprintf(stderr, "  %s\n", hint);
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *vault = argc > 1 ? argv[1] : "development";
    const char *name = argc > 2 ? argv[2] : "database-password";
    so_reader *reader = NULL;
    so_bytes properties = {NULL, 0};
    so_bytes value = {NULL, 0};
    int rc = 0;

    /* NULL options: SOURCEORRERY_HOME and the environment passphrase sources. */
    if (so_reader_open((const uint8_t *)vault, strlen(vault), NULL, 0, NULL, 0, &reader) != SO_STATUS_OK) {
        return fail("so_reader_open");
    }

    /* NULL version: the newest accessible version. */
    if (so_reader_get(reader, (const uint8_t *)name, strlen(name), NULL, 0, &properties, &value) != SO_STATUS_OK) {
        rc = fail("so_reader_get");
        goto done;
    }

    /* Use value.ptr / value.len here, then free it: so_bytes_free zeroises. */
    printf("%s from vault %s: %zu bytes, properties %s\n", name, vault, value.len, (const char *)properties.ptr);
    so_bytes_free(&value);
    so_bytes_free(&properties);

done:
    so_reader_close(reader);
    return rc;
}
