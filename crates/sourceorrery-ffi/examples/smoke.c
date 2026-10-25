/*
 * Minimal C caller of the SourceOrrery C ABI: create a vault (its recovery
 * key is returned and released at once), store a secret, read it back, check
 * an error code, close.
 *
 * Build after `cargo build -p sourceorrery-ffi`, from the repository root:
 *
 *   Windows (MSVC):
 *     cl /W4 /WX /I crates\sourceorrery-ffi\include crates\sourceorrery-ffi\examples\smoke.c ^
 *        /link target\debug\sourceorrery_ffi.dll.lib
 *   Linux / macOS:
 *     cc -Wall -Wextra -Werror -I crates/sourceorrery-ffi/include \
 *        crates/sourceorrery-ffi/examples/smoke.c -L target/debug -lsourceorrery_ffi -o smoke
 *
 * Run with a scratch home directory as the only argument. The vault keeps no
 * key in the OS credential store ("this_machine": false), so the example
 * leaves nothing behind there.
 */
#include <stdio.h>
#include <string.h>

#include "sourceorrery.h"

static int fail(const char *what) {
    fprintf(stderr, "%s failed: %s: %s\n", what, so_last_error_code(), so_last_error_message());
    return 1;
}

static const uint8_t *text(const char *s) {
    return (const uint8_t *)s;
}

int main(int argc, char **argv) {
    const char *home = argc > 1 ? argv[1] : NULL; /* NULL: SOURCEORRERY_HOME or the platform default */
    const char *name = "smoke";
    const char *create_options = "{\"this_machine\":false}";
    const char *secret = "db-password";
    const char *plaintext = "hunter2";
    const char *options = "{\"content_type\":\"text/plain\"}";
    so_vault *vault = NULL;
    so_bytes props = {NULL, 0};
    so_bytes value = {NULL, 0};
    so_bytes recovery_key = {NULL, 0};
    int rc = 0;

    printf("contract %s, abi %u\n", so_contract_version(), (unsigned)so_abi_version());

    if (so_vault_create(text(home), home ? strlen(home) : 0, text(name), strlen(name),
                        text(create_options), strlen(create_options), &recovery_key,
                        &vault) != SO_STATUS_OK) {
        return fail("so_vault_create");
    }
    /* A real tool shows the recovery key to its owner once; this one only
       checks its shape and wipes it. */
    if (recovery_key.len != 29) {
        fprintf(stderr, "unexpected recovery key length %zu\n", recovery_key.len);
        rc = 1;
    }
    so_bytes_free(&recovery_key); /* zeroised before free */

    if (so_secret_set(vault, text(secret), strlen(secret), text(plaintext), strlen(plaintext),
                      text(options), strlen(options), &props) != SO_STATUS_OK) {
        rc = fail("so_secret_set");
        goto done;
    }
    printf("set: %s\n", (const char *)props.ptr); /* JSON is NUL-terminated */
    so_bytes_free(&props);

    if (so_secret_get(vault, text(secret), strlen(secret), NULL, 0, &props, &value) != SO_STATUS_OK) {
        rc = fail("so_secret_get");
        goto done;
    }
    if (value.len != strlen(plaintext) || memcmp(value.ptr, plaintext, value.len) != 0) {
        fprintf(stderr, "value mismatch\n");
        rc = 1;
    }
    so_bytes_free(&value); /* zeroised before free */
    so_bytes_free(&props);

    if (so_secret_get(vault, text("missing"), 7, NULL, 0, &props, &value) == SO_STATUS_OK) {
        fprintf(stderr, "expected not_found\n");
        rc = 1;
    } else if (strcmp(so_last_error_code(), "not_found") != 0) {
        rc = fail("so_secret_get(missing) reported the wrong code");
    } else {
        printf("missing secret: %s\n", so_last_error_code());
    }
    so_bytes_free(&props); /* empty after a failed call: no-op */
    so_bytes_free(&value);

done:
    so_vault_close(vault);
    return rc;
}
