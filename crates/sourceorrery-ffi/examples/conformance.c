/*
 * Conformance runner for the C SDK (tests/conformance/sdk/README.md): one
 * scenario per invocation, observations as key<TAB>value lines. Metadata is
 * printed as the core's JSON (`properties_json`, `descriptor_json`,
 * `entry.N.json`); the harness derives the fields from it.
 *
 *   conformance <op> [key=value ...]
 *
 * Build as examples/get_secret.c; only so_reader_* / so_project_* are used.
 */
#define _CRT_SECURE_NO_WARNINGS 1 /* getenv, strcat on MSVC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sourceorrery.h"

static const char *arg_value(int argc, char **argv, const char *key) {
    size_t len = strlen(key);
    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], key, len) == 0 && argv[i][len] == '=') {
            return argv[i] + len + 1;
        }
    }
    return NULL;
}

static const uint8_t *u8(const char *s) { return (const uint8_t *)s; }
static size_t slen(const char *s) { return s == NULL ? 0 : strlen(s); }

/* Append a JSON string literal to buf. */
static void json_string(char *buf, size_t cap, const char *text) {
    size_t n = strlen(buf);
    if (n + 1 < cap) buf[n++] = '"';
    for (; *text != '\0' && n + 2 < cap; text++) {
        if (*text == '"' || *text == '\\') buf[n++] = '\\';
        buf[n++] = *text;
    }
    if (n + 1 < cap) buf[n++] = '"';
    buf[n] = '\0';
}

static void print_bytes(const char *key, const so_bytes *bytes) {
    printf("%s\t", key);
    if (bytes->ptr != NULL) fwrite(bytes->ptr, 1, bytes->len, stdout);
    printf("\n");
}

static int report_error(void) {
    const char *hint = so_last_error_hint();
    const char *code = so_last_error_code();
    printf("outcome\terror\n");
    printf("code\t%s\n", code == NULL ? "" : code);
    printf("message\t%s\n", so_last_error_message() == NULL ? "" : so_last_error_message());
    printf("hint\t%s\n", hint == NULL ? "" : hint);
    printf("transient\t%s\n", code != NULL && strcmp(code, "not_yet_valid") == 0 ? "true" : "false");
    printf("type\tso_status\n");
    return 0;
}

static int secret_result(so_status status, so_bytes *props, so_bytes *value) {
    if (status != SO_STATUS_OK) return report_error();
    printf("outcome\tok\n");
    print_bytes("value", value);
    print_bytes("properties_json", props);
    so_bytes_free(value);
    so_bytes_free(props);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: conformance <op> [key=value ...]\n");
        return 2;
    }
    const char *op = argv[1];
    const char *vault = arg_value(argc, argv, "vault");
    if (vault == NULL) vault = getenv("SOURCEORRERY_TEST_VAULT");
    if (vault == NULL) vault = "development";
    const char *home = arg_value(argc, argv, "home");
    const char *passphrase = arg_value(argc, argv, "passphrase");
    const char *passphrase_file = arg_value(argc, argv, "passphrase_file");
    const char *environment = arg_value(argc, argv, "environment");
    const char *name = arg_value(argc, argv, "name");
    const char *version = arg_value(argc, argv, "version");
    const char *reference = arg_value(argc, argv, "reference");
    const char *manifest = arg_value(argc, argv, "manifest");

    char options[4096] = "{";
    if (home != NULL) { strcat(options, "\"home\":"); json_string(options, sizeof options, home); strcat(options, ","); }
    if (passphrase_file != NULL) { strcat(options, "\"passphrase_file\":"); json_string(options, sizeof options, passphrase_file); strcat(options, ","); }
    strcat(options, environment != NULL && strcmp(environment, "false") == 0 ? "\"environment\":false}" : "\"environment\":true}");

    so_bytes props = {NULL, 0}, value = {NULL, 0};

    if (strcmp(op, "load") == 0) {
        so_project *project = NULL;
        if (so_project_load(u8(manifest), slen(manifest), u8(options), strlen(options), u8(passphrase), slen(passphrase), &project) != SO_STATUS_OK) {
            return report_error();
        }
        printf("outcome\tok\n");
        so_bytes info = {NULL, 0};
        if (so_project_info(project, &info) == SO_STATUS_OK) {
            print_bytes("project_info_json", &info);
            so_bytes_free(&info);
        }
        size_t count = so_project_count(project);
        for (size_t i = 0; i < count; i++) {
            so_bytes entry = {NULL, 0}, entry_value = {NULL, 0};
            if (so_project_entry(project, i, &entry, &entry_value) == SO_STATUS_OK) {
                char key[64];
                snprintf(key, sizeof key, "entry.%zu.json", i);
                print_bytes(key, &entry);
                snprintf(key, sizeof key, "entry.%zu.value", i);
                print_bytes(key, &entry_value);
                so_bytes_free(&entry);
                so_bytes_free(&entry_value);
            }
        }
        so_project_free(project);
        return 0;
    }

    so_reader *reader = NULL;
    if (so_reader_open(u8(vault), strlen(vault), u8(options), strlen(options), u8(passphrase), slen(passphrase), &reader) != SO_STATUS_OK) {
        return report_error();
    }
    int rc = 0;
    if (strcmp(op, "open") == 0) {
        so_bytes descriptor = {NULL, 0};
        if (so_reader_descriptor(reader, &descriptor) != SO_STATUS_OK) {
            rc = report_error();
        } else {
            printf("outcome\tok\n");
            print_bytes("descriptor_json", &descriptor);
            so_bytes_free(&descriptor);
        }
    } else if (strcmp(op, "get") == 0) {
        rc = secret_result(so_reader_get(reader, u8(name), slen(name), u8(version), slen(version), &props, &value), &props, &value);
    } else if (strcmp(op, "get-newest-explicit") == 0) {
        so_bytes newest = {NULL, 0};
        if (so_reader_properties(reader, u8(name), slen(name), NULL, 0, &newest) != SO_STATUS_OK) {
            rc = report_error();
        } else {
            /* Pull "version":"..." out of the properties JSON. */
            const char *at = strstr((const char *)newest.ptr, "\"version\":\"");
            char id[128] = "";
            if (at != NULL) {
                at += strlen("\"version\":\"");
                const char *end = strchr(at, '"');
                if (end != NULL && (size_t)(end - at) < sizeof id) {
                    memcpy(id, at, (size_t)(end - at));
                    id[end - at] = '\0';
                }
            }
            so_bytes_free(&newest);
            rc = secret_result(so_reader_get(reader, u8(name), slen(name), u8(id), strlen(id), &props, &value), &props, &value);
        }
    } else if (strcmp(op, "properties") == 0) {
        if (so_reader_properties(reader, u8(name), slen(name), u8(version), slen(version), &props) != SO_STATUS_OK) {
            rc = report_error();
        } else {
            printf("outcome\tok\n");
            print_bytes("properties_json", &props);
            so_bytes_free(&props);
        }
    } else if (strcmp(op, "resolve") == 0) {
        rc = secret_result(so_reader_resolve(reader, u8(reference), slen(reference), &props, &value), &props, &value);
    } else {
        fprintf(stderr, "unknown scenario op '%s'\n", op);
        rc = 2;
    }
    so_reader_close(reader);
    return rc;
}
