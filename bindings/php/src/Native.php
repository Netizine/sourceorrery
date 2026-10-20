<?php

declare(strict_types=1);

namespace SourceOrrery;

use FFI;
use FFI\CData;

/**
 * The read-only part of the SourceOrrery C ABI through PHP's FFI extension.
 *
 * Only so_reader_* and so_project_* functions are declared, so code built on
 * this class cannot write to a vault. The declarations below are the
 * relevant subset of crates/sourceorrery-ffi/include/sourceorrery.h (PHP's
 * FFI parser takes plain C declarations, not the preprocessed header).
 *
 * The library is found in the directory named by SOURCEORRERY_NATIVE_DIR,
 * else next to this package under native/<os>-<arch>/, else by the dynamic
 * loader (LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, PATH).
 *
 * @internal
 */
final class Native
{
    public const DECLARATIONS = <<<'C'
        typedef int32_t so_status;
        typedef struct so_reader so_reader;
        typedef struct so_project so_project;
        typedef struct so_bytes { uint8_t *ptr; size_t len; } so_bytes;
        uint32_t so_abi_version(void);
        const char *so_contract_version(void);
        void so_bytes_free(so_bytes *bytes);
        const char *so_last_error_code(void);
        const char *so_last_error_message(void);
        const char *so_last_error_hint(void);
        so_status so_reader_open(const uint8_t *name, size_t name_len,
                                 const uint8_t *options_json, size_t options_json_len,
                                 const uint8_t *passphrase, size_t passphrase_len,
                                 so_reader **out_handle);
        void so_reader_close(so_reader *handle);
        so_status so_reader_descriptor(const so_reader *handle, so_bytes *out_json);
        so_status so_reader_get(const so_reader *handle,
                                const uint8_t *name, size_t name_len,
                                const uint8_t *version, size_t version_len,
                                so_bytes *out_properties_json, so_bytes *out_value);
        so_status so_reader_properties(const so_reader *handle,
                                       const uint8_t *name, size_t name_len,
                                       const uint8_t *version, size_t version_len,
                                       so_bytes *out_properties_json);
        so_status so_reader_resolve(const so_reader *handle,
                                    const uint8_t *reference, size_t reference_len,
                                    so_bytes *out_properties_json, so_bytes *out_value);
        so_status so_project_load(const uint8_t *manifest_path, size_t manifest_path_len,
                                  const uint8_t *options_json, size_t options_json_len,
                                  const uint8_t *passphrase, size_t passphrase_len,
                                  so_project **out_handle);
        size_t so_project_count(const so_project *handle);
        so_status so_project_info(const so_project *handle, so_bytes *out_json);
        so_status so_project_entry(const so_project *handle, size_t index,
                                   so_bytes *out_entry_json, so_bytes *out_value);
        void so_project_free(so_project *handle);
        C;

    private static ?FFI $ffi = null;

    public static function ffi(): FFI
    {
        return self::$ffi ??= FFI::cdef(self::DECLARATIONS, self::libraryPath());
    }

    private static function libraryPath(): string
    {
        $file = self::fileName();
        $fromEnv = getenv('SOURCEORRERY_NATIVE_DIR');
        if (is_string($fromEnv) && $fromEnv !== '') {
            $candidate = rtrim($fromEnv, '/\\') . DIRECTORY_SEPARATOR . $file;
            if (is_file($candidate)) {
                return $candidate;
            }
        }
        $bundled = dirname(__DIR__) . '/native/' . self::platform() . '/' . $file;
        if (is_file($bundled)) {
            return $bundled;
        }
        return $file; // dynamic loader search path
    }

    private static function fileName(): string
    {
        return match (PHP_OS_FAMILY) {
            'Windows' => 'sourceorrery_ffi.dll',
            'Darwin' => 'libsourceorrery_ffi.dylib',
            default => 'libsourceorrery_ffi.so',
        };
    }

    /** `<os>-<arch>` as the bundled native directories are named. */
    public static function platform(): string
    {
        $os = match (PHP_OS_FAMILY) {
            'Windows' => 'windows',
            'Darwin' => 'macos',
            default => 'linux',
        };
        $arch = strtolower(php_uname('m'));
        $arch = match ($arch) {
            'amd64', 'x86_64' => 'x86_64',
            'arm64', 'aarch64' => 'aarch64',
            default => $arch,
        };
        return $os . '-' . $arch;
    }

    /** A `so_bytes` output slot, zeroed. */
    public static function bytesSlot(): CData
    {
        $slot = self::ffi()->new('so_bytes');
        $slot->ptr = null;
        $slot->len = 0;
        return $slot;
    }

    /** Copy a UTF-8 buffer out as a string and free it. */
    public static function takeString(CData $slot): string
    {
        $text = $slot->ptr === null ? '' : FFI::string($slot->ptr, $slot->len);
        self::ffi()->so_bytes_free(FFI::addr($slot));
        return $text;
    }

    /** Throw the typed exception for the last error when `$status` is not OK. */
    public static function check(int $status): void
    {
        if ($status === 0) {
            return;
        }
        $ffi = self::ffi();
        $code = self::cString($ffi->so_last_error_code()) ?? ($status === 2 ? 'internal' : 'unknown');
        $message = self::cString($ffi->so_last_error_message()) ?? 'unknown error';
        $hint = self::cString($ffi->so_last_error_hint()) ?? '';
        throw SourceOrreryException::forCode($code, $message, $hint);
    }

    /**
     * A `const char *` return value: PHP's FFI hands a NUL-terminated string
     * back as a PHP string already, NULL as null, and (on some builds) a
     * CData pointer.
     */
    public static function cString(mixed $pointer): ?string
    {
        if ($pointer === null || is_string($pointer)) {
            return $pointer;
        }
        return FFI::string($pointer);
    }

    /** A string argument as `(ptr, len)`; null becomes `(NULL, 0)`. */
    public static function arg(?string $text): array
    {
        if ($text === null || $text === '') {
            return [null, 0];
        }
        $length = strlen($text);
        $buffer = self::ffi()->new("uint8_t[$length]", false);
        FFI::memcpy($buffer, $text, $length);
        return [$buffer, $length];
    }

    /** Release a buffer made by `arg()`, wiping it first. */
    public static function release(?CData $buffer, int $length): void
    {
        if ($buffer !== null) {
            FFI::memset($buffer, 0, $length);
            FFI::free($buffer);
        }
    }
}
