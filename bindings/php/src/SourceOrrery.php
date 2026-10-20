<?php

declare(strict_types=1);

namespace SourceOrrery;

use FFI;

/** Information about the loaded native library. */
final class SourceOrrery
{
    private function __construct()
    {
    }

    /** Contract version of the core (`"1"` for this package). */
    public static function contractVersion(): string
    {
        return FFI::string(Native::ffi()->so_contract_version());
    }

    /** Version of the C ABI the library was built with. */
    public static function abiVersion(): int
    {
        return Native::ffi()->so_abi_version();
    }
}
