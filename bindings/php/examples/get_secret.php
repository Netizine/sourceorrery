<?php
// Read one secret and report its size, never its value.
//
//   composer require sourceorrery/sourceorrery
//   export SOURCEORRERY_PASSPHRASE=...   # or rely on the OS credential store
//   php get_secret.php development database-password

declare(strict_types=1);

require file_exists(__DIR__ . '/../vendor/autoload.php') ? __DIR__ . '/../vendor/autoload.php' : __DIR__ . '/../autoload.php';

use SourceOrrery\SecretReader;
use SourceOrrery\SourceOrreryException;

$vault = $argv[1] ?? 'development';
$name = $argv[2] ?? 'database-password';

try {
    // Unlocked by the OS credential store, then SOURCEORRERY_PASSPHRASE,
    // then SOURCEORRERY_PASSPHRASE_FILE; never a prompt.
    $reader = SecretReader::open($vault);
    $secret = $reader->get($name); // newest accessible version
    printf("%s version %s from vault %s: %d bytes\n", $name, $secret->properties->version, $vault, $secret->value->length());
    $secret->close(); // zeroises the value
    $reader->close();
} catch (SourceOrreryException $err) {
    // $err->code() is stable; getMessage() is the detail plus a hint. No values.
    fwrite(STDERR, sprintf("error [%s]: %s\n", $err->code(), $err->getMessage()));
    exit(1);
}
