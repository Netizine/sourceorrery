<?php
// Minimal PSR-4 autoloader for use without Composer (tests, examples). With
// Composer, `vendor/autoload.php` does the same for the SourceOrrery\ namespace:
// the manifest is composer.json at the repository root, where Packagist reads
// it, and it maps the two files below that hold more than one class.

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'SourceOrrery\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
        return;
    }
    // Exception subclasses live in SourceOrreryException.php; ProjectSecret in Project.php.
    foreach (['SourceOrreryException', 'Project'] as $holder) {
        require_once __DIR__ . '/src/' . $holder . '.php';
        if (class_exists($class, false)) {
            return;
        }
    }
});
