<?php

declare(strict_types=1);

// Keep the existing dependency-free test runner and its exit status intact.
// Filtering must be configured before the SDK's classes are loaded.
if (!extension_loaded('xdebug') || !in_array('coverage', xdebug_info('mode'), true)) {
    fwrite(STDERR, "coverage: PHP requires Xdebug with XDEBUG_MODE=coverage\n");
    exit(2);
}

$coverageRepo = dirname(__DIR__, 2);
xdebug_set_filter(XDEBUG_FILTER_CODE_COVERAGE, XDEBUG_PATH_INCLUDE, [
    $coverageRepo . '/bindings/php/src/',
    $coverageRepo . '/bindings/php/autoload.php',
]);
xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);

register_shutdown_function(static function () use ($coverageRepo): void {
    $data = xdebug_get_code_coverage();
    xdebug_stop_code_coverage();
    $output = $coverageRepo . '/coverage/php.json';
    if (file_put_contents($output, json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)) === false) {
        throw new RuntimeException('Cannot write PHP coverage report: ' . $output);
    }
});
