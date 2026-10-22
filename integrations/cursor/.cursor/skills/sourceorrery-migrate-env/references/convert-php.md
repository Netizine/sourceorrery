# Converting PHP code

SDK: `composer require sourceorrery/sourceorrery` (PHP 8.2+ with the `ffi`
extension). It loads the native library from the `sourceorrery-ffi`
archive of the matching GitHub release, found through
`SOURCEORRERY_NATIVE_DIR`: https://sourceorrery.ai/sdks/php/. FFI is on
for the command line by default; web servers (php-fpm, Apache mod_php)
need `ffi.enable=true` in `php.ini`. Where FFI cannot be enabled, keep the
variables and start the process with `sourceorrery run --`.

## One helper for every read

```php
<?php
// src/Secrets.php
namespace App;

use SourceOrrery\Project;

final class Secrets
{
    private static ?Project $project = null;

    /** The value delivered as environment variable $name. */
    public static function get(string $name, ?string $default = null): ?string
    {
        self::$project ??= Project::load(); // nearest sourceorrery.toml
        return self::$project->env($name)?->expose() ?? $default;
    }
}
```

## Replacements

| Before | After |
|--------|-------|
| `getenv('DATABASE_URL')`, `$_ENV['DATABASE_URL']`, `$_SERVER['DATABASE_URL']` | `Secrets::get('DATABASE_URL')` |
| `Dotenv\Dotenv::createImmutable(__DIR__)->load();` | delete, once every key is covered |

## Frameworks

- **Laravel**: `config/*.php` read variables with `env('DB_PASSWORD')`,
  and the framework loads `.env` itself. Replace those calls in the
  config files with `\App\Secrets::get('DB_PASSWORD', <same default>)`,
  keep `.env` only for non-secret settings if the user wants, and run
  `php artisan config:clear`. Or start `artisan` and the PHP server under
  `sourceorrery run --`.
- **Symfony**: `%env(DATABASE_URL)%` reads the real environment before
  `.env`; start the server and `bin/console` under `sourceorrery run --`.

## Tests

`sourceorrery run -- vendor/bin/phpunit`, or let the code load the
project.
