# Finding every read of the imported variables

Search the code, scripts and configuration for each key, never the `.env`
files themselves. Get the key list without values:

```bash
sourceorrery -o json import .env --dry-run
```

Each entry in `keys` has `key` (the variable), `secret` (its secret name)
and `vault` (what import does with it).

## Search by name

ripgrep, excluding env files, dependencies and build output:

```bash
rg -n -w --hidden -g '!.git' -g '!.env*' -g '!node_modules' -g '!vendor' \
   -g '!target' -g '!dist' -g '!build' -g '!.venv' -e DATABASE_URL -e STRIPE_KEY
```

Without ripgrep, exclude tracked env files explicitly too:

```bash
git grep -n -w -e DATABASE_URL -e STRIPE_KEY -- . ':(exclude).env*' ':(exclude)**/.env*'
```

PowerShell:
`Get-ChildItem -Recurse -File | Where-Object FullName -notmatch '\\(\.git|node_modules|vendor|target|dist|build|\.venv)\\|\\\.env' | Select-String -Pattern '\bDATABASE_URL\b'`.

## Search for dynamic and indirect reads

A key can be read without its name appearing literally. Look for these
too and inspect each hit:

| Language | Patterns |
|----------|----------|
| Python | `os.environ`, `os.getenv`, `environ.get`, `load_dotenv`, `dotenv_values`, `pydantic` `BaseSettings` (field names map to variables), `decouple.config` |
| JavaScript / TypeScript | `process.env`, `import.meta.env`, `dotenv`, `dotenv-expand`, `env-cmd`, `cross-env` in scripts, `@nestjs/config`, `envalid`, `zod` env schemas |
| Java / Kotlin | `System.getenv`, `${...}` in `application.properties` / `application.yml`, `@Value("${...}")`, `dotenv-java` |
| .NET | `Environment.GetEnvironmentVariable`, `IConfiguration` keys (`Section__Key` variables map to `Section:Key`), `DotNetEnv` |
| Go | `os.Getenv`, `os.LookupEnv`, `os.Environ`, `godotenv`, `envconfig`, `viper.AutomaticEnv`, struct tags `env:"..."` |
| Rust | `std::env::var`, `env::var_os`, `env!` / `option_env!` (compile time), `dotenvy`, `envy`, `config` crate |
| PHP | `getenv`, `$_ENV`, `$_SERVER`, `env(` (Laravel), `%env(...)%` (Symfony), `Dotenv\Dotenv` |
| Ruby | `ENV[`, `ENV.fetch`, `dotenv` gem |
| C / C++ | `getenv`, `std::getenv`, `secure_getenv`, `_dupenv_s` |
| Shell, Make | `$NAME`, `${NAME}`, `$(NAME)`, `export`, `source .env`, `. ./.env`, `set -a` |

## Search configuration and tooling

- `package.json` scripts (`dotenv -e`, `env-cmd`, `node --env-file=.env`),
  `Makefile`, `justfile`, `Procfile`, `.vscode/launch.json`
  (`envFile`), JetBrains run configurations.
- `Dockerfile` (`ARG`, `ENV`), `docker-compose*.yml` (`env_file:`,
  `${NAME}` interpolation), `.devcontainer/`.
- CI: `.github/workflows/*.yml` (`env:`, `${{ secrets.NAME }}`),
  `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`.
- Deployment: Kubernetes manifests and Helm values (`secretKeyRef`,
  `envFrom`), Terraform (`TF_VAR_*`), `serverless.yml`, `vercel.json`,
  `netlify.toml`, `fly.toml`, `app.yaml`.
- Documentation that tells people to copy `.env.example` to `.env`.

Record each hit as: file, line, key, how it is read, and whether it runs
in a process you can change (convert the code) or in a tool you cannot
(start it with `sourceorrery run --`).
