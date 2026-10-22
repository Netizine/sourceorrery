# Converting Python code

SDK: `pip install sourceorrery` (Python 3.11+, wheels for Windows, macOS
and Linux; add it to `requirements.txt` / `pyproject.toml`).

## One module for every read

```python
# app/secrets.py
"""Secrets from the SourceOrrery vault named in sourceorrery.toml."""
from sourceorrery import Project

_project = Project.load()  # nearest sourceorrery.toml, unlocked like the CLI


def secret(name: str) -> str:
    """The value delivered as environment variable `name`."""
    value = _project.env(name)
    if value is None:
        raise KeyError(f"{name} is not available from sourceorrery.toml")
    return value.expose_text()


def optional_secret(name: str, default: str | None = None) -> str | None:
    value = _project.env(name)
    return default if value is None else value.expose_text()
```

## Replacements

| Before | After |
|--------|-------|
| `os.environ["DATABASE_URL"]` | `secret("DATABASE_URL")` |
| `os.getenv("DATABASE_URL")` | `optional_secret("DATABASE_URL")` |
| `os.environ.get("TIMEOUT", "30")` | `optional_secret("TIMEOUT", "30")` |
| `load_dotenv()` / `dotenv_values(".env")` | delete, once every key is covered |

Keep the replacement 1:1: same variable name, same default, same type
conversion (`int(secret("PORT"))`). Remove `python-dotenv` from the
dependencies when no loader is left.

## Frameworks

- **Django**: replace the reads in `settings.py` with `secret(...)`;
  `settings.py` is imported once, which suits `Project.load()`.
- **Flask / FastAPI**: read in the config object or settings module the
  same way.
- **pydantic `BaseSettings` / `pydantic-settings`**: these read the
  environment by field name. Either keep them and start the app with
  `sourceorrery run -- uvicorn app:app`, or pass values explicitly:
  `Settings(database_url=secret("DATABASE_URL"))`.
- **Celery, gunicorn, scripts started by tools you do not control**:
  `sourceorrery run -- <command>`.

## Tests

`pytest` reads the same vault: run `sourceorrery run -- pytest` or let the
code load the project. Tests that monkeypatch `os.environ` for a
non-secret value can stay; never put a real value in a fixture.
