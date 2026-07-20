# Contributing to GhostCred

First off, thank you for considering contributing to GhostCred! It's people like you that make GhostCred an effective tool for the whole community.

## Development Setup

The easiest way to get started is by using the provided Dev Container:
1. Open this repository in VS Code
2. When prompted, click **Reopen in Container**
3. The environment will automatically build and install all dependencies via `pip install -e .[dev]`.

To set it up locally without Dev Containers:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Running Tests

GhostCred uses `pytest`. Run the test suite before submitting any PR:
```bash
pytest tests/ -v
```

To run the regex fuzz tests (protects against ReDoS):
```bash
pytest tests/test_fuzz_patterns.py
```

## Writing a Plugin (Revokers & Scanners)

> [!WARNING]
> **API Stability:** GhostCred is currently at `v0.1.0`. The `pluggy` plugin API used to register custom patterns and revokers is currently considered **experimental**. Breaking changes to the plugin architecture may occur before `v1.0.0`.

GhostCred uses `pluggy` to discover secret patterns and revokers. You can write your own Python package (e.g., `ghostcred-plugin-myprovider`) and register it.

1. Implement `ghostcred_register_patterns()` to return a list of `SecretPattern`s.
2. Implement `ghostcred_register_revokers()` to return a dictionary mapping your provider's name to a `Revoker` class instance.
3. In your plugin's `pyproject.toml`, register the entry point:
```toml
[project.entry-points."ghostcred"]
myprovider = "ghostcred_plugin_myprovider.plugin"
```
