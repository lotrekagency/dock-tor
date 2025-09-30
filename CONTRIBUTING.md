# Contributing to dock-tor

Thanks for considering contributing! This guide explains how to get set up, coding standards, and the workflow for proposing changes.

## Development setup

```bash
git clone https://github.com/your-org/dock-tor.git
cd dock-tor
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Run a scan locally (needs Docker socket + Trivy installed or available in PATH):

```bash
export MAIL_TO="you@example.com" MAIL_FROM="scanner@example.com" SMTP_HOST=localhost SMTP_PORT=1025
python -m app.main
```

If you prefer using Docker for development you can invoke the compose service directly once you integrate it into your stack.

## Style & quality

* Favor small, focused PRs.
* Keep functions side‑effect light; prefer pure data transforms.
* Maintain strong typing – run `python -m mypy app` (zero new errors).
* Update the environment variable table in the README when adding or changing settings.
* Avoid adding dependencies unless clearly necessary; prefer stdlib.
* Write clear docstrings for any new public functions or dataclasses.

## Adding an environment variable

1. Add it to `app/settings.py` (docstring + `Settings.load`).
2. Provide a sensible default to keep local usage simple.
3. Update the README environment table and any examples.
4. Reference it in this doc if it alters contributor workflow.

## Reporting issues / feature requests

When opening an issue include:

* What problem you’re solving / desired behavior.
* Repro steps (if a bug) – commands, environment, logs.
* Relevant stack traces or truncated logs (avoid secrets).
* Suggested solution direction (optional but helpful).

## Pull request checklist

Before marking your PR ready for review:

- [ ] Lint / type checks pass (`python -m mypy app`).
- [ ] Basic manual scan run completes without traceback.
- [ ] README / docs updated (if behavior or env vars changed).
- [ ] Added / adjusted tests (if/when a test suite is introduced).

## Code of Conduct

Be respectful, constructive, and assume good intent. Harassment, discrimination, or personal attacks are not tolerated.

## License

By contributing you agree that your contributions will be licensed under the MIT License located in `LICENSE`.

Happy scanning!
