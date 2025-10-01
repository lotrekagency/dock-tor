# docktor

<p align="center">
	<img src="app/static/docktor-logo.png" alt="docktor logo" width="260" />
</p>

Lightweight, self-contained container image vulnerability scanning helper designed to drop into an existing Docker / docker‑compose environment and regularly email a concise vulnerability summary. It wraps [Trivy](https://github.com/aquasecurity/trivy) to scan each unique image referenced by your running (or all) containers, aggregates severity counts, renders plain text + optional HTML + per‑image Markdown/JSON artifacts, and sends them via SMTP. If no vulnerability meets your configured severity threshold the run exits quietly (no spammy “all clear” messages).

Core goals:

* Zero persistent state – every run is ephemeral.
* Scan only what matters (deduplicate images, optional compose‑project scoping, exclusion labels).
* Signal over noise – single email with summarized counts + detailed attachments only when something crosses your threshold.
* Simple deploy – single container, minimal required env vars.

---

## Quickstart

### 1. Run with docker compose (recommended)

If you already have a compose stack, add a service (example snippet):

```yaml
services:
	docktor:
		image: your-registry/docktor:latest # or build: .
		build: .
		environment:
			SMTP_HOST: "smtp.mail.local"
			SMTP_PORT: "587"
			SMTP_USER: "scanner"
			SMTP_PASS: "changeme"
			MAIL_FROM: "scanner@example.com"
			MAIL_TO: "sec@example.com,dev@example.com"
			MIN_NOTIFY_SEVERITY: "MEDIUM"   # optional (default LOW)
			SCAN_SCOPE: "COMPOSE"           # optional (default ALL)
		volumes:
			- /var/run/docker.sock:/var/run/docker.sock:ro
```

Then run:

```bash
docker compose run --rm docktor
```

Change `SCAN_SCOPE` to `ALL` to scan every container visible to the Docker daemon (subject to `ONLY_RUNNING` and exclusion labels). `COMPOSE` restricts scanning to only the containers that belong to the same docker-compose project as the `docktor` service itself.

---

## Environment Variables

Complete list (see `app/settings.py`). Defaults shown in parentheses.

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `SMTP_HOST` | str | `smtp.example.com` | SMTP server hostname |
| `SMTP_PORT` | int | `587` | SMTP port |
| `SMTP_USER` | str | `` (empty) | SMTP username (optional) |
| `SMTP_PASS` | str | `` (empty) | SMTP password (optional) |
| `SMTP_USE_SSL` | bool | `true` | If true issue STARTTLS before sending (set `false` to skip) |
| `MAIL_FROM` | str | `scanner@example.com` | From address |
| `MAIL_TO` | CSV str | `security@example.com` | Comma separated recipients |
| `TRIVY_BIN` | str | `trivy` | Trivy executable name/path |
| `TRIVY_ARGS` | str | `--severity HIGH,CRITICAL --ignore-unfixed --timeout 5m` | Extra Trivy flags appended to `trivy image` |
| `EXCLUDE_LABEL` | key=value | `docktor.ignore=true` | Containers with this label are skipped |
| `ONLY_RUNNING` | bool | `true` | If true, ignore stopped containers |
| `ATTACH_JSON` | bool | `true` | Attach raw JSON scan outputs per image |
| `LOG_LEVEL` | str | `INFO` | Python logging level |
| `MIN_NOTIFY_SEVERITY` | str | `LOW` | Minimum severity that triggers email + inclusion in summaries |
| `SCAN_SCOPE` | str | `ALL` | `ALL` = every visible container, `COMPOSE` = restrict to own compose project |

Convenience examples:

```bash
export MIN_NOTIFY_SEVERITY=HIGH            # suppress mail unless >= HIGH
export SCAN_SCOPE=COMPOSE                  # only this compose project
export TRIVY_ARGS="--severity CRITICAL --timeout 3m"  # faster, only CRITICAL
export EXCLUDE_LABEL="custom.ignore=true" # redefine exclusion label
```

Exclusion label logic: a container is skipped if either it has `docktor.ignore=true` OR it matches the dynamic `EXCLUDE_LABEL` key/value.

Notification suppression: if no vulnerability with severity >= `MIN_NOTIFY_SEVERITY` is found across all scanned images, the run exits without sending email (attachments are discarded after process exit).

---

## Typing

The project now uses structured types instead of loose dictionaries:

- `domain_types.ScanResult`: dataclass representing a scanned image result
- `domain_types.Vulnerability`: `TypedDict` subset of Trivy vulnerability fields actually consumed
- `domain_types.Attachment`: tuple alias `(filename, path, mime)`
- `domain_types.ReportBodies`: tuple alias `(text_body, optional_html_body)`

Static analysis is configured via `mypy.ini` (strict-ish settings). To run:

```bash
python -m mypy app
```

`mypy` is declared in `requirements.txt` (optional). You can omit installation if you don't need static checks.

## Workflow Summary

1. Enumerate containers -> `scanner.enumerate_containers`
2. Scan unique images -> `scanner.scan_all`
3. Render reports -> `reporting.render_reports`
4. Build attachments -> `reporting.build_attachments`
5. Send email -> `email_utils.send_email_with_attachments`

---

## Scan Scope

Use `SCAN_SCOPE` to control which containers are enumerated:

- `ALL` (default): scan every container visible to the Docker daemon (subject to `ONLY_RUNNING` and exclusion labels).
- `COMPOSE`: restrict scanning to only the containers that belong to the same docker-compose project as the `docktor` service itself. This relies on the standard label `com.docker.compose.project`. If the project label cannot be resolved (e.g., running outside docker-compose) the scanner falls back to scanning all containers and logs a warning.

Example:

```bash
export SCAN_SCOPE=COMPOSE   # Only scan containers from the same compose project
```

### Notification Threshold

Set `MIN_NOTIFY_SEVERITY` (default: `LOW`) to control when an email is sent and which vulnerabilities are displayed in the email bodies and per-image markdown attachment tables. If no vulnerability at or above the threshold is found, the scan exits without sending an email (JSON artifacts may still be created transiently during the scan).

Severity ordering (lowest -> highest): `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

Example:

```bash
export MIN_NOTIFY_SEVERITY=HIGH   # Only HIGH and CRITICAL vulns trigger mail and appear in summaries
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, style guidance, and PR checklist.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.

---

Happy scanning!
