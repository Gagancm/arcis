# Arcis CLI telemetry

The `arcis` CLI sends anonymous usage statistics so development is steered by
real usage. This page explains exactly what is collected and how to turn it off.

## What is collected

One event per command, containing only:

| Field | Example | Why |
|---|---|---|
| `install_id` | random UUID v4 | Count distinct installs over time. Not tied to you. |
| `cli_version` | `1.2.1` | Know which versions are in use. |
| `command` | `audit` / `sca` / `scan` / `start` | Know which features are used. |
| `os` | `linux` / `macos` / `windows` | Prioritize platform support. |
| `arch` | `x86_64` / `aarch64` | Prioritize build targets. |
| `ci` | `true` / `false` | Separate interactive use from automation. |

## What is NOT collected

No source code. No scanned file paths. No scan target URLs. No findings or
vulnerability details. No request contents. No IP addresses (the collector does
not log them). No usernames, emails, or any personal data. The `install_id` is a
random UUID with no link to your identity or your code.

## How to opt out

Set either of these and the CLI sends nothing:

```bash
export ARCIS_TELEMETRY=0      # Arcis-specific kill switch
export DO_NOT_TRACK=1         # cross-tool standard (https://consoledonottrack.com)
```

When telemetry is off, the command runs exactly as before. Telemetry is always
fire-and-forget with a short timeout, so it never slows a command down or changes
its exit code, even when on.

## Where the data goes

Events are POSTed to an Arcis-operated collector. The `install_id` file lives at
`~/.arcis/install-id` (delete it any time to reset). A one-time notice is printed
to stderr on first interactive use.
