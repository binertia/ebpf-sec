# Tracejutsu

Tracejutsu is a local Linux security tool. It watches runtime activity with
eBPF, groups related events into incidents, stores them in SQLite, and can ask a
local LLM to explain an incident.

It is local-first: events stay on the machine unless you explicitly configure a
remote LLM endpoint.

## What It Captures

By default, live mode watches:

- process starts (`execve`)
- outbound network connections
- file writes
- permission changes (`chmod`)

For lab investigations, `--collectors behavior_core` adds broader behavior
signals such as sensitive file reads, namespace changes, process access, and
network server activity.

## Current Release Scope

`v0.1.0` is validated for **Debian 13 (trixie) amd64**.

The live collector can also run on Linux amd64 and native arm64, but other
systems are not part of the validated release target yet.

## Quick Start

Run the demo first. It does not need root and does not use eBPF:

```sh
go run ./cmd/tracejutsu demo
```

Run the tests:

```sh
go test ./...
```

The module uses Go toolchain `go1.26.4`. Keep `GOTOOLCHAIN=auto` enabled or
install Go `1.26.4` or newer.

## Save Demo Results

Use a private SQLite database path:

```sh
mkdir -p "$HOME/.local/state/tracejutsu"
chmod 700 "$HOME/.local/state/tracejutsu"
DB="$HOME/.local/state/tracejutsu/tracejutsu.db"

go run ./cmd/tracejutsu demo --db "$DB"
go run ./cmd/tracejutsu incidents --db "$DB"
go run ./cmd/tracejutsu show --db "$DB" inc-evt-001
```

Useful database commands:

```sh
go run ./cmd/tracejutsu events --db "$DB"
go run ./cmd/tracejutsu event-summary --db "$DB" --type file_write
go run ./cmd/tracejutsu db-stats --db "$DB"
```

## Live Capture

Live capture needs Linux and root, or equivalent eBPF capabilities:

```sh
sudo go run ./cmd/tracejutsu run
```

Save live events and incidents:

```sh
sudo go run ./cmd/tracejutsu run --db "$DB"
```

For service-style output, hide per-event JSON and print incidents plus runtime
stats:

```sh
sudo go run ./cmd/tracejutsu run --db "$DB" --quiet-events
```

Enable the broader lab collector set:

```sh
sudo go run ./cmd/tracejutsu run --collectors behavior_core
```

Press `Ctrl-C` to stop. Tracejutsu prints final runtime stats at shutdown.

## Local LLM Analysis

LLM analysis is optional. Start a local `llama-server` compatible endpoint, then
analyze a stored incident:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/tracejutsu llm --db "$DB" inc-evt-001
go run ./cmd/tracejutsu show --db "$DB" inc-evt-001
```

Remote LLM endpoints are blocked unless you pass `--allow-remote-endpoint`.
If your local server requires an API key, set `TRACEJUTSU_LLM_API_KEY`.

## Install As A Service

Build a binary:

```sh
go build -trimpath -o ./bin/tracejutsu ./cmd/tracejutsu
```

Install guide:

- [docs/INSTALL.md](docs/INSTALL.md) - binary, Debian package, systemd service,
  release builds, and validation
- [docs/OPERATIONS.md](docs/OPERATIONS.md) - database size, backups,
  compaction, and logs

## Validation

Fast local release check:

```sh
scripts/release-check.sh
```

Fresh disposable Debian/Ubuntu host validation:

```sh
./test.sh --quick --yes
```

Full validation:

```sh
./test.sh --yes
```

## Command Summary

```text
tracejutsu demo [--db path] [fixture.json]
tracejutsu run [--db path] [--collectors list] [--quiet-events]
tracejutsu events [--db path] [--limit count]
tracejutsu event-summary [--db path] [--type event_type]
tracejutsu db-stats [--db path]
tracejutsu incidents [--db path] [--limit count]
tracejutsu show [--db path] <incident_id>
tracejutsu llm [--db path] <incident_id>
tracejutsu rules
tracejutsu config
tracejutsu version
```

## More Docs

- [examples/README.md](examples/README.md) - demo fixture notes
- [docs/TRACEJUTSU_PLAN.md](docs/TRACEJUTSU_PLAN.md) - architecture and roadmap
- [docs/HANDOFF.md](docs/HANDOFF.md) - current status and known limitations
- [docs/ARM_TEST.md](docs/ARM_TEST.md) - arm64 validation notes
- [docs/STRESS_VALIDATION.md](docs/STRESS_VALIDATION.md) - stress validation
