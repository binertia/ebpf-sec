# Runtime Guard Handoff

Updated: 2026-06-03

## Current State

Runtime Guard is an estimated **95% complete for the MVP**. The fake-event
pipeline is runnable without root, deterministic detection and compression are
implemented, SQLite persistence is hardened, Linux amd64 eBPF collectors are
present, the live event path uses a bounded async persistence queue, and the
local LLM client is wired through the CLI.

The remaining **5%** is concentrated in capable-host validation:

1. Run root-only eBPF smoke tests on a host that permits BPF map creation and
   probe attachment.
2. Perform an end-to-end test against an actual local `llama-server`.

## Implemented MVP Surface

The current pipeline is:

```text
eBPF raw tracepoints
  -> normalized events
  -> bounded process-tree grouping
  -> deterministic rules and additive score
  -> compressed incident timeline
  -> SQLite storage
  -> optional local LLM explanation
  -> terminal report
```

Implemented live Linux amd64 collectors:

- `execve`
- IPv4 `connect`
- path-backed `write`, `writev`, `pwrite64`, `pwritev`, and `pwritev2`
- `chmod`, `fchmod`, `fchmodat`, and `fchmodat2`

File write and chmod records currently represent syscall-entry **attempts**.
Successful completion tracking remains a later hardening step.

Implemented deterministic rules:

- `web_process_spawned_shell`
- `shell_downloaded_file`
- `tmp_file_made_executable`
- `recently_downloaded_binary_executed`
- `downloaded_binary_connected_outbound`
- `suspicious_reverse_shell_pattern`
- `package_manager_spawned_shell`
- `sensitive_file_access`
- `crypto_miner_process_name`
- `unexpected_network_tool_execution`

## Important Boundaries

- The LLM is not the first security boundary. Rules detect, compression
  explains, and the LLM summarizes.
- The LLM client receives compressed incident JSON only, never raw event rows.
- LLM endpoints are loopback-only by default. Remote endpoints require
  `--allow-remote-endpoint`.
- HTTP redirects are refused, loopback proxy use is bypassed, request timeouts
  are enforced, responses are size-limited, and strict JSON is required.
- New SQLite files are created with `0600`. Existing DB paths must be private
  regular files and cannot be symlinks. The immediate parent directory must be
  owned by the running UID and cannot permit group or other writes.
- Terminal output strips control and bidirectional formatting characters.
- Grouping retains at most 4096 events per active candidate and 65536 events
  globally. Dropped older history is reported in the incident JSON and CLI.
- Incident storage upserts its supporting evidence rows and incident links in
  one transaction, independent of async event-queue timing.
- The live CLI reports normalized, grouped, analyzed, incident, kernel
  ring-buffer-drop, and event-persistence counters every 10 seconds and at
  shutdown.
- The MVP never automatically kills, blocks, or remediates processes.

## Known Limitations

- Event persistence is asynchronous, but incident writes remain synchronous.
  A slow disk can still delay incident reporting even though live ingestion is
  no longer blocked on per-event SQLite writes.
- The local LLM path has fake-transport coverage but has not been exercised with
  an actual `llama-server` model in this workspace.
- Container fields are populated best-effort from procfs cgroup and container
  hostname data when available. This is a bounded PID/start-time cache; the
  hostname is not guaranteed to match the container-runtime display name.
- IPv6 connection capture is not implemented.
- This workspace host denies BPF map creation even outside the sandbox. Live
  collector startup fails with `operation not permitted`; use a capable Linux
  host for root-only smoke execution.
- `runtime-guard show` appends an existing stored LLM analysis after the
  deterministic incident evidence when one is available.

## Validation

Use a writable Go cache in this environment:

```sh
GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go test ./...

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go vet ./...

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go test -race ./...

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go test -tags=ebpf_smoke ./internal/ebpf -run '^$'
```

All commands above passed on 2026-06-03. The tagged smoke command verifies
compilation only. Execute root smoke tests on a BPF-capable Linux amd64 host:

```sh
sudo go test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke'
```

Run the non-root fake pipeline:

```sh
mkdir -p "$HOME/.local/state/runtime-guard"
chmod 700 "$HOME/.local/state/runtime-guard"
DB="$HOME/.local/state/runtime-guard/runtime-guard.db"
go run ./cmd/runtime-guard demo --db "$DB"
go run ./cmd/runtime-guard show --db "$DB" inc-evt-001
```

Run local LLM analysis:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/runtime-guard llm --db "$DB" inc-evt-001
```

## Recommended Next Task

Exercise the root-only eBPF path and the real local LLM path on a capable host.

## File Map

```text
cmd/runtime-guard/        CLI routing and live loop
internal/ebpf/            Linux amd64 raw-tracepoint collectors
internal/events/          normalized event model and grouping
internal/pipeline/        grouper -> detector -> compressor orchestration
internal/detect/          deterministic rules and scoring
internal/compress/        compact incident timeline and summary
internal/store/           SQLite persistence, schema, and upgrades
internal/llm/             local HTTP client, prompt, strict report contract
internal/report/          terminal-safe rendering
internal/persistqueue/    bounded async event persistence queue
testdata/events/          fake normalized event fixtures
docs/                     plan and this handoff
```
