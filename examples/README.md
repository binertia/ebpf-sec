# Examples

Run the non-root fake-event pipeline from the repository root:

```sh
go run ./cmd/tracejutsu demo
```

The demo loads `testdata/events/web-download-execute-connect.json`, evaluates
the initial deterministic behavior chain, groups related process-tree events,
compresses them into an incident, and prints a terminal report. It does not
invoke eBPF probes or an LLM.
