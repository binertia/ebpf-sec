# Runtime Guard Operations

This guide covers basic maintenance for an installed local service. Runtime
Guard stores normalized events, incidents, and optional LLM reports in SQLite
under `/var/lib/runtime-guard/runtime-guard.db`.

## Monitor Growth

Check database table counts and file sizes:

```sh
sudo /usr/local/bin/runtime-guard db-stats \
  --db /var/lib/runtime-guard/runtime-guard.db
```

Watch these fields over time:

- `events`
- `incidents`
- `llm_reports`
- `database_bytes`
- `wal_bytes`
- `freelist_count`

If file-write volume is high, inspect event sources before changing retention
or collector settings:

```sh
sudo /usr/local/bin/runtime-guard event-summary \
  --db /var/lib/runtime-guard/runtime-guard.db \
  --type file_write \
  --limit 20
```

## Back Up

The service uses SQLite WAL mode. Prefer SQLite's online backup command instead
of copying only the main database file while the service is running:

```sh
sudo install -d -o root -g root -m 0700 /var/backups/runtime-guard
sudo sqlite3 /var/lib/runtime-guard/runtime-guard.db \
  ".backup '/var/backups/runtime-guard/runtime-guard-$(date -u +%Y%m%dT%H%M%SZ).db'"
```

Confirm backup permissions stay private:

```sh
sudo chmod 0600 /var/backups/runtime-guard/runtime-guard-*.db
```

## Retention

The current MVP does not automatically prune stored events or incidents. Do not
delete rows from a production database without first taking a backup. Event rows
are linked to incidents; deleting old events can remove evidence links through
SQLite foreign-key cascades.

If a host needs retention limits before automatic pruning is implemented, use a
fresh stress database to choose collector tuning first. Prefer reducing
excessive event volume with validated collector settings over manually deleting
production evidence.

## Compaction

After a deliberate manual cleanup, stop the service before compacting:

```sh
sudo systemctl stop runtime-guard.service
sudo sqlite3 /var/lib/runtime-guard/runtime-guard.db 'PRAGMA wal_checkpoint(TRUNCATE); VACUUM;'
sudo systemctl start runtime-guard.service
```

Recheck growth after restart:

```sh
sudo /usr/local/bin/runtime-guard db-stats \
  --db /var/lib/runtime-guard/runtime-guard.db
```

## Journal Retention

The packaged service uses `--quiet-events`, so journald receives startup
messages, periodic runtime stats, incidents, and shutdown stats rather than
every normalized event. Use normal journald policy for retention. For a one-time
manual cleanup:

```sh
sudo journalctl --vacuum-time=30d
```

Do not rely on journald as the incident database. The SQLite database remains
the source of stored event and incident history.
