# Agent-safe MariaDB dump builder (v0)

## Requirements
- Python 3.11+
- `mariadb` CLI
- `mariadb-dump` CLI

## Credentials (local only)
Do **not** store credentials in this repo.
Use local MariaDB client option files:
- `~/.ig-replica.cnf` (remote read-only replica)
- `~/.ig-local.cnf` (local MariaDB)

Both files must be `chmod 600`.

Example format:

```ini
[client]
host=...
port=3306
user=...
password=...
ssl=true
```

## Dry run

```bash
python scripts/build_agent_dump.py \
  --policy dump-policy.yml \
  --source-defaults-file ~/.ig-replica.cnf \
  --local-defaults-file ~/.ig-local.cnf \
  --staging-db agent_dump_staging \
  --output dump-output/agent-safe.sql.gz \
  --dry-run
```

Dry-run prints exactly which tables are full dump vs partial dump and the computed PK floors.

## Real run

```bash
python scripts/build_agent_dump.py \
  --policy dump-policy.yml \
  --source-defaults-file ~/.ig-replica.cnf \
  --local-defaults-file ~/.ig-local.cnf \
  --staging-db agent_dump_staging \
  --output dump-output/agent-safe.sql.gz
```

## Notes
- v0 uses metadata queries and PK slicing for four monster tables.
- v0 streams remote dump directly into local MariaDB where possible.
- Raw PII temporarily exists in the local staging DB **until sanitization completes**.
- Final output is intended to contain sanitized data only.


## Safety warning
Use a **dedicated local MariaDB instance/container** for this process. The script can drop and recreate only allowlisted schemas when `--allow-destructive-local-recreate` is passed.
