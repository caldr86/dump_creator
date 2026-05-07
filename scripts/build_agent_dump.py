#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


from scripts.sanitizer import ensure_salt, redact_by_rule, sanitize_maybe_json_text

TEXT_TYPES = {"text", "tinytext", "mediumtext", "longtext", "json"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build agent-safe MariaDB dump")
    p.add_argument("--policy", required=True)
    p.add_argument("--source-defaults-file", required=True)
    p.add_argument("--local-defaults-file", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--salt-file", default="~/.agent-dump-salt")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-dump", action="store_true")
    p.add_argument("--skip-sanitize", action="store_true")
    p.add_argument("--allow-destructive-local-recreate", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def run_sql(defaults_file: str, sql: str) -> str:
    cmd = ["mariadb", f"--defaults-extra-file={str(Path(defaults_file).expanduser())}", "-N", "-e", sql]
    return subprocess.check_output(cmd, text=True)


def fetch_tables(defaults_file: str, allowlist: list[str]) -> list[dict[str, Any]]:
    dbs = ",".join(f"'{db}'" for db in allowlist)
    sql = f"SELECT table_schema,table_name,COALESCE(auto_increment,0) FROM information_schema.tables WHERE table_schema IN ({dbs}) AND table_type='BASE TABLE' ORDER BY 1,2"
    rows = run_sql(defaults_file, sql).strip().splitlines()
    out = []
    for r in rows:
        s, t, ai = r.split("\t")
        out.append({"schema": s, "table": t, "auto_increment": int(ai)})
    return out


def stream_dump(source_defaults: str, local_defaults: str, dump_args: list[str]) -> None:
    p1 = subprocess.Popen(["mariadb-dump", f"--defaults-extra-file={source_defaults}", *dump_args], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["mariadb", f"--defaults-extra-file={local_defaults}"], stdin=p1.stdout)
    assert p1.stdout is not None
    p1.stdout.close()
    if p2.wait() != 0 or p1.wait() != 0:
        raise RuntimeError("Dump pipeline failed")


def sanitize_local(local_defaults: str, policy: dict[str, Any], salt: bytes) -> dict[str, int]:
    allowlist = policy["database_allowlist"]
    explicit_rules = policy.get("sanitize", {}).get("explicit_column_rules", {})
    dbs = ",".join(f"'{db}'" for db in allowlist)
    cols_sql = f"SELECT table_schema,table_name,column_name,data_type FROM information_schema.columns WHERE table_schema IN ({dbs})"
    rows = run_sql(local_defaults, cols_sql).strip().splitlines()
    counters = {"cells_updated": 0, "tables_touched": 0}

    by_table: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for r in rows:
        s, t, c, dt = r.split("\t")
        by_table.setdefault((s, t), []).append((c, dt.lower()))

    for (schema, table), cols in by_table.items():
        pk_sql = f"SELECT k.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage k ON tc.constraint_name=k.constraint_name AND tc.table_schema=k.table_schema AND tc.table_name=k.table_name WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema='{schema}' AND tc.table_name='{table}' ORDER BY k.ordinal_position LIMIT 1"
        pk = run_sql(local_defaults, pk_sql).strip()
        if not pk:
            continue
        last = 0
        touched = False
        while True:
            q = f"SELECT `{pk}` FROM `{schema}`.`{table}` WHERE `{pk}` > {last} ORDER BY `{pk}` LIMIT 500"
            ids = [x.strip() for x in run_sql(local_defaults, q).strip().splitlines() if x.strip()]
            if not ids:
                break
            id_list = ",".join(ids)
            sel_cols = [pk] + [c for c, _ in cols]
            sel = ",".join(f"`{c}`" for c in sel_cols)
            data_sql = f"SELECT {sel} FROM `{schema}`.`{table}` WHERE `{pk}` IN ({id_list})"
            data_rows = run_sql(local_defaults, data_sql).splitlines()
            for raw in data_rows:
                vals = raw.split("\t")
                row_id = vals[0]
                updates = []
                for (col, dtype), val in zip(cols, vals[1:]):
                    fq = f"{schema}.{table}.{col}"
                    rule = explicit_rules.get(fq)
                    new_val = val
                    if rule:
                        new_val = redact_by_rule(val, rule, fq, salt)
                    elif dtype in TEXT_TYPES:
                        new_val = sanitize_maybe_json_text(val, fq, salt)
                    elif any(x in col.lower() for x in ["email", "phone", "mobile", "password", "token", "secret", "dbpass", "auth"]):
                        mapped = "email" if "email" in col.lower() else "phone" if ("phone" in col.lower() or "mobile" in col.lower()) else "password" if "password" in col.lower() else "token"
                        new_val = redact_by_rule(val, mapped, fq, salt)
                    if new_val != val:
                        touched = True
                        counters["cells_updated"] += 1
                        if new_val is None:
                            updates.append(f"`{col}`=NULL")
                        else:
                            esc = str(new_val).replace("\\", "\\\\").replace("'", "\\'")
                            updates.append(f"`{col}`='{esc}'")
                if updates:
                    up_sql = f"UPDATE `{schema}`.`{table}` SET {', '.join(updates)} WHERE `{pk}`={row_id};"
                    run_sql(local_defaults, up_sql)
            last = int(ids[-1])
        if touched:
            counters["tables_touched"] += 1
    return counters


def leak_check(local_defaults: str, policy: dict[str, Any]) -> None:
    allowlist = policy["database_allowlist"]
    explicit_rules = policy.get("sanitize", {}).get("explicit_column_rules", {})
    dbs = ",".join(f"'{db}'" for db in allowlist)
    cols_sql = f"SELECT table_schema,table_name,column_name,data_type FROM information_schema.columns WHERE table_schema IN ({dbs}) AND data_type IN ('char','varchar','text','tinytext','mediumtext','longtext','json')"
    rows = run_sql(local_defaults, cols_sql).strip().splitlines()
    bad_emails = []
    bad_tokens = []
    for r in rows:
        s, t, c, _ = r.split("\t")
        q = f"SELECT COUNT(*) FROM `{s}`.`{t}` WHERE `{c}` REGEXP '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{{2,}}' AND `{c}` NOT LIKE '%@example.test%'"
        cnt = int(run_sql(local_defaults, q).strip() or "0")
        if cnt > 0:
            bad_emails.append((s, t, c, cnt))
        rule = explicit_rules.get(f"{s}.{t}.{c}")
        if rule in {"token", "password", "secret"}:
            q2 = f"SELECT COUNT(*) FROM `{s}`.`{t}` WHERE `{c}` IS NOT NULL AND `{c}` NOT IN ('[REDACTED]','[REDACTED_PASSWORD]')"
            c2 = int(run_sql(local_defaults, q2).strip() or "0")
            if c2 > 0:
                bad_tokens.append((s, t, c, c2))
    if bad_emails or bad_tokens:
        raise RuntimeError(f"Leak check failed: emails={bad_emails} token_cols={bad_tokens}")


def main() -> None:
    args = parse_args()
    text = Path(args.policy).read_text()
    try:
        import yaml  # type: ignore
        policy = yaml.safe_load(text)
    except ModuleNotFoundError:
        policy = json.loads(text)
    allowlist = policy["database_allowlist"]
    source_defaults = str(Path(args.source_defaults_file).expanduser())
    local_defaults = str(Path(args.local_defaults_file).expanduser())
    salt = ensure_salt(args.salt_file)

    tables = fetch_tables(source_defaults, allowlist)
    partial_rules = policy["partial_tables"]
    by_name = {f"{t['schema']}.{t['table']}": t for t in tables}
    floors = {fq: max(1, by_name[fq]["auto_increment"] - int(rule["rows"])) for fq, rule in partial_rules.items()}

    print("=== Dump Plan ===")
    for t in tables:
        fq = f"{t['schema']}.{t['table']}"
        if fq in partial_rules:
            print(f"PARTIAL {fq} WHERE {partial_rules[fq]['pk']} >= {floors[fq]}")
        else:
            print(f"FULL    {fq}")
    if args.dry_run:
        return
    if not args.allow_destructive_local_recreate and not args.skip_dump:
        raise RuntimeError("Refusing destructive local recreate without --allow-destructive-local-recreate")

    if not args.skip_dump:
        for db in allowlist:
            run_sql(local_defaults, f"DROP DATABASE IF EXISTS `{db}`; CREATE DATABASE `{db}`;")
        stream_dump(source_defaults, local_defaults, ["--single-transaction", "--quick", "--skip-lock-tables", "--no-data", "--databases", *allowlist])
        for t in tables:
            db, table = t["schema"], t["table"]
            fq = f"{db}.{table}"
            a = ["--single-transaction", "--quick", "--skip-lock-tables", "--no-create-info", db, table]
            if fq in partial_rules:
                a += ["--where", f"{partial_rules[fq]['pk']} >= {floors[fq]}"]
            stream_dump(source_defaults, local_defaults, a)

    if not args.skip_sanitize:
        stats = sanitize_local(local_defaults, policy, salt)
        print("Sanitizer counters:", json.dumps(stats))
    else:
        raise RuntimeError("--skip-sanitize is unsafe for release blocker patch")

    leak_check(local_defaults, policy)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dump_cmd = ["mariadb-dump", f"--defaults-extra-file={local_defaults}", "--single-transaction", "--quick", "--skip-lock-tables", "--databases", *allowlist]
    with subprocess.Popen(dump_cmd, stdout=subprocess.PIPE) as p:
        assert p.stdout is not None
        with gzip.open(out_path, "wb") as gz:
            shutil.copyfileobj(p.stdout, gz)
        if p.wait() != 0:
            raise RuntimeError("Failed export")


if __name__ == "__main__":
    main()
