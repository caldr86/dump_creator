#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import yaml


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build agent-safe MariaDB dump")
    p.add_argument("--policy", required=True)
    p.add_argument("--source-defaults-file", required=True)
    p.add_argument("--local-defaults-file", required=True)
    p.add_argument("--staging-db", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-dump", action="store_true")
    p.add_argument("--skip-sanitize", action="store_true")
    p.add_argument("--keep-staging", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def check_defaults_file(path: str) -> None:
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Defaults file not found: {p}")
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode != 0o600:
        raise PermissionError(f"Defaults file must be chmod 600: {p} (current: {oct(mode)})")


def run_cmd(args: list[str], stdin=None, stdout=None, verbose: bool = False) -> subprocess.Popen:
    if verbose:
        print("RUN:", " ".join(args))
    return subprocess.Popen(args, stdin=stdin, stdout=stdout)


def run_sql(defaults_file: str, sql: str) -> str:
    cmd = ["mariadb", f"--defaults-extra-file={str(Path(defaults_file).expanduser())}", "-N", "-e", sql]
    out = subprocess.check_output(cmd, text=True)
    return out


def fetch_metadata(source_defaults: str, allowlist: list[str]) -> list[dict[str, Any]]:
    dbs = ",".join(f"'{db}'" for db in allowlist)
    sql = f"""
    SELECT table_schema, table_name, table_type, engine,
           COALESCE(table_rows,0), COALESCE(data_length,0), COALESCE(index_length,0), COALESCE(auto_increment,0)
    FROM information_schema.tables
    WHERE table_schema IN ({dbs})
      AND table_type='BASE TABLE'
    ORDER BY table_schema, table_name;
    """
    rows = run_sql(source_defaults, sql).strip().splitlines()
    result = []
    for row in rows:
        s, t, table_type, engine, table_rows, data_len, index_len, auto_inc = row.split("\t")
        result.append(
            {
                "schema": s,
                "table": t,
                "table_type": table_type,
                "engine": engine,
                "table_rows": int(table_rows),
                "data_length": int(data_len),
                "index_length": int(index_len),
                "auto_increment": int(auto_inc),
            }
        )
    return result


def stream_dump_to_local(source_defaults: str, local_defaults: str, dump_args: list[str], verbose: bool) -> None:
    src = ["mariadb-dump", f"--defaults-extra-file={str(Path(source_defaults).expanduser())}"] + dump_args
    dst = ["mariadb", f"--defaults-extra-file={str(Path(local_defaults).expanduser())}"]
    p1 = run_cmd(src, stdout=subprocess.PIPE, verbose=verbose)
    p2 = run_cmd(dst, stdin=p1.stdout, verbose=verbose)
    assert p1.stdout is not None
    p1.stdout.close()
    rc2 = p2.wait()
    rc1 = p1.wait()
    if rc1 != 0 or rc2 != 0:
        raise RuntimeError(f"Pipe failed: rc1={rc1}, rc2={rc2}")


def main() -> None:
    args = parse_args()
    policy = yaml.safe_load(Path(args.policy).read_text())
    check_defaults_file(args.source_defaults_file)
    check_defaults_file(args.local_defaults_file)

    allowlist = policy["database_allowlist"]
    partial_rules = policy["partial_tables"]
    metadata = fetch_metadata(args.source_defaults_file, allowlist)
    by_name = {f"{m['schema']}.{m['table']}": m for m in metadata}

    partial_floors: dict[str, int] = {}
    for fqtn, rule in partial_rules.items():
        auto_inc = by_name[fqtn]["auto_increment"]
        floor = max(1, auto_inc - int(rule["rows"]))
        partial_floors[fqtn] = floor

    print("=== Dump Plan ===")
    for m in metadata:
        fqtn = f"{m['schema']}.{m['table']}"
        if fqtn in partial_rules:
            print(f"PARTIAL {fqtn} WHERE {partial_rules[fqtn]['pk']} >= {partial_floors[fqtn]}")
        else:
            print(f"FULL    {fqtn}")

    if args.dry_run:
        return

    if not args.skip_dump:
        run_sql(args.local_defaults_file, f"DROP DATABASE IF EXISTS `{args.staging_db}`; CREATE DATABASE `{args.staging_db}`;")

        stream_dump_to_local(
            args.source_defaults_file,
            args.local_defaults_file,
            ["--single-transaction", "--quick", "--skip-lock-tables", "--no-data", "--databases", *allowlist],
            args.verbose,
        )

        for m in metadata:
            db = m["schema"]
            table = m["table"]
            fqtn = f"{db}.{table}"
            dump_args = ["--single-transaction", "--quick", "--skip-lock-tables", "--no-create-info", db, table]
            if fqtn in partial_rules:
                pk = partial_rules[fqtn]["pk"]
                dump_args.extend(["--where", f"{pk} >= {partial_floors[fqtn]}"])
            stream_dump_to_local(args.source_defaults_file, args.local_defaults_file, dump_args, args.verbose)

    if not args.skip_sanitize:
        print("Sanitization phase placeholder: run UPDATE statements using scripts/sanitizer.py helpers.")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dump_cmd = [
        "mariadb-dump",
        f"--defaults-extra-file={str(Path(args.local_defaults_file).expanduser())}",
        "--single-transaction",
        "--quick",
        "--skip-lock-tables",
        args.staging_db,
    ]
    with subprocess.Popen(dump_cmd, stdout=subprocess.PIPE) as p:
        assert p.stdout is not None
        with gzip.open(out_path, "wb") as gz:
            shutil.copyfileobj(p.stdout, gz)
        rc = p.wait()
        if rc != 0:
            raise RuntimeError("Failed to export final dump")

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print("=== Summary ===")
    print(json.dumps({"partial_floors": partial_floors, "output": str(out_path), "size_mb": round(size_mb, 2)}, indent=2))


if __name__ == "__main__":
    main()
