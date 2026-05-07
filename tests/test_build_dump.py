from pathlib import Path
import sys
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))

import scripts.build_agent_dump as m


def test_final_export_uses_databases_and_sanitize_called(tmp_path):
    policy = {
        "database_allowlist": ["ig_user", "ig_wallet"],
        "partial_tables": {"ig_wallet.Transaction": {"pk": "TransactionID", "rows": 100}},
        "sanitize": {"explicit_column_rules": {}},
    }
    pol = tmp_path / "p.yml"
    pol.write_text("{\"database_allowlist\":[\"ig_user\",\"ig_wallet\"],\"partial_tables\":{\"ig_wallet.Transaction\":{\"pk\":\"TransactionID\",\"rows\":100}},\"sanitize\":{\"explicit_column_rules\":{}}}")

    calls = []

    def fake_run_sql(defaults, sql):
        if "information_schema.tables" in sql:
            return "ig_wallet\tTransaction\t500\nig_user\tUsers\t200\n"
        if "DROP DATABASE" in sql or "CREATE DATABASE" in sql:
            return ""
        return ""

    class P:
        def __init__(self, cmd, stdout=None):
            calls.append(cmd)
            self.stdout = open('/dev/null','rb') if stdout else None
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            if self.stdout:
                self.stdout.close()
            return False
        def wait(self):
            return 0

    out = tmp_path / "out.sql.gz"
    argv = ["x","--policy",str(pol),"--source-defaults-file","a","--local-defaults-file","b","--output",str(out),"--allow-destructive-local-recreate"]
    with patch.object(sys, "argv", argv), patch.object(m, "run_sql", side_effect=fake_run_sql), patch.object(m, "stream_dump", return_value=None), patch.object(m, "sanitize_local", return_value={"cells_updated":1}), patch.object(m, "leak_check", return_value=None), patch("scripts.build_agent_dump.ensure_salt", return_value=b"s"), patch("subprocess.Popen", P):
        m.main()
    assert any("--databases" in c for c in calls)


def test_sanitize_failure_blocks_export(tmp_path):
    pol = tmp_path / "p.yml"
    pol.write_text("{\"database_allowlist\":[\"ig_user\"],\"partial_tables\":{},\"sanitize\":{\"explicit_column_rules\":{}}}")
    def fake_run_sql(defaults, sql):
        if "information_schema.tables" in sql:
            return "ig_user\tUsers\t200\n"
        return ""
    argv = ["x","--policy",str(pol),"--source-defaults-file","a","--local-defaults-file","b","--output",str(tmp_path/'o.gz'),"--allow-destructive-local-recreate"]
    with patch.object(sys, "argv", argv), patch.object(m, "run_sql", side_effect=fake_run_sql), patch.object(m, "stream_dump", return_value=None), patch.object(m, "sanitize_local", side_effect=RuntimeError("boom")), patch("scripts.build_agent_dump.ensure_salt", return_value=b"s"):
        try:
            m.main()
            assert False
        except RuntimeError:
            pass
