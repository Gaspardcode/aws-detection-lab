import json

import pytest

from tests.loader import ROOT, load_lambda

runner = load_lambda("athena_runner")


def test_parse_threshold():
    assert runner.parse_threshold("-- threshold: 42\nSELECT 1") == 42
    with pytest.raises(ValueError):
        runner.parse_threshold("SELECT 1")


def test_to_rows_skips_header():
    rs = {"Rows": [{"Data": [{"VarCharValue": "principal"}, {"VarCharValue": "n"}]},
                   {"Data": [{"VarCharValue": "arn:x"}, {"VarCharValue": "7"}]}]}
    assert runner.to_rows(rs) == [{"principal": "arn:x", "n": "7"}]


class FakeAthena:
    def __init__(self, rows_by_query):
        self.rows_by_query, self.started = rows_by_query, []

    def start_query_execution(self, QueryString, **_):
        self.started.append(QueryString)
        return {"QueryExecutionId": f"q{len(self.started)}"}

    def get_query_execution(self, QueryExecutionId):
        return {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}}

    def get_query_results(self, QueryExecutionId):
        idx = int(QueryExecutionId[1:]) - 1
        rows = self.rows_by_query[idx]
        header = {"Data": [{"VarCharValue": "principal"}, {"VarCharValue": "heure"}, {"VarCharValue": "n"}]}
        return {"ResultSet": {"Rows": [header] + [{"Data": [{"VarCharValue": r[k]} for k in ("principal", "heure", "n")]} for r in rows]}}


def test_handler_sends_only_alerts_over_threshold(monkeypatch):
    monkeypatch.setattr(runner, "RULES_DIR", ROOT / "rules")  # en prod, Terraform copie les règles à côté du handler
    queries = runner.load_queries()
    assert len(queries) == 3
    monkeypatch.setenv("WORKGROUP", "wg"); monkeypatch.setenv("DATABASE", "adl_logs"); monkeypatch.setenv("TRIAGE_FUNCTION", "triage")
    rules = list(queries)  # ordre trié = ordre de lancement
    rows = []
    for rid in rules:
        d = ROOT / "rules" / rid
        rows.append(json.loads((d / ("positive.json" if rid.startswith("006") else "negative.json")).read_text())["rows"])
    athena, invoked = FakeAthena(rows), []

    class FakeLambda:
        def invoke(self, **kw):
            invoked.append(kw)

    monkeypatch.setattr(runner, "client", lambda n: athena if n == "athena" else FakeLambda())
    out = runner.handler()
    assert out == {"alerts": 1, "failed": []}
    payload = json.loads(invoked[0]["Payload"])
    assert payload["rule_id"].startswith("006") and payload["event"]["source"] == "adl.athena"
    assert payload["event"]["detail"]["threshold"] == 100
