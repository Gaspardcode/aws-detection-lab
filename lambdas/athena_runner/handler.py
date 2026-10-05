"""Lambda "athena_runner" : exécute chaque rules/*/query.sql, alerte via triage quand le seuil est dépassé.

Convention des fichiers query.sql : en-tête de commentaires
    -- threshold: <entier>     seuil au-delà duquel une ligne devient une alerte
La requête renvoie les colonnes (principal, heure, n).
Variables d'environnement : WORKGROUP, DATABASE, TRIAGE_FUNCTION, QUERY_TIMEOUT
"""
import json
import logging
import os
import re
import time
from pathlib import Path

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

RULES_DIR = Path(__file__).parent / "rules"


def client(name):
    return boto3.client(name)


def parse_threshold(sql):
    m = re.search(r"^--\s*threshold:\s*(\d+)\s*$", sql, re.MULTILINE)
    if not m:
        raise ValueError("en-tête '-- threshold: N' manquant")
    return int(m.group(1))


def rows_over_threshold(rows, threshold):
    return [r for r in rows if float(r["n"]) > threshold]


def to_rows(result_set):
    """Athena renvoie l'en-tête comme première ligne."""
    raw = [[c.get("VarCharValue") for c in row["Data"]] for row in result_set["Rows"]]
    if not raw:
        return []
    header, body = raw[0], raw[1:]
    return [dict(zip(header, r)) for r in body]


def load_queries():
    queries = {}
    for path in sorted(RULES_DIR.glob("*/query.sql")):
        sql = path.read_text()
        queries[path.parent.name] = {"sql": sql, "threshold": parse_threshold(sql)}
    return queries


def run_queries(queries, athena, timeout):
    ids = {}
    for rule_id, q in queries.items():
        ids[rule_id] = athena.start_query_execution(
            QueryString=q["sql"], WorkGroup=os.environ["WORKGROUP"],
            QueryExecutionContext={"Database": os.environ["DATABASE"]})["QueryExecutionId"]
    deadline = time.time() + timeout
    results, pending = {}, dict(ids)
    while pending and time.time() < deadline:
        for rule_id, qid in list(pending.items()):
            state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
            if state == "SUCCEEDED":
                results[rule_id] = to_rows(athena.get_query_results(QueryExecutionId=qid)["ResultSet"])
                del pending[rule_id]
            elif state in ("FAILED", "CANCELLED"):
                log.error("requête %s en échec: %s", rule_id, state)
                results[rule_id] = None
                del pending[rule_id]
        if pending:
            time.sleep(2)
    for rule_id in pending:
        log.error("requête %s : délai dépassé", rule_id)
        results[rule_id] = None
    return results


def handler(event=None, _ctx=None):
    queries = load_queries()
    results = run_queries(queries, client("athena"), int(os.environ.get("QUERY_TIMEOUT", "240")))
    sent, failed = 0, []
    for rule_id, rows in results.items():
        if rows is None:
            failed.append(rule_id)
            continue
        for row in rows_over_threshold(rows, queries[rule_id]["threshold"]):
            payload = {"rule_id": rule_id, "event": {
                "source": "adl.athena", "detail-type": "Athena scheduled query",
                "detail": {"rule_id": rule_id, "principal": row.get("principal"), "heure": row.get("heure"),
                           "n": row.get("n"), "threshold": queries[rule_id]["threshold"]}}}
            client("lambda").invoke(FunctionName=os.environ["TRIAGE_FUNCTION"], InvocationType="Event",
                                    Payload=json.dumps(payload).encode())
            sent += 1
    return {"alerts": sent, "failed": failed}
