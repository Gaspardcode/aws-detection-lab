"""Chaque règle : fichiers présents, fixtures positive/négative cohérentes, aucune donnée réelle."""
import json
import re
from pathlib import Path

import pytest
import yaml

from tests.loader import load_lambda
from tests.matcher import matches

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted(p for p in (ROOT / "rules").iterdir() if p.is_dir())
PATTERN_RULES = [r for r in RULES if (r / "pattern.json").exists()]
QUERY_RULES = [r for r in RULES if (r / "query.sql").exists()]
ids = lambda rules: [r.name for r in rules]  # noqa: E731


def load(path):
    return json.loads(path.read_text())


def test_rule_counts():
    assert len(PATTERN_RULES) == 5 and len(QUERY_RULES) == 3


@pytest.mark.parametrize("rule", RULES, ids=ids(RULES))
def test_required_files(rule):
    for name in ("rule.yml", "meta.json", "positive.json", "negative.json", "runbook.md"):
        assert (rule / name).exists(), name
    assert (rule / "pattern.json").exists() != (rule / "query.sql").exists(), "un seul de pattern.json / query.sql"


@pytest.mark.parametrize("rule", RULES, ids=ids(RULES))
def test_meta_matches_sigma(rule):
    meta, sigma = load(rule / "meta.json"), yaml.safe_load((rule / "rule.yml").read_text())
    assert meta["id"] == rule.name and sigma["id"] == rule.name.split("-")[0]
    assert meta["title"] == sigma["title"]
    attack_ids = {t.split(".", 1)[1].upper() for t in sigma["tags"] if t.startswith("attack.t")}
    assert attack_ids == set(meta["attack"])
    assert meta["severity"] == sigma["level"]
    assert meta["severity"] in ("critical", "high", "medium", "low")


@pytest.mark.parametrize("rule", RULES, ids=ids(RULES))
def test_response_only_for_critical(rule):
    meta = load(rule / "meta.json")
    if meta["response"]:
        assert meta["severity"] == "critical", "la réponse automatique est réservée aux règles critiques"


@pytest.mark.parametrize("rule", RULES, ids=ids(RULES))
def test_runbook_not_empty(rule):
    text = (rule / "runbook.md").read_text()
    assert text.startswith("# ") and "Contenir" in text or "Vérifier" in text


@pytest.mark.parametrize("rule", PATTERN_RULES, ids=ids(PATTERN_RULES))
def test_pattern_positive_negative(rule):
    pattern = load(rule / "pattern.json")
    assert matches(pattern, load(rule / "positive.json")), "la fixture positive doit déclencher la règle"
    assert not matches(pattern, load(rule / "negative.json")), "la fixture négative ne doit pas déclencher"


@pytest.mark.parametrize("rule", QUERY_RULES, ids=ids(QUERY_RULES))
def test_query_threshold_consistent(rule):
    runner = load_lambda("athena_runner")
    parse_threshold, rows_over_threshold = runner.parse_threshold, runner.rows_over_threshold
    sql, meta = (rule / "query.sql").read_text(), load(rule / "meta.json")
    thr = parse_threshold(sql)
    assert thr == meta["threshold"]
    assert f"HAVING" in sql and str(thr) in sql.split("HAVING")[1], "le seuil de l'en-tête doit être celui du HAVING"
    assert rows_over_threshold(load(rule / "positive.json")["rows"], thr)
    assert not rows_over_threshold(load(rule / "negative.json")["rows"], thr)


def test_no_real_identifiers_in_repo():
    """Fixtures et règles : seuls les identifiants fictifs (plages de documentation) sont autorisés."""
    allowed_accounts = {"111122223333", "999988887777", "000000000000"}  # 0* : fin de l'UUID factice
    bad = []
    for path in list((ROOT / "rules").rglob("*")) + list((ROOT / "tests").rglob("*.py")):
        if not path.is_file():
            continue
        text = path.read_text()
        bad += [f"{path.name}: compte {m}" for m in re.findall(r"(?<![0-9a-z])\d{12}(?![0-9])", text) if m not in allowed_accounts]
        for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
            if not ip.startswith(("203.0.113.", "192.0.2.", "198.51.100.", "10.", "0.", "172.", "192.168.")) and ip.count(".") == 3 and not re.fullmatch(r"\d\.\d+\.\d+\.\d+", ip):
                bad.append(f"{path.name}: IP {ip}")
    assert not bad, bad
