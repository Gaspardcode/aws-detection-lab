import json

import boto3
import pytest
from moto import mock_aws

from pathlib import Path

from tests.loader import load_lambda

triage = load_lambda("triage")
ROOT = Path(__file__).resolve().parent.parent
ACC = "111122223333"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-north-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    for v in ("DEDUP_TABLE", "WEBHOOK_PARAM", "RESPONSE_FUNCTION", "ENRICH_HISTORY"):
        monkeypatch.delenv(v, raising=False)
    # packaging : les meta.json sont copiés à côté de handler.py par Terraform ; en test on pointe vers rules/
    monkeypatch.setattr(triage, "RULES_DIR", ROOT / "rules")


def fixture(rule, name="positive"):
    return json.loads((ROOT / "rules" / rule / f"{name}.json").read_text())


def test_cloudtrail_alert_fields():
    alert = triage.build_alert("003-cloudtrail-tamper", fixture("003-cloudtrail-tamper"))
    assert alert["severity"] == "critical"
    assert alert["actions"] == ["disable_access_key"]
    assert alert["context"]["user_name"] == "dev-adl"
    assert alert["context"]["access_key_id"] == "AKIAEXAMPLEEXAMPLE00"
    assert alert["fields"]["appel"] == "StopLogging"


def test_bucket_policy_external_is_critical():
    alert = triage.build_alert("005-bucket-policy-changed", fixture("005-bucket-policy-changed"))
    assert alert["severity"] == "critical"
    assert alert["fields"]["principaux_externes"] == ["arn:aws:iam::999988887777:root"]
    assert alert["context"]["bucket"] == f"adl-patients-{ACC}"


def test_bucket_policy_internal_is_ignored():
    ev = fixture("005-bucket-policy-changed")
    ev["detail"]["requestParameters"]["bucketPolicy"]["Statement"][0]["Principal"] = {"AWS": f"arn:aws:iam::{ACC}:role/adl-app"}
    assert triage.build_alert("005-bucket-policy-changed", ev)["severity"] == "info"
    assert triage.handler({"rule_id": "005-bucket-policy-changed", "event": ev})["status"] == "ignored"


def test_wildcard_principal_is_external():
    assert triage.external_principals({"Statement": [{"Effect": "Allow", "Principal": "*"}]}, ACC) == ["*"]
    assert triage.external_principals({"Statement": [{"Effect": "Deny", "Principal": "*"}]}, ACC) == []


def test_athena_alert():
    event = {"source": "adl.athena", "detail": {"principal": "arn:aws:iam::111122223333:user/lab/dev-adl",
                                                "heure": "2026-10-10 14:00:00.000", "n": "480", "threshold": 100}}
    alert = triage.build_alert("006-s3-getobject-massive", event)
    assert alert["severity"] == "high" and alert["actions"] == []
    assert alert["dedup_key"].endswith("2026-10-10 14:00:00.000")


def test_guardduty_credential_exfiltration_isolates_instance():
    event = {"source": "aws.guardduty", "detail": {
        "severity": 8.0, "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "title": "Credentials exfiltrated", "resource": {"instanceDetails": {"instanceId": "i-0123456789abcdef0"}}}}
    alert = triage.build_alert("guardduty", event)
    assert alert["severity"] == "critical" and alert["actions"] == ["isolate_instance"]
    assert alert["context"]["instance_id"] == "i-0123456789abcdef0"


def test_instance_of():
    assert triage.instance_of(f"arn:aws:sts::{ACC}:assumed-role/adl-app/i-0abc") == "i-0abc"
    assert triage.instance_of(f"arn:aws:iam::{ACC}:user/lab/dev-adl") is None


@mock_aws
def test_dedup_with_dynamodb(monkeypatch):
    ddb = boto3.client("dynamodb")
    ddb.create_table(TableName="dedup", BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}])
    monkeypatch.setenv("DEDUP_TABLE", "dedup")
    sent = []
    monkeypatch.setattr(triage, "send_discord", lambda p: sent.append(p))
    msg = {"rule_id": "003-cloudtrail-tamper", "event": fixture("003-cloudtrail-tamper")}
    assert triage.handler(msg)["status"] == "alerted"
    assert triage.handler(msg)["status"] == "duplicate"
    assert len(sent) == 1


@mock_aws
def test_response_only_triggered_for_critical(monkeypatch):
    monkeypatch.setenv("RESPONSE_FUNCTION", "adl-response")
    calls = []

    class FakeLambda:
        def invoke(self, **kw):
            calls.append(kw)

    monkeypatch.setattr(triage, "client", lambda name: FakeLambda() if name == "lambda" else boto3.client(name))
    monkeypatch.setattr(triage, "send_discord", lambda p: None)
    triage.handler({"rule_id": "003-cloudtrail-tamper", "event": fixture("003-cloudtrail-tamper")})
    assert len(calls) == 1
    payload = json.loads(calls[0]["Payload"])
    assert payload["actions"] == ["disable_access_key"] and calls[0]["InvocationType"] == "Event"
    # règle haute : pas de réponse
    triage.handler({"rule_id": "004-flowlogs-deleted", "event": fixture("004-flowlogs-deleted")})
    assert len(calls) == 1


@mock_aws
def test_enrich_adds_user_tags():
    iam = boto3.client("iam")
    iam.create_user(UserName="dev-adl", Tags=[{"Key": "Role", "Value": "maillon-faible"}])
    alert = triage.build_alert("003-cloudtrail-tamper", fixture("003-cloudtrail-tamper"))
    alert["actor"]["type"] = "IAMUser"
    assert triage.enrich(alert)["fields"]["tags_utilisateur"] == {"Role": "maillon-faible"}


def test_discord_payload_is_readable():
    alert = triage.build_alert("003-cloudtrail-tamper", fixture("003-cloudtrail-tamper"))
    embed = triage.discord_payload(alert)["embeds"][0]
    assert embed["title"].startswith("[CRITICAL]")
    assert "SIMULÉE" in embed["description"] and "runbook" in embed["description"].lower()
