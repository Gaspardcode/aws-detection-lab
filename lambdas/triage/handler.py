"""Lambda "triage" : enrichit, déduplique, fixe la sévérité, alerte Discord, déclenche la réponse.

Entrées (toutes de la forme {"rule_id": ..., "event": <événement EventBridge>}) :
  - règles EventBridge temps réel (enveloppe ajoutée par un input transformer) ;
  - findings GuardDuty (rule_id = "guardduty") ;
  - alertes volumétriques envoyées par athena_runner (source "adl.athena").

Variables d'environnement (toutes facultatives, pour pouvoir tester hors AWS) :
  DEDUP_TABLE, WEBHOOK_PARAM, RESPONSE_FUNCTION, ENRICH_HISTORY, RUNBOOK_BASE_URL
"""
import json
import logging
import os
import time
import urllib.request
from pathlib import Path

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

RULES_DIR = Path(__file__).parent / "rules"
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
DEDUP_SECONDS = {"pattern": 900, "query": 25 * 3600, "guardduty": 3600}


def load_meta(rule_id):
    if rule_id == "guardduty":
        return {"id": "guardduty", "title": "Finding GuardDuty", "severity": "medium", "kind": "guardduty",
                "response": [], "runbook": None}
    path = RULES_DIR / rule_id / "meta.json"
    return json.loads(path.read_text())


def client(name):
    return boto3.client(name)


# --------------------------------------------------------------------------- normalisation
def actor_of(detail):
    ident = detail.get("userIdentity", {}) or {}
    return {
        "arn": ident.get("arn"),
        "type": ident.get("type"),
        "user_name": ident.get("userName"),
        "access_key_id": ident.get("accessKeyId"),
    }


def instance_of(actor_arn):
    """Un rôle d'instance a pour session l'ID de l'instance : assumed-role/<rôle>/i-0123..."""
    if actor_arn and "assumed-role/" in actor_arn:
        session = actor_arn.rsplit("/", 1)[-1]
        if session.startswith("i-"):
            return session
    return None


def external_principals(policy, own_account):
    """Principaux d'une politique de bucket qui ne sont pas du compte (ou valent *)."""
    if isinstance(policy, str):
        policy = json.loads(policy)
    found = []
    for st in (policy or {}).get("Statement", []):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        values = []
        if principal == "*":
            values = ["*"]
        elif isinstance(principal, dict):
            for v in principal.values():
                values += v if isinstance(v, list) else [v]
        for v in values:
            if v == "*" or (v.startswith("arn:aws:iam::") and v.split(":")[4] != own_account) \
                    or (v.isdigit() and v != own_account):
                found.append(v)
    return sorted(set(found))


def build_alert(rule_id, event):
    meta = load_meta(rule_id)
    detail = event.get("detail", {})
    source = event.get("source", "")
    alert = {
        "rule_id": rule_id, "title": meta["title"], "severity": meta["severity"], "kind": meta["kind"],
        "attack": meta.get("attack", []), "actions": list(meta.get("response", [])),
        "time": event.get("time") or detail.get("eventTime"), "account": event.get("account"),
        "region": event.get("region"), "runbook": meta.get("runbook"), "context": {}, "fields": {},
    }

    if source == "adl.athena":
        alert["principal"] = detail.get("principal")
        alert["fields"] = {"valeur": detail.get("n"), "seuil": detail.get("threshold"), "heure": detail.get("heure")}
        alert["dedup_key"] = f"{rule_id}|{detail.get('principal')}|{detail.get('heure')}"
        return alert

    if source == "aws.guardduty":
        sev = float(detail.get("severity", 0))
        alert["severity"] = "high" if sev >= 7 else "medium" if sev >= 4 else "low"
        alert["title"] = detail.get("title", alert["title"])
        alert["fields"] = {"type": detail.get("type"), "score": sev}
        instance = (detail.get("resource", {}).get("instanceDetails") or {}).get("instanceId")
        if instance and "InstanceCredentialExfiltration" in detail.get("type", ""):
            alert["severity"] = "critical"
            alert["actions"] = ["isolate_instance"]
            alert["context"]["instance_id"] = instance
        alert["principal"] = instance
        alert["dedup_key"] = f"guardduty|{detail.get('type')}|{instance}"
        return alert

    actor = actor_of(detail)
    params = detail.get("requestParameters") or {}
    alert["principal"] = actor["arn"]
    alert["actor"] = actor
    alert["source_ip"] = detail.get("sourceIPAddress")
    alert["fields"] = {"appel": detail.get("eventName"), "ip": detail.get("sourceIPAddress"),
                       "cible": params.get("userName") or params.get("roleName") or params.get("bucketName")
                       or params.get("name")}
    alert["context"] = {
        "user_name": actor["user_name"], "access_key_id": actor["access_key_id"],
        "instance_id": instance_of(actor["arn"]), "bucket": params.get("bucketName"),
    }
    alert["dedup_key"] = f"{rule_id}|{actor['arn']}|{detail.get('eventName')}"

    if meta.get("inspect") == "bucket_policy_external_principal":
        policy = params.get("bucketPolicy")
        if detail.get("eventName") == "DeleteBucketPolicy":
            alert["fields"]["analyse"] = "politique supprimée"
        else:
            ext = external_principals(policy, event.get("account") or detail.get("recipientAccountId"))
            if not ext:
                alert["severity"] = "info"       # changement interne : journalisé, pas d'alerte
            alert["fields"]["principaux_externes"] = ext or "aucun"
    return alert


# --------------------------------------------------------------------------- enrichissement
def enrich(alert):
    actor = alert.get("actor") or {}
    if actor.get("type") == "IAMUser" and actor.get("user_name"):
        try:
            tags = client("iam").list_user_tags(UserName=actor["user_name"]).get("Tags", [])
            alert["fields"]["tags_utilisateur"] = {t["Key"]: t["Value"] for t in tags}
        except Exception as exc:  # enrichissement : jamais bloquant
            log.warning("tags IAM indisponibles: %s", exc)
    if os.environ.get("ENRICH_HISTORY", "false") == "true" and actor.get("user_name"):
        try:
            import datetime as dt
            now = dt.datetime.now(dt.timezone.utc)
            events = client("cloudtrail").lookup_events(
                LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": actor["user_name"]}],
                StartTime=now - dt.timedelta(hours=24), EndTime=now, MaxResults=50).get("Events", [])
            names = {}
            for e in events:
                names[e["EventName"]] = names.get(e["EventName"], 0) + 1
            alert["fields"]["historique_24h"] = dict(sorted(names.items(), key=lambda kv: -kv[1])[:5])
        except Exception as exc:
            log.warning("historique CloudTrail indisponible: %s", exc)
    return alert


# --------------------------------------------------------------------------- déduplication
def is_duplicate(alert):
    table = os.environ.get("DEDUP_TABLE")
    if not table:
        return False
    now = int(time.time())
    ttl = DEDUP_SECONDS.get(alert["kind"], 900)
    try:
        client("dynamodb").put_item(
            TableName=table,
            Item={"pk": {"S": alert["dedup_key"]}, "ttl": {"N": str(now + ttl)}},
            ConditionExpression="attribute_not_exists(pk) OR #t < :now",
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues={":now": {"N": str(now)}},
        )
        return False
    except client("dynamodb").exceptions.ConditionalCheckFailedException:
        return True


# --------------------------------------------------------------------------- sorties
COLORS = {"critical": 0xB71C1C, "high": 0xE65100, "medium": 0xF9A825, "low": 0x1565C0, "info": 0x546E7A}


def discord_payload(alert):
    fields = [{"name": k, "value": f"`{json.dumps(v, ensure_ascii=False)[:200]}`" if not isinstance(v, str) else v[:200],
               "inline": True} for k, v in alert["fields"].items() if v not in (None, "")]
    desc = f"Principal : `{alert.get('principal')}`"
    if alert.get("attack"):
        desc += "\nATT&CK : " + ", ".join(alert["attack"])
    if alert.get("runbook"):
        base = os.environ.get("RUNBOOK_BASE_URL", "")
        desc += f"\nRunbook : {base}{alert['runbook']}" if base else f"\nRunbook : `{alert['runbook']}`"
    if alert.get("actions"):
        mode = "SIMULÉE (dry-run)" if os.environ.get("RESPONSE_DRY_RUN", "true") != "false" else "ACTIVE"
        desc += f"\nRéponse automatique : {', '.join(alert['actions'])} ({mode})"
    return {"embeds": [{"title": f"[{alert['severity'].upper()}] {alert['title']}", "description": desc,
                        "color": COLORS.get(alert["severity"], 0), "fields": fields[:10],
                        "footer": {"text": f"{alert['rule_id']} · {alert.get('time')}"}}]}


def send_discord(payload):
    param = os.environ.get("WEBHOOK_PARAM")
    if not param:
        log.info("pas de webhook configuré, alerte non envoyée: %s", json.dumps(payload)[:500])
        return False
    url = client("ssm").get_parameter(Name=param, WithDecryption=True)["Parameter"]["Value"]
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "adl-triage/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return 200 <= resp.status < 300


def trigger_response(alert):
    fn = os.environ.get("RESPONSE_FUNCTION")
    # Réponse automatique réservée aux alertes critiques (choix de conception)
    if not fn or not alert["actions"] or alert["severity"] != "critical":
        return False
    client("lambda").invoke(FunctionName=fn, InvocationType="Event", Payload=json.dumps(
        {"rule_id": alert["rule_id"], "actions": alert["actions"], "context": alert["context"]}).encode())
    return True


def handler(event, _ctx=None):
    rule_id = event["rule_id"]
    alert = build_alert(rule_id, event["event"])
    if alert["severity"] == "info":
        log.info("changement bénin ignoré: %s", alert["dedup_key"])
        return {"status": "ignored", "rule_id": rule_id}
    if is_duplicate(alert):
        log.info("doublon: %s", alert["dedup_key"])
        return {"status": "duplicate", "rule_id": rule_id}
    enrich(alert)
    send_discord(discord_payload(alert))
    responded = trigger_response(alert)
    return {"status": "alerted", "rule_id": rule_id, "severity": alert["severity"], "response_triggered": responded}
