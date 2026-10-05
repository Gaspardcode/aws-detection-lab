#!/usr/bin/env python3
"""Confirme chaque règle avec l'évaluateur d'EventBridge (events:TestEventPattern).

Complète tests/test_rules.py (évaluateur local) : c'est EventBridge lui-même qui décide.
Utilise un rôle CI qui n'a QUE ce droit. Sans identifiants, le script sort en 0 en le disant,
pour ne pas casser les forks qui n'ont pas de secrets.
"""
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import NoCredentialsError

RULES = Path(__file__).resolve().parent.parent / "rules"


def main() -> int:
    client = boto3.client("events", region_name="eu-north-1")
    failures = []
    for rule in sorted(RULES.glob("*/pattern.json")):
        pattern = rule.read_text()
        for fixture, expected in (("positive", True), ("negative", False)):
            event = (rule.parent / f"{fixture}.json").read_text()
            try:
                got = client.test_event_pattern(EventPattern=pattern, Event=event)["Result"]
            except NoCredentialsError:
                print("Pas d'identifiants AWS : test EventBridge ignoré.")
                return 0
            status = "ok" if got == expected else "ÉCHEC"
            print(f"{status:6} {rule.parent.name} {fixture} (attendu {expected}, obtenu {got})")
            if got != expected:
                failures.append(f"{rule.parent.name}/{fixture}")
    if failures:
        print(json.dumps(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
