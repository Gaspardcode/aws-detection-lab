"""Évaluateur minimal de motifs EventBridge, pour tester les règles hors AWS.

Opérateurs gérés : valeur exacte, prefix, suffix, anything-but, exists.
Tout autre opérateur lève NotImplementedError : on préfère un test qui échoue bruyamment
à un motif jugé valide à tort. La CI complète avec `events:TestEventPattern` (scripts/test_patterns_aws.py).
"""


def _match_value(spec, value, present):
    if isinstance(spec, dict):
        (op, arg), = spec.items()
        if op == "exists":
            return present == arg
        if not present:
            return False
        if op == "prefix":
            return isinstance(value, str) and value.startswith(arg)
        if op == "suffix":
            return isinstance(value, str) and value.endswith(arg)
        if op == "anything-but":
            return value not in (arg if isinstance(arg, list) else [arg])
        raise NotImplementedError(op)
    return present and value == spec


def matches(pattern, event):
    for key, spec in pattern.items():
        present = isinstance(event, dict) and key in event
        value = event.get(key) if present else None
        if isinstance(spec, dict) and not any(k in ("prefix", "suffix", "anything-but", "exists") or k in
                                              ("numeric", "wildcard", "equals-ignore-case", "cidr") for k in spec):
            # sous-objet : récursion ; si l'événement a une liste d'objets, un élément doit correspondre
            if isinstance(value, list):
                if not any(matches(spec, v) for v in value):
                    return False
            elif not present or not matches(spec, value):
                return False
        elif isinstance(spec, list):
            values = value if isinstance(value, list) else [value]
            if not any(_match_value(s, v, present) for s in spec for v in values):
                return False
        else:
            raise ValueError(f"motif invalide pour {key}: les feuilles doivent être des listes")
    return True
