# Journal des attaques

> **Aucune mesure n'a encore été faite.** Ce fichier est le gabarit du week-end 1 (10-11 oct)
> et du week-end 2 (scénario complet). Toute cellule « à mesurer » sera remplie à partir
> des traces réelles (CloudTrail, Discord, console GuardDuty), jamais estimée.

## Une ligne par exécution

| Date (UTC) | Technique | Événement CloudTrail observé | Finding GuardDuty (oui/non, type) | Délai GuardDuty | Règle maison déclenchée | Délai règle maison | Notes |
|---|---|---|---|---|---|---|---|
| à mesurer | `aws.credential-access.ec2-steal-instance-credentials` | à mesurer | à mesurer | à mesurer | à mesurer | à mesurer | |

## Définitions
- **Délai** : heure de l'alerte (Discord / finding) moins l'heure de `detonate-end` du journal `attacks/raw/<run>.jsonl`.
- **MTTD** : médiane des délais sur 3 rejeux du scénario complet. **MTTR** : de l'alerte à l'action de réponse effective (clé désactivée).
- Les événements bruts sont anonymisés (compte, IP, ARN) avant d'être copiés dans `rules/*/positive.json`.
