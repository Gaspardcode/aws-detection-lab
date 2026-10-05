# 004 — Flow Logs supprimés

**Sévérité** : haute. **ATT&CK** : T1562.008.

## Vérifier
Le flow log supprimé appartenait-il au VPC du lab ? Le terraform de la soirée (`network`) peut le faire légitimement :
comparer l'heure avec les destroy planifiés et l'identité (`lab-admin`).

## Contenir
Recréer le flow log (`terraform apply` du stack `network`) ; désactiver la clé de l'appelant si l'appel est suspect (pas de réponse automatique).
