# 008 — Volume sortant anormal

**Sévérité** : moyenne. **ATT&CK** : T1048. Pas de réponse automatique.

## Vérifier
1. Destination (`dstaddr`) : service AWS connu (mises à jour SSM, S3 hors endpoint) ou IP inconnue ?
2. L'instance a-t-elle un rôle dont les identifiants ont été volés (GuardDuty `InstanceCredentialExfiltration`) ?

## Limite
Le trafic S3 via l'endpoint de passerelle n'apparaît pas comme du trafic Internet : cette règle ne voit pas l'exfiltration S3 (couverte par 006).
