# 007 — Pic de kms:Decrypt

**Sévérité** : moyenne. **ATT&CK** : T1530. Pas de réponse automatique : signal corroborant de la règle 006.

## Vérifier
Le principal lit-il le bucket patients (règle 006 déclenchée en parallèle) ? Si oui, traiter l'incident 006.
Sinon, chercher un usage de la clé hors S3 (`GenerateDataKey`, `ReEncrypt`).
