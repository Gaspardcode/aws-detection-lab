# 003 — CloudTrail modifié

**Sévérité** : critique. **ATT&CK** : T1562.008.

## Contexte
Le bucket `log-archive` est protégé (Object Lock, refus de suppression) : les journaux déjà
écrits restent. Mais un `StopLogging` crée un trou pour la suite de l'attaque.

## Contenir
1. Relancer immédiatement : `aws cloudtrail start-logging --name adl-trail`.
2. Désactiver la clé qui a fait l'appel (réponse automatique si activée).
3. Vérifier `UpdateTrail` / `PutEventSelectors` : le périmètre (data events du bucket patients) est-il toujours couvert ?

## Après
Valider les fichiers de journal avec `aws cloudtrail validate-logs` sur la période du trou.
