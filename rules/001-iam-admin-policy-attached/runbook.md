# 001 — AdministratorAccess attachée

**Sévérité** : critique. **ATT&CK** : T1136.003, T1098.

## Ce qui s'est passé
Une identité IAM (`requestParameters.userName` / `roleName`) a reçu la politique gérée
`AdministratorAccess`. Les événements IAM sont globaux : ils arrivent dans `us-east-1`
et sont relayés vers la région principale par une règle de transfert.

## Vérifier (5 min)
1. Qui a fait l'appel (`userIdentity`) ? Est-ce attendu (changement planifié) ?
2. L'IP source est-elle connue ? L'identité qui attache a-t-elle d'autres appels récents (24 h) ?
3. L'identité qui reçoit les droits existe-t-elle depuis longtemps ?

## Contenir
- Réponse automatique (si `DRY_RUN=false`) : désactivation de la clé d'accès utilisée pour l'appel.
- À la main : détacher la politique, supprimer l'utilisateur créé, révoquer les sessions du rôle.

## Après
Chercher d'autres actions de la même clé (`CreateAccessKey`, `CreateLoginProfile`, `PutBucketPolicy`).
