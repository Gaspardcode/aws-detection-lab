# 005 — Politique du bucket patients modifiée

**Sévérité** : critique si la politique contient un principal d'un autre compte. **ATT&CK** : T1537.

## Pourquoi cette règle est large
Un motif EventBridge ne peut pas dire « principal différent de mon compte » sur une liste de statements.
La règle capte donc tout changement de politique du bucket patients ; la Lambda `triage` lit
`requestParameters.bucketPolicy` et ne laisse en critique que les principaux externes (`*` ou autre compte).

## Contenir
Réponse automatique : restauration de la politique de référence (SSM `/adl/baseline-bucket-policy`), puis désactivation de la clé.
À la main : `aws s3api put-bucket-policy` avec la politique du stack `workload`.

## Après
Chercher des `GetObject` du compte externe dans les data events du bucket.
