# 006 — Lecture massive du bucket patients

**Sévérité** : haute. **ATT&CK** : T1530. Règle volumétrique (Athena, toutes les heures).

## Vérifier
1. Le principal est-il l'application (`adl-app`) ? Son volume nominal est bas : calibrer le seuil sur les mesures du week-end 1.
2. L'IP source (CloudTrail data events) est-elle dans le VPC (endpoint S3) ou externe ?

## Contenir
Désactiver la clé du principal à la main (pas de réponse automatique, sévérité haute) ; vérifier `s3:ListBucket` en amont (reconnaissance).

## Limite
Détection retardée : jusqu'à 1 h + délai de livraison CloudTrail (~5-15 min).
