# Matrice de couverture ATT&CK

> **État : v0, avant mesure.** Les colonnes « Prévu » viennent de la conception (documentation AWS,
> hypothèses de conception) et **ne sont pas des résultats**. Les colonnes « Mesuré » restent à
> `à mesurer` jusqu'au week-end d'attaque ; elles seront remplies à partir de `attacks/runs.md`.
> Les colonnes vides de la dernière colonne indiquent **où il faut encore écrire des règles**.

Légende : ✅ couvert par une règle · ⚠️ couverture partielle · ❌ aucune règle maison (trou connu) · `à mesurer`.

| # | Technique Stratus | ATT&CK | Appel d'API attendu dans CloudTrail | GuardDuty : prévu (hypothèse) | GuardDuty : mesuré | Règle maison (conception) | Règle maison : mesuré |
|---|---|---|---|---|---|---|---|
| 1 | `aws.credential-access.ec2-steal-instance-credentials` | T1552.005 | utilisation des identifiants d'instance depuis une IP externe | oui (`InstanceCredentialExfiltration`) | à mesurer | ⚠️ pas de règle EventBridge ; le triage isole l'instance sur le finding GuardDuty | à mesurer |
| 2 | `aws.discovery.ec2-enumerate-from-instance` | T1580 | `Describe*` depuis le rôle de l'instance | partiel | à mesurer | ❌ | à mesurer |
| 3 | `aws.persistence.iam-create-admin-user` | T1136.003 | `CreateUser`, `AttachUserPolicy` (AdministratorAccess) | non en général | à mesurer | ✅ `001` (événement IAM global, relayé depuis us-east-1) | à mesurer |
| 4 | `aws.persistence.iam-create-user-login-profile` | T1098 | `CreateLoginProfile` | non | à mesurer | ✅ `002` | à mesurer |
| 5 | `aws.privilege-escalation.iam-update-user-login-profile` | T1098 | `UpdateLoginProfile` | non | à mesurer | ✅ `002` | à mesurer |
| 6 | `aws.exfiltration.s3-backdoor-bucket-policy` | T1537 | `PutBucketPolicy` | possiblement | à mesurer | ⚠️ `005` ne surveille que `adl-patients-*` ; Stratus crée **son propre** bucket, donc la règle ne se déclenche pas sur la technique Stratus brute : valider avec l'étape 4 de `attacks/scenario.sh` | à mesurer |
| 7 | `aws.exfiltration.ec2-share-ebs-snapshot` | T1537 | `ModifySnapshotAttribute` | non | à mesurer | ❌ trou connu | à mesurer |
| 8 | `aws.defense-evasion.cloudtrail-stop` | T1562.008 | `StopLogging` | oui (`Stealth:IAMUser/CloudTrailLoggingDisabled`) | à mesurer | ✅ `003` | à mesurer |
| 9 | `aws.defense-evasion.vpc-remove-flow-logs` | T1562.008 | `DeleteFlowLogs` | non | à mesurer | ✅ `004` | à mesurer |
| 10 | maison : lecture massive du bucket patients (`attacks/dev-mass-read.sh`) | T1530 | `GetObject` en rafale (data events), `kms:Decrypt` | peut-être (anomalie S3) | à mesurer | ✅ `006` (≥ 100/h/principal), ✅ `007` (≥ 200 Decrypt/h) | à mesurer |
| — | trafic sortant volumineux depuis l'instance | T1048 | (Flow Logs) | — | à mesurer | ✅ `008` (≥ 500 Mo/h vers IP publiques ; ne voit pas S3 via l'endpoint) | à mesurer |

## Lecture
- Les **seuils** (100, 200, 500 Mo) sont des valeurs de départ : ils seront recalibrés avec le trafic normal mesuré.
- Les règles 001–005 sont **temps réel** (EventBridge) ; 006–008 sont **volumétriques** (Athena, une exécution par heure, donc détection retardée jusqu'à ~1 h).
- **Trous connus à documenter honnêtement** : n°2 (énumération), n°7 (partage de snapshot EBS) et n°1 (pas de règle propre).
- Les seuils de GuardDuty, ses délais et ses types de findings ne sont connus qu'après exécution.
