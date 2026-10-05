# aws-detection-lab

Détection et réponse sur AWS pour un SI qui héberge des données de santé.

Un petit SI fictif (VPC, EC2, bucket de faux dossiers patients chiffré en KMS, utilisateur IAM
volontairement trop privilégié) est attaqué avec [Stratus Red Team]. On mesure ce que GuardDuty
voit et ce qu'il manque, puis on comble les trous avec des **règles écrites comme du code**,
**testées en CI**, suivies d'une **réponse automatique** prudente.

L'histoire de la démo : *clé d'un développeur fuitée → reconnaissance → escalade de privilèges →
exfiltration de dossiers patients → effacement des traces.*

## État du projet

| Brique | État |
|---|---|
| Infrastructure (réseau, workload, archive, logging, detection) | écrite et validée hors ligne (`terraform validate`, trivy, tflint) ; **jamais appliquée dans ce dépôt** pour logging/detection |
| 5 règles temps réel + 3 volumétriques, fixtures, runbooks | écrites, testées hors ligne (67 tests) |
| Lambdas `triage`, `response`, `athena_runner` | écrites, testées avec moto ; **jamais exécutées sur AWS** |
| Attaques Stratus et scénario complet | scripts prêts, **non exécutés** |
| Matrice de couverture | v0 : colonnes « mesuré » à remplir ([docs/coverage-matrix.md](docs/coverage-matrix.md)) |
| MTTD / MTTR | **à mesurer** : aucun chiffre n'est annoncé tant que le scénario n'a pas été rejoué 3 fois |

Le planning détaillé est dans [ROADMAP.md](ROADMAP.md).

## Architecture

```
 Stratus Red Team ──API──▶  compte AWS dédié (eu-north-1)
 (profil "attaquant")        ├─ VPC 10.20.0.0/16, EC2 "app" (SSM, aucun port entrant), endpoint S3
                             ├─ S3 "patients" (SSE-KMS, données Faker), user IAM "dev" trop privilégié
                             │
                             │  Télémétrie
                             ├─ CloudTrail multi-région (+ data events S3 du seul bucket patients)
                             ├─ VPC Flow Logs (Parquet) ──▶ S3 log-archive (Object Lock, suppression interdite)
                             └─ GuardDuty (protection S3)
                                        │
                             Détection  ▼
                             ├─ temps réel : règles EventBridge (un événement, un motif)
                             ├─ volumétrique : requêtes Athena planifiées (athena_runner, 1/h)
                             └─ findings GuardDuty ──▶ EventBridge
                                        ▼
                             Lambda "triage" : enrichit, déduplique (DynamoDB), fixe la sévérité
                               ├──▶ webhook Discord (alerte + lien vers le runbook)
                               └──▶ Lambda "réponse" (alertes critiques, DRY-RUN par défaut)
                                     · désactive la clé d'accès  · isole l'EC2 (snapshot + SG vide)
                                     · restaure la politique du bucket patients
```

### Choix assumés
- **Pas de SIEM.** EventBridge pour le temps réel, Athena pour les agrégats : natif, quasi gratuit, simple à défendre.
- **Pas de NAT Gateway** (≈ 1 $/jour). L'EC2 est en subnet public sans port entrant, administrée par SSM.
- **Une seule AZ** : le sujet est la détection, pas la haute disponibilité.
- **Sigma comme source lisible**, traduit à la main en motif EventBridge ou en SQL Athena : les sémantiques diffèrent
  (EventBridge ne sait pas comparer deux valeurs ni compter), un traducteur automatique cacherait ces limites.
- **Réponse automatique réservée aux alertes critiques**, et en **dry-run tant que `response_dry_run` n'est pas `false`**.
  Chaque action a son propre statement IAM ; la désactivation de clé ne touche que les utilisateurs du chemin `/lab/`.
- **SSE-S3 sur le bucket de logs** (pas de clé KMS dédiée) : l'intégrité vient d'Object Lock et de la validation des
  fichiers CloudTrail. Exception trivy documentée dans le code.

### Pièges AWS rencontrés (et traités)
- Les **événements IAM sont globaux** : ils n'existent que sur le bus de `us-east-1`. Les règles `001` et `002` ont donc
  une règle de **transfert** `us-east-1` → bus de la région principale (stack `detection`, `global: true` dans `meta.json`).
- Un motif EventBridge **ne peut pas** dire « principal d'un autre compte » : la règle `005` capte tout changement de la politique du bucket
  patients et le triage inspecte la politique pour ne garder en critique que les principaux externes.
- Les tables Athena utilisent la **partition projection** (pas de crawler) ; la table CloudTrail est partitionnée par région
  car les événements IAM sont journalisés en `us-east-1`.

## Règles

| ID | Détecte | Type | ATT&CK | Sévérité | Réponse auto |
|---|---|---|---|---|---|
| 001 | AdministratorAccess attachée | temps réel | T1136.003, T1098 | critique | clé désactivée |
| 002 | profil de connexion console créé/modifié | temps réel | T1098 | haute | — |
| 003 | CloudTrail arrêté/modifié | temps réel | T1562.008 | critique | clé désactivée |
| 004 | Flow Logs supprimés | temps réel | T1562.008 | haute | — |
| 005 | politique du bucket patients modifiée (externe) | temps réel + inspection | T1537 | critique | politique restaurée, clé désactivée |
| 006 | lecture massive du bucket patients | Athena (1/h) | T1530 | haute | — |
| 007 | pic de `kms:Decrypt` | Athena (1/h) | T1530 | moyenne | — |
| 008 | volume sortant anormal | Athena (1/h) | T1048 | moyenne | — |

Chaque dossier `rules/<id>/` contient : `rule.yml` (Sigma), `pattern.json` **ou** `query.sql`, `meta.json` (sévérité, réponse),
`positive.json` / `negative.json` (fixtures **synthétiques** : compte `111122223333`, IP `203.0.113.x`) et `runbook.md`.
Les fixtures seront remplacées par des événements réels anonymisés après le week-end d'attaque.

## Arborescence

```
terraform/{bootstrap,archive,network,workload,logging,detection}/   un stack = un state
terraform/detection/modules/rule/    module réutilisé par chaque règle EventBridge
rules/<id>/                          règle + fixtures + runbook
lambdas/{triage,response,athena_runner}/handler.py
attacks/                             scripts Stratus, scénario, journal (runs.md)
tests/                               pytest : motifs, triage, réponse (moto), athena_runner
scripts/test_patterns_aws.py         confirme les motifs avec events:TestEventPattern
docs/                                setup-compte.md, coverage-matrix.md
.github/workflows, .forgejo/workflows   CI identique sur les deux forges
```

| Stack | Rôle | Cycle de vie |
|---|---|---|
| `bootstrap` | state S3, budgets, blocage public S3, rôle `lab-attaquant` | permanent, state local |
| `archive` | bucket de télémétrie (Object Lock, suppression interdite) | permanent |
| `network` | VPC, subnet, endpoint S3, SG app/isolement, Flow Logs | détruit chaque soir |
| `workload` | bucket patients KMS, EC2 app, IAM dont l'utilisateur `dev` | détruit chaque soir |
| `logging` | CloudTrail, GuardDuty, Glue/Athena | permanent pendant le projet |
| `detection` | règles EventBridge, Lambdas, déduplication | détruit chaque soir |

## Démarrer

Prérequis et connexion : [docs/setup-compte.md](docs/setup-compte.md). Ordre d'application :

```bash
make plan STACK=bootstrap  # puis apply, une fois ; copier la sortie backend_hcl dans terraform/backend.hcl
for s in archive network workload logging detection; do make plan STACK=$s && make apply STACK=$s; done
```

`detection` doit passer **après** `workload` : il photographie la politique du bucket patients comme référence de restauration
(l'appliquer sur un bucket déjà trafiqué figerait la politique piégée).
Créer à la main le webhook Discord : `aws ssm put-parameter --name /adl/discord-webhook --type SecureString --value <URL>`.

## Tests (hors ligne, aucun appel AWS)

```bash
pip install -r requirements-dev.txt
make test          # pytest : motifs vs fixtures +/−, triage, réponse (moto), athena_runner
make validate      # terraform fmt/validate sur tous les stacks
make scan          # trivy sur l'IaC
```

La CI (GitHub et Forgejo) rejoue ces contrôles, plus tflint, gitleaks et — si le rôle CI est configuré — le test des motifs
par EventBridge lui-même. Casser un motif ou une fixture fait passer la CI au rouge.

## Attaquer (compte du lab uniquement)

```bash
export AWS_PROFILE=lab-attaquant ADL_ACCOUNT_ID=<id du compte du lab> CONFIRM_LAB=yes
attacks/run-technique.sh aws.defense-evasion.cloudtrail-stop     # une technique, journalisée, nettoyée
AWS_PROFILE=lab-admin attacks/scenario.sh                        # scénario complet (week-end 2)
```

Les scripts refusent de tourner si le compte courant n'est pas `ADL_ACCOUNT_ID` et suppriment les clés qu'ils créent, même en cas d'erreur.
Ne scanner **que** ses propres ressources (règles de test d'intrusion AWS).

## Coûts (estimation, à vérifier sur la facture réelle)

Visé : < 10 $ pour deux semaines (GuardDuty en essai gratuit, un trail de gestion gratuit, data events limités au bucket patients,
une clé KMS). Pièges : NAT Gateway, endpoints d'interface oubliés, ressources Stratus non nettoyées, data events sur tous les buckets.
Une alerte budget est posée par le stack `bootstrap`. Garde-fou Athena : requête annulée au-delà de 1 Go scanné.

## Limites

- Détection volumétrique **retardée** : jusqu'à 1 h + livraison CloudTrail (5 à 15 min).
- La règle 008 ne voit pas l'exfiltration S3 via l'endpoint de passerelle (couverte par 006).
- Pas de règle pour l'énumération (T1580) ni le partage de snapshot EBS (T1537) : trous documentés dans la matrice.
- Les identifiants de l'instance volée (technique 1) ne sont détectés que si GuardDuty les voit.
- Le triage dépend de la livraison EventBridge ; pas de file d'attente ni de rejeu en cas d'échec Discord.

## En production, je ferais aussi

Organisation AWS avec compte de logs séparé, SCP interdisant l'arrêt de CloudTrail, KMS dédié pour les journaux,
Security Hub / SIEM, rôles de réponse avec approbation humaine, rotation automatique des clés, tests de bruit sur le trafic réel
pour calibrer les seuils, et une file d'attente (SQS) avec rejeu devant le triage.

[Stratus Red Team]: https://github.com/DataDog/stratus-red-team
