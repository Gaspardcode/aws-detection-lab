# aws-detection-lab

Détection et réponse sur AWS pour un SI qui héberge des données de santé.
Un petit SI fictif est attaqué avec [Stratus Red Team] ; on mesure ce que
GuardDuty détecte et ce qu'il manque, puis on comble les trous avec des règles
écrites comme du code, testées en CI, et suivies d'une réponse automatique.

> Projet en cours, voir [ROADMAP.md](ROADMAP.md). Ce README sera réécrit au J14.

## Stacks Terraform

| Stack | Rôle | Cycle de vie |
|---|---|---|
| `bootstrap` | state S3, budgets, blocage public S3 du compte, rôle `lab-attaquant` | permanent, state local |
| `archive` | bucket de télémétrie (Object Lock, suppression interdite) | permanent |
| `network` | VPC, subnet, endpoint S3, SG app/isolement, VPC Flow Logs | détruit chaque soir |
| `workload` | *J2* : bucket patients KMS, EC2 app, IAM | détruit chaque soir |
| `logging` | *J3-J5* : CloudTrail, GuardDuty, Athena | permanent pendant le projet |
| `detection` | *J8+* : règles EventBridge et Athena, Lambdas | détruit chaque soir |

## Démarrer

Voir [docs/setup-compte.md](docs/setup-compte.md).

```bash
make validate          # validation hors ligne de tous les stacks
make scan              # trivy sur l'IaC
make plan STACK=network
make apply STACK=network
```

[Stratus Red Team]: https://github.com/DataDog/stratus-red-team
