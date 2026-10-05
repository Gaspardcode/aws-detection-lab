# J0 — Préparer le compte AWS (à faire à la main, environ 1 h)

Ces étapes restent manuelles : elles touchent à ta carte bancaire, au root et à
tes identifiants.

## 1. Compte
Le lab tourne dans un **projet AWS** (« new AWS experience »), région
`eu-north-1` (Stockholm). On s'y connecte avec `aws login`, sans IAM Identity
Center et sans clé longue durée.

- [ ] Ce projet sert **uniquement** au lab : Stratus y lance de vraies attaques.
- [ ] MFA activé sur le compte de connexion.

## 2. Connexion sur le serveur (où tourne Terraform)
Le serveur n'a pas de navigateur, d'où `--remote` : il affiche une URL, on
se connecte depuis le navigateur du laptop et on recopie le code.
```bash
ssh -t <HOTE_TERRAFORM> '~/.local/bin/aws login --remote --profile lab-admin --region eu-north-1'
ssh <HOTE_TERRAFORM> '~/.local/bin/aws sts get-caller-identity --profile lab-admin'
```
Les identifiants se renouvellent toutes les 15 min, restent valables 12 h, et
peuvent être renouvelés pendant 90 jours sans repasser par le navigateur.
Le rôle obtenu est `AccountFullAccessRole`.

> `ssh hôte 'commande'` ne lit pas `.bashrc` : utiliser le chemin complet
> `~/.local/bin/aws`, ou ouvrir une session `ssh` interactive.

## 3. Profil attaquant (après le bootstrap)
```ini
# ~/.aws/config sur le serveur
[profile lab-attaquant]
role_arn          = arn:aws:iam::<ACCOUNT_ID>:role/lab-attaquant
source_profile    = lab-admin
role_session_name = stratus
region            = eu-north-1
```

## 4. Bootstrap
```bash
export AWS_PROFILE=lab-admin
TF_VAR_alert_email=<ton-adresse> make bootstrap   # ou un terraform.tfvars non versionné
terraform -chdir=terraform/bootstrap output -raw backend_hcl > terraform/backend.hcl
```
- [ ] Confirmer les e-mails d'abonnement aux budgets s'il y en a.
- [ ] **Sauvegarder** `terraform/bootstrap/terraform.tfstate` (state local) dans
      `~/.homelab-offline/` ou dans restic.

## 5. Archive, puis réseau (J1)
```bash
make plan STACK=archive   && make apply STACK=archive
make plan STACK=network   && make apply STACK=network
```
Vérification J1 : 10 à 15 min après l'apply,
```bash
aws s3 ls s3://adl-log-archive-<ACCOUNT_ID>/vpc-flow-logs/ --recursive | head
```
Le soir : `make destroy STACK=network`. L'archive et le bootstrap restent en
place, et le Makefile refuse de les détruire.
