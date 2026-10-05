#!/usr/bin/env bash
# Technique n°10 (maison) : lecture massive du bucket patients avec la clé du user "dev".
# Crée une clé d'accès temporaire pour "dev", lit tout, puis SUPPRIME la clé (trap),
# même en cas d'erreur : le user dev ne doit avoir aucune clé en dehors des scénarios.
# Usage : AWS_PROFILE=lab-admin ADL_ACCOUNT_ID=... CONFIRM_LAB=yes attacks/dev-mass-read.sh [nombre_d_objets]
source "$(dirname "$0")/lib.sh"

count="${1:-500}"
project="${ADL_PROJECT:-adl}"
dev_user="dev-${project}"
bucket="${project}-patients-${ADL_ACCOUNT_ID}"
run="$(date -u +%Y%m%dT%H%M%SZ)-dev_mass_read"
assert_lab_account

key_json="$(aws iam create-access-key --user-name "$dev_user")"
key_id="$(jq -r .AccessKey.AccessKeyId <<<"$key_json")"
trap 'aws iam delete-access-key --user-name "$dev_user" --access-key-id "$key_id" || true; log_step "$run" dev-mass-read cleanup' EXIT
export_dev() { env -u AWS_PROFILE -u AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID="$key_id" AWS_SECRET_ACCESS_KEY="$(jq -r .AccessKey.SecretAccessKey <<<"$key_json")" "$@"; }

echo "Attente de la propagation de la clé IAM..." ; sleep 15
log_step "$run" dev-mass-read detonate-start
export_dev aws s3api list-objects-v2 --bucket "$bucket" --max-items "$count" --query 'Contents[].Key' --output text \
  | tr '\t' '\n' | head -n "$count" \
  | while read -r obj; do export_dev aws s3api get-object --bucket "$bucket" --key "$obj" /dev/null >/dev/null; done
log_step "$run" dev-mass-read detonate-end
echo "Fait. Attendre l'heure pleine suivante + la livraison CloudTrail pour la règle 006."
