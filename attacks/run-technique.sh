#!/usr/bin/env bash
# Lance UNE technique Stratus Red Team avec le profil attaquant, journalise les heures,
# puis nettoie. Usage :
#   AWS_PROFILE=lab-attaquant ADL_ACCOUNT_ID=... CONFIRM_LAB=yes attacks/run-technique.sh aws.defense-evasion.cloudtrail-stop
# Vérifier les noms exacts avec : stratus list --platform aws
source "$(dirname "$0")/lib.sh"

technique="${1:?technique Stratus requise (voir attacks/techniques.txt)}"
run="$(date -u +%Y%m%dT%H%M%SZ)-${technique//./_}"
assert_lab_account

trap 'stratus cleanup "$technique" || true; log_step "$run" "$technique" cleanup' EXIT
log_step "$run" "$technique" warmup
stratus warmup "$technique"
log_step "$run" "$technique" detonate-start
stratus detonate "$technique"
log_step "$run" "$technique" detonate-end
echo "Fait. Relever maintenant : trace CloudTrail, finding GuardDuty (oui/non, type, délai), règle maison."
echo "Journal : attacks/raw/$run.jsonl ; à reporter dans attacks/runs.md"
