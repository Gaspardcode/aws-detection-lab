#!/usr/bin/env bash
# Fonctions communes aux scripts d'attaque. À sourcer, pas à exécuter.
# Garde-fous : on n'attaque QUE le compte du lab, et seulement avec confirmation explicite.
set -euo pipefail

: "${ADL_ACCOUNT_ID:?exporter ADL_ACCOUNT_ID (ID du compte du lab, ne jamais le committer)}"
: "${CONFIRM_LAB:?exporter CONFIRM_LAB=yes pour confirmer que le compte courant est le compte du lab}"
[ "$CONFIRM_LAB" = "yes" ] || { echo "CONFIRM_LAB doit valoir 'yes'" >&2; exit 1; }

ATTACKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAW_DIR="$ATTACKS_DIR/raw"          # non versionné : contient des identifiants du compte
mkdir -p "$RAW_DIR"
export AWS_REGION="${AWS_REGION:-eu-north-1}"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

assert_lab_account() {
  local actual
  actual="$(aws sts get-caller-identity --query Account --output text)"
  if [ "$actual" != "$ADL_ACCOUNT_ID" ]; then
    echo "Refus : le compte courant n'est pas celui du lab." >&2
    exit 1
  fi
}

# journal : une ligne JSON par étape (heure de début/fin), pour calculer le MTTD ensuite
log_step() { # run technique phase
  printf '{"run":"%s","technique":"%s","phase":"%s","at":"%s"}\n' "$1" "$2" "$3" "$(now)" >> "$RAW_DIR/$1.jsonl"
}
