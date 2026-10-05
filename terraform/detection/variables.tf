variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "adl"
}

variable "response_dry_run" {
  description = "La Lambda de réponse ne modifie rien tant que ce n'est pas false"
  type        = bool
  default     = true
}

variable "enrich_history" {
  description = "Le triage interroge CloudTrail (24 h) pour enrichir l'alerte"
  type        = bool
  default     = true
}

variable "runbook_base_url" {
  description = "Préfixe des liens vers les runbooks (ex. URL du dépôt) ; vide = chemin relatif"
  type        = string
  default     = ""
}

variable "webhook_param" {
  description = "Nom du paramètre SSM (SecureString) qui contient l'URL du webhook Discord, créé à la main"
  type        = string
  default     = "/adl/discord-webhook"
}

variable "athena_schedule" {
  type    = string
  default = "rate(1 hour)"
}
