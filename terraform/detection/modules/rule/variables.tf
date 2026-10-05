variable "rule_id" {
  description = "Identifiant de la règle (nom du dossier rules/<id>) ; transmis au triage"
  type        = string
}

variable "description" {
  type = string
}

variable "pattern" {
  description = "Motif EventBridge (JSON)"
  type        = string
}

variable "target_arn" {
  description = "Cible : ARN de la Lambda triage, ou d'un bus d'événements pour un transfert inter-régions"
  type        = string
}

variable "lambda_function_name" {
  description = "Si renseigné, autorise EventBridge à invoquer cette Lambda"
  type        = string
  default     = null
}

variable "role_arn" {
  description = "Rôle EventBridge, requis pour une cible de type bus d'événements"
  type        = string
  default     = null
}

variable "wrap_rule_id" {
  description = "Enveloppe l'événement en {rule_id, event} pour le triage ; false pour un simple transfert"
  type        = bool
  default     = true
}

variable "attack" {
  description = "Techniques ATT&CK couvertes (tag)"
  type        = list(string)
  default     = []
}

variable "name_prefix" {
  type    = string
  default = "adl"
}
