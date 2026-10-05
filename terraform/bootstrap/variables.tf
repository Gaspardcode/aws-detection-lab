variable "region" {
  description = "Région AWS du lab (celle du projet AWS)"
  type        = string
  default     = "eu-north-1"
}

variable "project" {
  description = "Préfixe des noms de ressources"
  type        = string
  default     = "adl"
}

variable "alert_email" {
  description = "Adresse qui reçoit les alertes de budget"
  type        = string
}

variable "budget_limits_usd" {
  description = "Seuils de budget mensuels (USD)"
  type        = list(number)
  default     = [10, 25]
}
