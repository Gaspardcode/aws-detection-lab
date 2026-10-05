variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "adl"
}

variable "lock_days" {
  description = "Rétention Object Lock (mode GOVERNANCE) des journaux"
  type        = number
  default     = 14
}

variable "retention_days" {
  description = "Expiration des journaux ; doit être >= lock_days"
  type        = number
  default     = 60

  validation {
    condition     = var.retention_days >= var.lock_days
    error_message = "retention_days doit couvrir au moins la période Object Lock."
  }
}
