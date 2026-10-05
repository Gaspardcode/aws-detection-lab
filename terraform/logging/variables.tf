variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "adl"
}

variable "query_regions" {
  description = "Régions interrogeables par Athena (les événements IAM globaux sont journalisés en us-east-1)"
  type        = list(string)
  default     = ["eu-north-1", "us-east-1"]
}

variable "projection_start_date" {
  description = "Date de début des partitions CloudTrail (partition projection)"
  type        = string
  default     = "2026/10/01"
}
