variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "adl"
}

variable "instance_type" {
  description = "Type éligible au free tier"
  type        = string
  default     = "t3.micro"
}

variable "nb_patients" {
  description = "Nombre de dossiers fictifs générés au démarrage"
  type        = number
  default     = 500
}
