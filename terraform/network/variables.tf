variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "adl"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

# Champs v2 par défaut + ceux utiles à la détection (instance, sens du flux,
# adresses réelles derrière une interface, chemin emprunté).
variable "flow_log_fields" {
  type = list(string)
  default = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes", "start", "end",
    "action", "log-status",
    "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type",
    "pkt-srcaddr", "pkt-dstaddr", "flow-direction", "traffic-path",
  ]
}
