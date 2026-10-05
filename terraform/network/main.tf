# Stack "network" : VPC du SI santé fictif. JETABLE : `terraform destroy`
# chaque soir, les Flow Logs déjà livrés restent dans le bucket d'archive.
#
# Choix :
#   - une seule AZ (le sujet est la détection, pas la haute disponibilité) ;
#   - pas de NAT Gateway (≈ 1 $/jour) : l'EC2 est en subnet public, sans aucun
#     port entrant, administrée par SSM ;
#   - endpoint S3 de type gateway (gratuit) : le trafic vers le bucket patients
#     ne sort pas par Internet, ce qui rend une exfiltration S3 "par Internet"
#     visible dans les Flow Logs ;
#   - le SG par défaut est vidé (CIS AWS 5.4) ;
#   - un SG "isolement" sans aucune règle, utilisé par la Lambda de réponse.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "s3" {
    key = "network/terraform.tfstate"
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "network"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

# Bucket d'archive créé par le stack "archive" : retrouvé par convention de
# nom, pour ne pas coupler les states.
data "aws_s3_bucket" "logs" {
  bucket = "${var.project}-log-archive-${data.aws_caller_identity.current.account_id}"
}

locals {
  az = "${var.region}a"
}

# ---------------------------------------------------------------------------
# VPC, subnet, routage
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = local.az
  map_public_ip_on_launch = false # IP publique décidée instance par instance
  tags                    = { Name = "${var.project}-public-a" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-rt-public" }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]
  tags              = { Name = "${var.project}-vpce-s3" }
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # aucune règle : le SG par défaut ne doit servir à rien
  tags = { Name = "${var.project}-default-locked" }
}

resource "aws_security_group" "app" {
  name        = "${var.project}-app"
  description = "EC2 app : aucun entrant, sortie HTTPS uniquement (SSM, S3, depots)"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project}-app" }
}

# Sortie HTTPS vers Internet : requise par SSM sans endpoints d'interface payants.
#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS sortant (SSM, API AWS, depots de paquets)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "isolation" {
  name        = "${var.project}-isolation"
  description = "Quarantaine : aucun entrant, aucun sortant (Lambda de reponse)"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.project}-isolation" }
}

# AWS ajoute une règle "egress all" à tout SG créé dans un VPC ; Terraform la
# supprime d'office pour aws_security_group : "isolation" est donc bien vide.

# ---------------------------------------------------------------------------
# VPC Flow Logs -> bucket d'archive, Parquet partitionné "Hive" par heure
# (Athena lit moins de données, donc coûte moins, et les partitions sont
# directement exploitables avec partition projection au J5).
# ---------------------------------------------------------------------------
resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${data.aws_s3_bucket.logs.arn}/vpc-flow-logs"
  max_aggregation_interval = 60
  log_format               = join(" ", [for f in var.flow_log_fields : "$${${f}}"])

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = { Name = "${var.project}-flowlogs" }
}
