# Stack "workload" : le SI santé fictif. JETABLE (détruit chaque soir).
#
#   - bucket "patients" chiffré par une clé KMS dédiée, données fictives
#     générées par l'EC2 au démarrage ;
#   - EC2 "app" (Amazon Linux 2023), administrée par SSM, IMDSv2 obligatoire ;
#   - utilisateur IAM "dev" VOLONTAIREMENT trop privilégié : c'est le maillon
#     faible du scénario (clé fuitée -> escalade -> exfiltration). Aucune clé
#     d'accès n'est créée ici : on en crée une seulement pendant un scénario.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "s3" {
    key = "workload/terraform.tfstate"
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "workload"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# Réseau retrouvé par tags (pas de couplage de states)
data "aws_vpc" "main" {
  tags = { Project = var.project, Name = "${var.project}-vpc" }
}

data "aws_subnet" "public" {
  vpc_id = data.aws_vpc.main.id
  tags   = { Name = "${var.project}-public-a" }
}

data "aws_security_group" "app" {
  vpc_id = data.aws_vpc.main.id
  name   = "${var.project}-app"
}

# ---------------------------------------------------------------------------
# KMS : clé dédiée aux données de santé
# ---------------------------------------------------------------------------
resource "aws_kms_key" "patients" {
  description             = "Donnees de sante (bucket patients)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "patients" {
  name          = "alias/${var.project}-patients"
  target_key_id = aws_kms_key.patients.key_id
}

# ---------------------------------------------------------------------------
# Bucket patients
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "patients" {
  bucket        = "${var.project}-patients-${local.account_id}"
  force_destroy = true # données fictives, régénérées à chaque démarrage
  tags          = { DataClassification = "sante" }
}

resource "aws_s3_bucket_versioning" "patients" {
  bucket = aws_s3_bucket.patients.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "patients" {
  bucket = aws_s3_bucket.patients.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.patients.arn
    }
    # Bucket key DÉSACTIVÉE exprès : elle mutualise les appels KMS, et ferait
    # disparaître un kms:Decrypt par objet lu. Or ces Decrypt servent de
    # signal d'exfiltration (règle volumétrique du J9). En prod on l'active
    # pour le coût et on s'appuie sur les data events S3.
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_public_access_block" "patients" {
  bucket                  = aws_s3_bucket.patients.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "patients" {
  bucket = aws_s3_bucket.patients.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "patients_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.patients.arn, "${aws_s3_bucket.patients.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyUnencryptedUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.patients.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "patients" {
  bucket     = aws_s3_bucket.patients.id
  policy     = data.aws_iam_policy_document.patients_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.patients]
}

# ---------------------------------------------------------------------------
# EC2 "app" : rôle d'instance au moindre privilège
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.project}-app"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "app_ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "PatientsList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.patients.arn]
  }
  statement {
    sid       = "PatientsRW"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.patients.arn}/*"]
  }
  statement {
    sid       = "PatientsKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.patients.arn]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "patients-rw"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app"
  role = aws_iam_role.app.name
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnet.public.id
  vpc_security_group_ids      = [data.aws_security_group.app.id]
  associate_public_ip_address = true # sortie Internet sans NAT payant ; aucun port entrant
  iam_instance_profile        = aws_iam_instance_profile.app.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 obligatoire
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/seed.sh.tftpl", {
    bucket   = aws_s3_bucket.patients.bucket
    key_arn  = aws_kms_key.patients.arn
    nb_files = var.nb_patients
  })

  tags = { Name = "${var.project}-app", DataClassification = "sante" }

  depends_on = [aws_s3_bucket_policy.patients, aws_iam_role_policy.app]
}

# ---------------------------------------------------------------------------
# Utilisateur "dev" : LE maillon faible, volontairement.
# Droits réalistes d'un dev pressé : lecture large, accès total au bucket,
# et quelques droits IAM "pour se débrouiller" qui permettent l'escalade
# (CreateUser + AttachUserPolicy = devenir admin ; CreateLoginProfile /
# UpdateLoginProfile = prendre la console d'un autre utilisateur).
# ---------------------------------------------------------------------------
resource "aws_iam_user" "dev" {
  name = "dev-${var.project}"
  path = "/lab/"
  tags = { Role = "maillon-faible" }
}

data "aws_iam_policy_document" "dev" {
  statement {
    sid       = "ReadOnlyRecon"
    actions   = ["ec2:Describe*", "s3:ListAllMyBuckets", "iam:List*", "iam:Get*"]
    resources = ["*"]
  }
  statement {
    sid       = "PatientsFull"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.patients.arn, "${aws_s3_bucket.patients.arn}/*"]
  }
  statement {
    sid       = "PatientsKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.patients.arn]
  }
  statement {
    sid = "IamEscalationPath"
    actions = [
      "iam:CreateUser",
      "iam:AttachUserPolicy",
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:UpdateLoginProfile",
    ]
    resources = ["arn:aws:iam::${local.account_id}:user/*"]
  }
}

resource "aws_iam_user_policy" "dev" {
  name   = "dev-trop-large"
  user   = aws_iam_user.dev.name
  policy = data.aws_iam_policy_document.dev.json
}
