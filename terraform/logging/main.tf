# Stack "logging" : télémétrie et requêtage. PERMANENT pendant le projet.
#
#   - CloudTrail multi-région, validation des fichiers, événements de gestion
#     + data events S3 du SEUL bucket patients (les autres buckets coûteraient
#     cher pour rien) ;
#   - GuardDuty avec protection S3 (essai de 30 jours) ;
#   - base Glue + tables CloudTrail et Flow Logs en partition projection :
#     pas de crawler, pas de MSCK REPAIR, les partitions sont calculées ;
#   - groupe de travail Athena avec limite de données scannées par requête.
#
# Le bucket log-archive vient du stack "archive" (nom déterministe).

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "s3" {
    key = "logging/terraform.tfstate"
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "logging"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  log_bucket     = "${var.project}-log-archive-${local.account_id}"
  patients_arn   = "arn:aws:s3:::${var.project}-patients-${local.account_id}"
  trail_name     = "${var.project}-trail" # le nom est autorisé d'avance par la policy du bucket (stack archive)
  cloudtrail_loc = "s3://${local.log_bucket}/cloudtrail/AWSLogs/${local.account_id}/CloudTrail"
  flowlogs_loc   = "s3://${local.log_bucket}/vpc-flow-logs/AWSLogs/aws-account-id=${local.account_id}/aws-service=vpcflowlogs"
}

data "aws_s3_bucket" "logs" {
  bucket = local.log_bucket
}

# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------
# Chiffrement SSE-S3 du bucket plutôt que clé KMS dédiée : choix assumé (cf. stack archive).
# L'intégrité est assurée par Object Lock + validation des fichiers ; une clé KMS ajouterait
# un coût fixe et une politique de clé de plus à protéger. Limite à citer dans le README.
#trivy:ignore:AVD-AWS-0015
resource "aws_cloudtrail" "main" {
  name                          = local.trail_name
  s3_bucket_name                = data.aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Sélecteurs avancés : on ne peut pas mélanger avec event_selector.
  advanced_event_selector {
    name = "Evenements de gestion (lecture et ecriture)"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "Data events S3 du bucket patients uniquement"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${local.patients_arn}/"]
    }
  }
}

# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# ---------------------------------------------------------------------------
# Glue + Athena
# ---------------------------------------------------------------------------
resource "aws_glue_catalog_database" "logs" {
  name = "adl_logs"
}

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail"
  database_name = aws_glue_catalog_database.logs.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                       = "TRUE"
    "projection.enabled"           = "true"
    "projection.day.type"          = "date"
    "projection.day.format"        = "yyyy/MM/dd"
    "projection.day.range"         = "${var.projection_start_date},NOW"
    "projection.day.interval"      = "1"
    "projection.day.interval.unit" = "DAYS"
    "projection.region.type"       = "enum"
    "projection.region.values"     = join(",", var.query_regions)
    "storage.location.template"    = "${local.cloudtrail_loc}/$${region}/$${day}"
  }

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "day"
    type = "string"
  }

  storage_descriptor {
    location      = local.cloudtrail_loc
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    dynamic "columns" {
      for_each = {
        eventversion = "string"
        useridentity = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
        eventtime    = "string"
        eventsource  = "string"
        eventname    = "string"
        awsregion    = "string"
        # Nom de colonne en minuscules : Athena est insensible à la casse.
        sourceipaddress     = "string"
        useragent           = "string"
        errorcode           = "string"
        errormessage        = "string"
        requestparameters   = "string"
        responseelements    = "string"
        additionaleventdata = "string"
        requestid           = "string"
        eventid             = "string"
        resources           = "array<struct<arn:string,accountid:string,type:string>>"
        eventtype           = "string"
        readonly            = "string"
        recipientaccountid  = "string"
        sharedeventid       = "string"
        vpcendpointid       = "string"
      }
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

resource "aws_glue_catalog_table" "vpc_flow_logs" {
  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.logs.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                       = "TRUE"
    "classification"               = "parquet"
    "projection.enabled"           = "true"
    "projection.aws-region.type"   = "enum"
    "projection.aws-region.values" = var.region
    "projection.year.type"         = "integer"
    "projection.year.range"        = "2026,2030"
    "projection.month.type"        = "integer"
    "projection.month.range"       = "1,12"
    "projection.month.digits"      = "2"
    "projection.day.type"          = "integer"
    "projection.day.range"         = "1,31"
    "projection.day.digits"        = "2"
    "projection.hour.type"         = "integer"
    "projection.hour.range"        = "0,23"
    "projection.hour.digits"       = "2"
    "storage.location.template"    = "${local.flowlogs_loc}/aws-region=$${aws-region}/year=$${year}/month=$${month}/day=$${day}/hour=$${hour}"
  }

  dynamic "partition_keys" {
    for_each = ["aws-region", "year", "month", "day", "hour"]
    content {
      name = partition_keys.value
      type = partition_keys.value == "aws-region" ? "string" : "int"
    }
  }

  storage_descriptor {
    location      = local.flowlogs_loc
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    # Mêmes champs que var.flow_log_fields du stack network, noms avec underscores
    dynamic "columns" {
      for_each = {
        version        = "int"
        account_id     = "string"
        interface_id   = "string"
        srcaddr        = "string"
        dstaddr        = "string"
        srcport        = "int"
        dstport        = "int"
        protocol       = "bigint"
        packets        = "bigint"
        bytes          = "bigint"
        start          = "bigint"
        end            = "bigint"
        action         = "string"
        log_status     = "string"
        vpc_id         = "string"
        subnet_id      = "string"
        instance_id    = "string"
        tcp_flags      = "int"
        type           = "string"
        pkt_srcaddr    = "string"
        pkt_dstaddr    = "string"
        flow_direction = "string"
        traffic_path   = "int"
      }
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

resource "aws_athena_workgroup" "detection" {
  name          = "${var.project}-detection"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false
    # Garde-fou de coût : une requête qui scanne plus de 1 Go est annulée
    bytes_scanned_cutoff_per_query = 1073741824

    result_configuration {
      output_location = "s3://${local.log_bucket}/athena-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
