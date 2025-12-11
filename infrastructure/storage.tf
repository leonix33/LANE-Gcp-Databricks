# Cloud Storage bucket for data lake
resource "google_storage_bucket" "data_lake" {
  name          = "${var.data_lake_bucket_name}-${local.name_suffix}"
  location      = var.region
  force_destroy = false

  # Uniform bucket-level access
  uniform_bucket_level_access = true

  # Versioning for data protection
  versioning {
    enabled = true
  }

  # Lifecycle management
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }

  # Logging
  logging {
    log_bucket = google_storage_bucket.logging_bucket.name
  }

  labels = local.common_tags
}

# Bucket for storing logs
resource "google_storage_bucket" "logging_bucket" {
  name          = "databricks-logs-${local.name_suffix}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  labels = local.common_tags
}

# Bucket for Databricks artifacts
resource "google_storage_bucket" "databricks_artifacts" {
  name          = "databricks-artifacts-${local.name_suffix}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  labels = local.common_tags
}

# BigQuery dataset for data warehouse
resource "google_bigquery_dataset" "warehouse" {
  dataset_id    = "${var.warehouse_dataset_name}_${local.name_suffix}"
  friendly_name = "Analytics Data Warehouse"
  description   = "Data warehouse for analytics and reporting"
  location      = var.region

  # Access control
  default_table_expiration_ms = 3600000 # 1 hour for temp tables

  # Labels
  labels = local.common_tags
}

# BigQuery dataset for raw data
resource "google_bigquery_dataset" "raw_data" {
  dataset_id    = "raw_data_${local.name_suffix}"
  friendly_name = "Raw Data Storage"
  description   = "Raw data ingestion dataset"
  location      = var.region

  labels = local.common_tags
}

# BigQuery dataset for processed data
resource "google_bigquery_dataset" "processed_data" {
  dataset_id    = "processed_data_${local.name_suffix}"
  friendly_name = "Processed Data"
  description   = "Processed and cleaned data"
  location      = var.region

  labels = local.common_tags
}

# Cloud SQL instance for Databricks metadata (optional)
resource "google_sql_database_instance" "databricks_metastore" {
  name             = "databricks-metastore-${local.name_suffix}"
  database_version = "POSTGRES_14"
  region          = var.region

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.databricks_vpc.id
      require_ssl     = true
    }

    backup_configuration {
      enabled    = true
      start_time = "02:00"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    user_labels = local.common_tags
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]

  deletion_protection = false
}

# Database for Hive metastore
resource "google_sql_database" "hive_metastore" {
  name     = "hive_metastore"
  instance = google_sql_database_instance.databricks_metastore.name
}

# Database user for Hive metastore
resource "google_sql_user" "hive_user" {
  name     = "hive"
  instance = google_sql_database_instance.databricks_metastore.name
  password = random_password.hive_password.result
}

# Random password for database user
resource "random_password" "hive_password" {
  length  = 16
  special = true
}

# Store the password in Secret Manager
resource "google_secret_manager_secret" "hive_password" {
  secret_id = "databricks-hive-password-${local.name_suffix}"

  replication {
    automatic = true
  }

  labels = local.common_tags
}

resource "google_secret_manager_secret_version" "hive_password" {
  secret      = google_secret_manager_secret.hive_password.id
  secret_data = random_password.hive_password.result
}