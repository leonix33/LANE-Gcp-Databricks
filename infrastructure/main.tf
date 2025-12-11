# Terraform configuration for Databricks on GCP
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    databricks = {
      source  = "databricks/databricks"
      version = "~> 1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# Configure the Google Cloud Provider
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Configure Databricks Provider
provider "databricks" {
  google_service_account = google_service_account.databricks_sa.email
  host                   = "https://accounts.gcp.databricks.com"
}

# Random suffix for unique resource naming
resource "random_id" "suffix" {
  byte_length = 4
}

# Local values for resource naming
locals {
  name_suffix = random_id.suffix.hex
  common_tags = {
    Environment = var.environment
    Project     = "databricks-gcp"
    ManagedBy   = "terraform"
    CreatedBy   = var.created_by
  }
}