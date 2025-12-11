# Infrastructure outputs
output "project_id" {
  description = "GCP Project ID"
  value       = var.project_id
}

output "region" {
  description = "GCP Region"
  value       = var.region
}

output "vpc_network_id" {
  description = "VPC Network ID"
  value       = google_compute_network.databricks_vpc.id
}

output "vpc_network_name" {
  description = "VPC Network Name"
  value       = google_compute_network.databricks_vpc.name
}

output "private_subnet_id" {
  description = "Private Subnet ID"
  value       = google_compute_subnetwork.private_subnet.id
}

output "public_subnet_id" {
  description = "Public Subnet ID"
  value       = google_compute_subnetwork.public_subnet.id
}

# Storage outputs
output "data_lake_bucket_name" {
  description = "Data Lake Bucket Name"
  value       = google_storage_bucket.data_lake.name
}

output "data_lake_bucket_url" {
  description = "Data Lake Bucket URL"
  value       = "gs://${google_storage_bucket.data_lake.name}"
}

output "logging_bucket_name" {
  description = "Logging Bucket Name"
  value       = google_storage_bucket.logging_bucket.name
}

output "artifacts_bucket_name" {
  description = "Artifacts Bucket Name"
  value       = google_storage_bucket.databricks_artifacts.name
}

output "bigquery_warehouse_dataset" {
  description = "BigQuery Warehouse Dataset ID"
  value       = google_bigquery_dataset.warehouse.dataset_id
}

output "bigquery_raw_dataset" {
  description = "BigQuery Raw Data Dataset ID"
  value       = google_bigquery_dataset.raw_data.dataset_id
}

output "bigquery_processed_dataset" {
  description = "BigQuery Processed Data Dataset ID"
  value       = google_bigquery_dataset.processed_data.dataset_id
}

# Databricks outputs
output "databricks_workspace_url" {
  description = "Databricks Workspace URL"
  value       = databricks_workspace.main.workspace_url
  sensitive   = true
}

output "databricks_workspace_id" {
  description = "Databricks Workspace ID"
  value       = databricks_workspace.main.workspace_id
}

output "databricks_workspace_name" {
  description = "Databricks Workspace Name"
  value       = databricks_workspace.main.workspace_name
}

output "analytics_cluster_id" {
  description = "Analytics Cluster ID"
  value       = databricks_cluster.analytics_cluster.id
}

output "ml_cluster_id" {
  description = "ML Cluster ID"
  value       = databricks_cluster.ml_cluster.id
}

output "sql_warehouse_id" {
  description = "SQL Warehouse ID"
  value       = databricks_sql_endpoint.analytics_warehouse.id
}

output "secret_scope_name" {
  description = "Databricks Secret Scope Name"
  value       = databricks_secret_scope.main.name
}

# Service Account outputs
output "databricks_service_account_email" {
  description = "Databricks Service Account Email"
  value       = google_service_account.databricks_sa.email
}

output "databricks_service_account_name" {
  description = "Databricks Service Account Name"
  value       = google_service_account.databricks_sa.name
}

# Database outputs
output "metastore_instance_name" {
  description = "Cloud SQL Instance Name"
  value       = google_sql_database_instance.databricks_metastore.name
}

output "metastore_private_ip" {
  description = "Cloud SQL Private IP"
  value       = google_sql_database_instance.databricks_metastore.private_ip_address
  sensitive   = true
}

output "metastore_connection_name" {
  description = "Cloud SQL Connection Name"
  value       = google_sql_database_instance.databricks_metastore.connection_name
}

# Monitoring outputs
output "monitoring_dashboard_url" {
  description = "Cloud Monitoring Dashboard URL"
  value       = var.enable_monitoring ? "https://console.cloud.google.com/monitoring/dashboards/custom/${google_monitoring_dashboard.databricks_dashboard[0].id}" : "Monitoring disabled"
}

output "notification_channel_id" {
  description = "Monitoring Notification Channel ID"
  value       = var.enable_monitoring ? google_monitoring_notification_channel.email[0].id : "Monitoring disabled"
}

# Environment configuration summary
output "environment_summary" {
  description = "Environment configuration summary"
  value = {
    environment           = var.environment
    project_id           = var.project_id
    region               = var.region
    workspace_name       = databricks_workspace.main.workspace_name
    data_lake_bucket     = google_storage_bucket.data_lake.name
    monitoring_enabled   = var.enable_monitoring
    preemptible_enabled  = var.enable_preemptible_instances
    auto_termination_min = var.auto_termination_minutes
  }
}

# Resource URLs for quick access
output "resource_urls" {
  description = "Quick access URLs for resources"
  value = {
    databricks_workspace = databricks_workspace.main.workspace_url
    cloud_console       = "https://console.cloud.google.com/home/dashboard?project=${var.project_id}"
    storage_browser     = "https://console.cloud.google.com/storage/browser/${google_storage_bucket.data_lake.name}?project=${var.project_id}"
    bigquery_console    = "https://console.cloud.google.com/bigquery?project=${var.project_id}"
    monitoring_console  = "https://console.cloud.google.com/monitoring?project=${var.project_id}"
  }
  sensitive = true
}

# Connection strings and configurations
output "connection_configs" {
  description = "Connection configurations for applications"
  value = {
    gcs_bucket_path     = "gs://${google_storage_bucket.data_lake.name}"
    bigquery_project_id = var.project_id
    sql_instance_name   = google_sql_database_instance.databricks_metastore.name
    vpc_network_name    = google_compute_network.databricks_vpc.name
    private_subnet_name = google_compute_subnetwork.private_subnet.name
  }
}

# Security and access information
output "security_config" {
  description = "Security configuration details"
  value = {
    service_account_email = google_service_account.databricks_sa.email
    secret_manager_secret = google_secret_manager_secret.hive_password.secret_id
    private_ip_enabled    = var.enable_private_ip
    allowed_ip_ranges     = var.allowed_ip_ranges
  }
  sensitive = true
}

# Cost optimization settings
output "cost_optimization" {
  description = "Cost optimization settings"
  value = {
    preemptible_instances = var.enable_preemptible_instances
    auto_termination_min  = var.auto_termination_minutes
    cluster_min_workers   = var.cluster_min_workers
    cluster_max_workers   = var.cluster_max_workers
    storage_lifecycle     = "Enabled with multi-tier archiving"
  }
}