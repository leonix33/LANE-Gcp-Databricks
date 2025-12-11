# Service account for Databricks
resource "google_service_account" "databricks_sa" {
  account_id   = "databricks-sa-${local.name_suffix}"
  display_name = "Databricks Service Account"
  description  = "Service account for Databricks workspace operations"
}

# IAM roles for Databricks service account
resource "google_project_iam_member" "databricks_compute_admin" {
  project = var.project_id
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.databricks_sa.email}"
}

resource "google_project_iam_member" "databricks_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.databricks_sa.email}"
}

resource "google_project_iam_member" "databricks_bigquery_admin" {
  project = var.project_id
  role    = "roles/bigquery.admin"
  member  = "serviceAccount:${google_service_account.databricks_sa.email}"
}

# Databricks workspace
resource "databricks_workspace" "main" {
  workspace_name = "${var.databricks_workspace_name}-${local.name_suffix}"
  deployment_name = "databricks-${local.name_suffix}"
  
  gcp_managed_network_config {
    gke_cluster_pod_ip_range     = "10.1.0.0/16"
    gke_cluster_service_ip_range = "10.2.0.0/20"
    subnet_cidr                  = var.private_subnet_cidr
  }

  gke_config {
    connectivity_type = "PRIVATE_NODE_PUBLIC_MASTER"
    master_ip_range   = "10.3.0.0/28"
  }

  network_id = google_compute_network.databricks_vpc.id
  
  depends_on = [
    google_service_account.databricks_sa,
    google_compute_network.databricks_vpc,
    google_compute_subnetwork.private_subnet
  ]
}

# Databricks cluster policy for cost control
resource "databricks_cluster_policy" "cost_control" {
  name = "Cost Control Policy"
  
  definition = jsonencode({
    "node_type_id": {
      "type": "allowlist",
      "values": ["n1-standard-4", "n1-highmem-2", "n1-highmem-4"]
    },
    "autotermination_minutes": {
      "type": "range",
      "maxValue": var.auto_termination_minutes
    },
    "enable_elastic_disk": {
      "type": "fixed",
      "value": true
    },
    "preemptible": {
      "type": "fixed",
      "value": var.enable_preemptible_instances
    }
  })

  depends_on = [databricks_workspace.main]
}

# Databricks cluster for general analytics
resource "databricks_cluster" "analytics_cluster" {
  cluster_name            = "Analytics Cluster"
  node_type_id           = var.cluster_node_type
  driver_node_type_id    = var.cluster_node_type
  autotermination_minutes = var.auto_termination_minutes
  
  autoscale {
    min_workers = var.cluster_min_workers
    max_workers = var.cluster_max_workers
  }
  
  spark_version = "13.3.x-scala2.12"
  
  spark_conf = {
    "spark.databricks.cluster.profile" = "serverless"
    "spark.databricks.repl.allowedLanguages" = "python,sql,scala,r"
    "spark.sql.adaptive.enabled" = "true"
    "spark.sql.adaptive.coalescePartitions.enabled" = "true"
  }

  policy_id = databricks_cluster_policy.cost_control.id

  depends_on = [databricks_workspace.main]
}

# Databricks cluster for ML workloads
resource "databricks_cluster" "ml_cluster" {
  cluster_name            = "ML Cluster"
  node_type_id           = "n1-highmem-4"
  driver_node_type_id    = "n1-highmem-4"
  autotermination_minutes = var.auto_termination_minutes
  
  autoscale {
    min_workers = 1
    max_workers = 4
  }
  
  spark_version = "13.3.x-cpu-ml-scala2.12"
  
  spark_conf = {
    "spark.databricks.cluster.profile" = "serverless"
    "spark.sql.adaptive.enabled" = "true"
    "spark.databricks.delta.preview.enabled" = "true"
  }

  policy_id = databricks_cluster_policy.cost_control.id

  depends_on = [databricks_workspace.main]
}

# Databricks SQL warehouse
resource "databricks_sql_endpoint" "analytics_warehouse" {
  name             = "Analytics Warehouse"
  cluster_size     = "Small"
  auto_stop_mins   = 30
  max_num_clusters = 1

  tags {
    custom_tags {
      key   = "Environment"
      value = var.environment
    }
  }

  depends_on = [databricks_workspace.main]
}

# Create workspace folders
resource "databricks_directory" "shared_analytics" {
  path = "/Shared/Analytics"

  depends_on = [databricks_workspace.main]
}

resource "databricks_directory" "shared_ml" {
  path = "/Shared/ML"

  depends_on = [databricks_workspace.main]
}

resource "databricks_directory" "shared_pipelines" {
  path = "/Shared/Pipelines"

  depends_on = [databricks_workspace.main]
}

# Secret scope for storing credentials
resource "databricks_secret_scope" "main" {
  name = "main-secrets"

  depends_on = [databricks_workspace.main]
}

# Store GCS credentials in secret scope
resource "databricks_secret" "gcs_credentials" {
  key          = "gcs-service-account"
  string_value = google_service_account.databricks_sa.email
  scope        = databricks_secret_scope.main.name

  depends_on = [databricks_secret_scope.main]
}

# Store database connection details
resource "databricks_secret" "db_password" {
  key          = "hive-metastore-password"
  string_value = random_password.hive_password.result
  scope        = databricks_secret_scope.main.name

  depends_on = [databricks_secret_scope.main]
}