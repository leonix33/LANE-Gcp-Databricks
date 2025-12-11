# Cloud Monitoring and Logging configuration

# Log sink for Databricks logs
resource "google_logging_project_sink" "databricks_logs" {
  count = var.enable_monitoring ? 1 : 0
  
  name        = "databricks-logs-sink-${local.name_suffix}"
  destination = "storage.googleapis.com/${google_storage_bucket.logging_bucket.name}"

  filter = "resource.type=\"gce_instance\" AND resource.labels.instance_name:\"databricks-*\""

  unique_writer_identity = true
}

# Grant the log writer permission to write to the bucket
resource "google_storage_bucket_iam_member" "log_writer" {
  count = var.enable_monitoring ? 1 : 0
  
  bucket = google_storage_bucket.logging_bucket.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.databricks_logs[0].writer_identity
}

# Cloud Monitoring notification channel (email)
resource "google_monitoring_notification_channel" "email" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name = "Email Notifications"
  type         = "email"
  
  labels = {
    email_address = "admin@example.com" # Replace with actual email
  }

  enabled = true
}

# Monitoring dashboard
resource "google_monitoring_dashboard" "databricks_dashboard" {
  count = var.enable_monitoring ? 1 : 0
  
  dashboard_json = jsonencode({
    displayName = "Databricks Analytics Dashboard"
    
    mosaicLayout = {
      tiles = [
        {
          width = 6
          height = 4
          widget = {
            title = "Cluster CPU Utilization"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"gce_instance\" AND metadata.user_labels.\"cluster-name\"=~\"databricks-.*\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_MEAN"
                      crossSeriesReducer = "REDUCE_MEAN"
                      groupByFields = ["resource.label.instance_id"]
                    }
                  }
                }
              }]
              yAxis = {
                label = "CPU Utilization %"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width = 6
          height = 4
          xPos = 6
          widget = {
            title = "Memory Utilization"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"gce_instance\" AND metadata.user_labels.\"cluster-name\"=~\"databricks-.*\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_MEAN"
                      crossSeriesReducer = "REDUCE_MEAN"
                      groupByFields = ["resource.label.instance_id"]
                    }
                  }
                }
              }]
              yAxis = {
                label = "Memory Usage %"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width = 12
          height = 4
          yPos = 4
          widget = {
            title = "Job Execution Status"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"databricks_job\""
                  aggregation = {
                    alignmentPeriod  = "3600s"
                    perSeriesAligner = "ALIGN_COUNT"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields = ["metric.label.status"]
                  }
                }
              }
            }
          }
        }
      ]
    }
  })
}

# Alert policy for high CPU usage
resource "google_monitoring_alert_policy" "high_cpu" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name = "High CPU Usage - Databricks Clusters"
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "CPU Usage > 85%"
    
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metadata.user_labels.\"cluster-name\"=~\"databricks-.*\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 85

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields = ["resource.label.instance_id"]
      }
    }
  }

  notification_channels = var.enable_monitoring ? [google_monitoring_notification_channel.email[0].id] : []

  alert_strategy {
    auto_close = "604800s" # 7 days
  }
}

# Alert policy for failed jobs
resource "google_monitoring_alert_policy" "failed_jobs" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name = "Databricks Job Failures"
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "Job Failure Rate"
    
    condition_threshold {
      filter          = "resource.type=\"databricks_job\" AND metric.label.status=\"FAILED\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  notification_channels = var.enable_monitoring ? [google_monitoring_notification_channel.email[0].id] : []
}

# Cloud Function for custom metrics (optional)
resource "google_cloudfunctions_function" "metrics_collector" {
  count = var.enable_monitoring ? 1 : 0
  
  name        = "databricks-metrics-collector-${local.name_suffix}"
  description = "Collects custom metrics from Databricks"
  runtime     = "python39"

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.databricks_artifacts.name
  source_archive_object = "metrics-collector.zip"
  trigger {
    event_trigger {
      event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
      resource   = google_pubsub_topic.metrics_topic[0].name
    }
  }
  timeout               = 60
  entry_point          = "collect_metrics"
  service_account_email = google_service_account.databricks_sa.email

  environment_variables = {
    PROJECT_ID = var.project_id
    REGION     = var.region
  }
}

# Pub/Sub topic for metrics collection
resource "google_pubsub_topic" "metrics_topic" {
  count = var.enable_monitoring ? 1 : 0
  
  name = "databricks-metrics-${local.name_suffix}"

  labels = local.common_tags
}

# Pub/Sub subscription
resource "google_pubsub_subscription" "metrics_subscription" {
  count = var.enable_monitoring ? 1 : 0
  
  name  = "databricks-metrics-sub-${local.name_suffix}"
  topic = google_pubsub_topic.metrics_topic[0].name

  ack_deadline_seconds = 20

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic = google_pubsub_topic.metrics_topic[0].id
    max_delivery_attempts = 5
  }

  labels = local.common_tags
}