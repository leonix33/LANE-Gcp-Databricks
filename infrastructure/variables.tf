# Project and Region Configuration
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region for resources"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP Zone for resources"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "created_by" {
  description = "Who created this infrastructure"
  type        = string
  default     = "terraform"
}

# Databricks Configuration
variable "databricks_workspace_name" {
  description = "Name of the Databricks workspace"
  type        = string
  default     = "analytics-workspace"
}

variable "databricks_account_id" {
  description = "Databricks Account ID"
  type        = string
}

# Storage Configuration
variable "data_lake_bucket_name" {
  description = "Name for the data lake bucket"
  type        = string
  default     = "databricks-datalake"
}

variable "warehouse_dataset_name" {
  description = "BigQuery dataset name for data warehouse"
  type        = string
  default     = "analytics_warehouse"
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.2.0/24"
}

# Databricks Cluster Configuration
variable "cluster_node_type" {
  description = "Node type for Databricks clusters"
  type        = string
  default     = "n1-standard-4"
}

variable "cluster_min_workers" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 1
}

variable "cluster_max_workers" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 8
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable Cloud Monitoring and Logging"
  type        = bool
  default     = true
}

variable "enable_audit_logs" {
  description = "Enable audit logging"
  type        = bool
  default     = true
}

# Security Configuration
variable "enable_private_ip" {
  description = "Enable private IP for instances"
  type        = bool
  default     = true
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access resources"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

# Cost Optimization
variable "enable_preemptible_instances" {
  description = "Use preemptible instances for cost optimization"
  type        = bool
  default     = true
}

variable "auto_termination_minutes" {
  description = "Auto-terminate idle clusters after minutes"
  type        = number
  default     = 30
}