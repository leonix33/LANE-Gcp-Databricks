# VPC Network for Databricks
resource "google_compute_network" "databricks_vpc" {
  name                    = "databricks-vpc-${local.name_suffix}"
  auto_create_subnetworks = false
  routing_mode           = "REGIONAL"

  lifecycle {
    prevent_destroy = false
  }
}

# Private subnet for Databricks clusters
resource "google_compute_subnetwork" "private_subnet" {
  name          = "databricks-private-${local.name_suffix}"
  ip_cidr_range = var.private_subnet_cidr
  region        = var.region
  network       = google_compute_network.databricks_vpc.id

  # Enable private Google access for instances without external IPs
  private_ip_google_access = true

  # Secondary IP ranges for pods and services (if needed for GKE integration)
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.2.0.0/20"
  }
}

# Public subnet for NAT gateway and load balancers
resource "google_compute_subnetwork" "public_subnet" {
  name          = "databricks-public-${local.name_suffix}"
  ip_cidr_range = var.public_subnet_cidr
  region        = var.region
  network       = google_compute_network.databricks_vpc.id

  private_ip_google_access = true
}

# Cloud Router for NAT gateway
resource "google_compute_router" "databricks_router" {
  name    = "databricks-router-${local.name_suffix}"
  region  = var.region
  network = google_compute_network.databricks_vpc.id
}

# NAT Gateway for outbound internet access from private instances
resource "google_compute_router_nat" "databricks_nat" {
  name                               = "databricks-nat-${local.name_suffix}"
  router                             = google_compute_router.databricks_router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall rules for Databricks
resource "google_compute_firewall" "databricks_internal" {
  name    = "databricks-internal-${local.name_suffix}"
  network = google_compute_network.databricks_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.vpc_cidr]
  target_tags   = ["databricks"]
}

# Firewall rule for SSH access (optional)
resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh-${local.name_suffix}"
  network = google_compute_network.databricks_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ip_ranges
  target_tags   = ["databricks"]
}

# Firewall rule for HTTPS access to Databricks UI
resource "google_compute_firewall" "allow_https" {
  name    = "allow-https-${local.name_suffix}"
  network = google_compute_network.databricks_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "8080"]
  }

  source_ranges = var.allowed_ip_ranges
  target_tags   = ["databricks-ui"]
}

# Private connection for Google services
resource "google_compute_global_address" "private_service_range" {
  name          = "private-service-range-${local.name_suffix}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.databricks_vpc.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.databricks_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range.name]

  depends_on = [google_compute_global_address.private_service_range]
}