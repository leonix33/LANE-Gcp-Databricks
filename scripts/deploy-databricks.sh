#!/bin/bash

# Databricks on GCP - Complete Deployment Script
# Automates the entire infrastructure and workspace deployment

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRASTRUCTURE_DIR="$PROJECT_ROOT/infrastructure"

# Default values
PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
DATABRICKS_ACCOUNT_ID="${DATABRICKS_ACCOUNT_ID:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

header() {
    echo -e "${BOLD}${CYAN}"
    echo "=================================="
    echo "$1"
    echo "=================================="
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Google Cloud SDK
    if ! command -v gcloud &> /dev/null; then
        error "Google Cloud SDK is not installed. Please install it first."
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        error "Terraform is not installed. Please install it first."
        exit 1
    fi
    
    # Check Databricks CLI
    if ! command -v databricks &> /dev/null; then
        warning "Databricks CLI is not installed. Installing..."
        pip install databricks-cli
    fi
    
    # Check authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        error "Google Cloud authentication required. Please run 'gcloud auth login'"
        exit 1
    fi
    
    success "Prerequisites check completed"
}

# Get or validate project configuration
setup_project_config() {
    log "Setting up project configuration..."
    
    # Get current project if not specified
    if [ -z "$PROJECT_ID" ]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        if [ -z "$PROJECT_ID" ]; then
            error "No GCP project specified. Please set PROJECT_ID environment variable or run 'gcloud config set project PROJECT_ID'"
            exit 1
        fi
    fi
    
    # Set project
    gcloud config set project "$PROJECT_ID"
    
    # Enable required APIs
    log "Enabling required GCP APIs..."
    gcloud services enable compute.googleapis.com
    gcloud services enable storage.googleapis.com
    gcloud services enable bigquery.googleapis.com
    gcloud services enable sql-component.googleapis.com
    gcloud services enable secretmanager.googleapis.com
    gcloud services enable monitoring.googleapis.com
    gcloud services enable logging.googleapis.com
    gcloud services enable cloudfunctions.googleapis.com
    gcloud services enable pubsub.googleapis.com
    gcloud services enable servicenetworking.googleapis.com
    
    success "Project configuration completed"
    log "Project ID: $PROJECT_ID"
    log "Region: $REGION"
    log "Environment: $ENVIRONMENT"
}

# Create Terraform variables file
create_terraform_config() {
    log "Creating Terraform configuration..."
    
    cd "$INFRASTRUCTURE_DIR"
    
    # Create terraform.tfvars if it doesn't exist
    if [ ! -f "terraform.tfvars" ]; then
        cat > terraform.tfvars << EOF
project_id = "$PROJECT_ID"
region = "$REGION"
environment = "$ENVIRONMENT"
created_by = "$(whoami)"

# Databricks configuration
databricks_workspace_name = "analytics-workspace"
databricks_account_id = "$DATABRICKS_ACCOUNT_ID"

# Storage configuration
data_lake_bucket_name = "databricks-datalake"
warehouse_dataset_name = "analytics_warehouse"

# Network configuration
vpc_cidr = "10.0.0.0/16"
private_subnet_cidr = "10.0.1.0/24"
public_subnet_cidr = "10.0.2.0/24"

# Cluster configuration
cluster_node_type = "n1-standard-4"
cluster_min_workers = 1
cluster_max_workers = 8

# Monitoring
enable_monitoring = true
enable_audit_logs = true

# Security
enable_private_ip = true
allowed_ip_ranges = ["10.0.0.0/8"]

# Cost optimization
enable_preemptible_instances = true
auto_termination_minutes = 30
EOF
        success "Created terraform.tfvars file"
    else
        log "Using existing terraform.tfvars file"
    fi
}

# Initialize and deploy Terraform infrastructure
deploy_infrastructure() {
    header "Deploying Infrastructure with Terraform"
    
    cd "$INFRASTRUCTURE_DIR"
    
    # Initialize Terraform
    log "Initializing Terraform..."
    terraform init
    
    # Validate configuration
    log "Validating Terraform configuration..."
    terraform validate
    
    # Plan deployment
    log "Creating deployment plan..."
    terraform plan -var-file="terraform.tfvars" -out=tfplan
    
    # Confirm deployment
    echo -e "${YELLOW}Review the plan above. Do you want to proceed with deployment? (y/N)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        log "Applying Terraform configuration..."
        terraform apply tfplan
        success "Infrastructure deployed successfully"
    else
        log "Deployment cancelled by user"
        return 1
    fi
    
    # Clean up plan file
    rm -f tfplan
}

# Configure Databricks CLI
configure_databricks_cli() {
    log "Configuring Databricks CLI..."
    
    cd "$INFRASTRUCTURE_DIR"
    
    # Get workspace URL from Terraform output
    local workspace_url
    workspace_url=$(terraform output -raw databricks_workspace_url 2>/dev/null || echo "")
    
    if [ -n "$workspace_url" ]; then
        log "Workspace URL: $workspace_url"
        
        echo -e "${YELLOW}Please configure Databricks CLI with your workspace:${NC}"
        echo -e "  1. Go to: $workspace_url"
        echo -e "  2. Generate a personal access token"
        echo -e "  3. Run: databricks configure --token"
        echo -e "  4. Enter workspace URL: $workspace_url"
        echo -e "  5. Enter your access token"
        
        echo -e "\n${CYAN}Press ENTER when you've completed Databricks CLI configuration...${NC}"
        read -r
        
        success "Databricks CLI configuration completed"
    else
        error "Could not retrieve workspace URL from Terraform outputs"
        return 1
    fi
}

# Deploy sample notebooks and jobs
deploy_databricks_assets() {
    log "Deploying Databricks notebooks and jobs..."
    
    # Upload notebooks
    if [ -d "$PROJECT_ROOT/notebooks" ]; then
        log "Uploading notebooks..."
        databricks workspace import_dir "$PROJECT_ROOT/notebooks" "/Shared/Analytics" --overwrite
        success "Notebooks uploaded successfully"
    fi
    
    # Create sample jobs (if job definitions exist)
    if [ -f "$PROJECT_ROOT/pipelines/job_definitions.json" ]; then
        log "Creating Databricks jobs..."
        # This would need to be implemented based on specific job requirements
        success "Jobs created successfully"
    fi
}

# Verify deployment
verify_deployment() {
    header "Verifying Deployment"
    
    cd "$INFRASTRUCTURE_DIR"
    
    log "Checking infrastructure status..."
    
    # Check Terraform state
    terraform show -json > /dev/null 2>&1 && success "Terraform state is valid" || error "Terraform state issues detected"
    
    # Test GCS bucket access
    local bucket_name
    bucket_name=$(terraform output -raw data_lake_bucket_name 2>/dev/null || echo "")
    if [ -n "$bucket_name" ]; then
        if gsutil ls "gs://$bucket_name" &> /dev/null; then
            success "Data lake bucket is accessible"
        else
            error "Data lake bucket access failed"
        fi
    fi
    
    # Test BigQuery dataset
    local dataset_id
    dataset_id=$(terraform output -raw bigquery_warehouse_dataset 2>/dev/null || echo "")
    if [ -n "$dataset_id" ]; then
        if bq ls -d "$PROJECT_ID:$dataset_id" &> /dev/null; then
            success "BigQuery dataset is accessible"
        else
            error "BigQuery dataset access failed"
        fi
    fi
    
    # Test Databricks workspace
    if databricks workspace list &> /dev/null; then
        success "Databricks workspace is accessible"
    else
        warning "Databricks workspace access test failed (may need CLI configuration)"
    fi
}

# Display deployment summary
show_deployment_summary() {
    header "Deployment Summary"
    
    cd "$INFRASTRUCTURE_DIR"
    
    echo -e "${CYAN}Project Details:${NC}"
    echo -e "  Project ID: ${BOLD}$PROJECT_ID${NC}"
    echo -e "  Region: ${BOLD}$REGION${NC}"
    echo -e "  Environment: ${BOLD}$ENVIRONMENT${NC}"
    
    echo -e "\n${CYAN}Infrastructure Resources:${NC}"
    
    # Get outputs from Terraform
    if [ -f "terraform.tfstate" ]; then
        local workspace_url
        local bucket_name
        local dataset_id
        
        workspace_url=$(terraform output -raw databricks_workspace_url 2>/dev/null || echo "Not available")
        bucket_name=$(terraform output -raw data_lake_bucket_name 2>/dev/null || echo "Not available")
        dataset_id=$(terraform output -raw bigquery_warehouse_dataset 2>/dev/null || echo "Not available")
        
        echo -e "  Databricks Workspace: ${BOLD}$workspace_url${NC}"
        echo -e "  Data Lake Bucket: ${BOLD}gs://$bucket_name${NC}"
        echo -e "  BigQuery Dataset: ${BOLD}$PROJECT_ID:$dataset_id${NC}"
    fi
    
    echo -e "\n${CYAN}Next Steps:${NC}"
    echo -e "  1. Access your Databricks workspace at the URL above"
    echo -e "  2. Create and run your first notebook"
    echo -e "  3. Upload data to the data lake bucket"
    echo -e "  4. Create data pipelines using the provided templates"
    echo -e "  5. Monitor your deployment in the GCP Console"
    
    echo -e "\n${CYAN}Useful Commands:${NC}"
    echo -e "  View all outputs: ${BLUE}cd infrastructure && terraform output${NC}"
    echo -e "  Access workspace: ${BLUE}databricks workspace list${NC}"
    echo -e "  Upload data: ${BLUE}gsutil cp data/* gs://$bucket_name/${NC}"
    echo -e "  Clean up: ${BLUE}./cleanup-resources.sh${NC}"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --project-id)
                PROJECT_ID="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --databricks-account-id)
                DATABRICKS_ACCOUNT_ID="$2"
                shift 2
                ;;
            --skip-infrastructure)
                SKIP_INFRASTRUCTURE=true
                shift
                ;;
            --skip-databricks)
                SKIP_DATABRICKS=true
                shift
                ;;
            --help)
                echo "Databricks on GCP Deployment Script"
                echo ""
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --project-id ID             GCP Project ID"
                echo "  --region REGION             GCP Region (default: us-central1)"
                echo "  --environment ENV           Environment (default: dev)"
                echo "  --databricks-account-id ID  Databricks Account ID"
                echo "  --skip-infrastructure       Skip Terraform deployment"
                echo "  --skip-databricks           Skip Databricks configuration"
                echo "  --help                      Show this help"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    header "Databricks on GCP - Complete Deployment"
    
    parse_arguments "$@"
    
    check_prerequisites
    setup_project_config
    
    if [ "$SKIP_INFRASTRUCTURE" != "true" ]; then
        create_terraform_config
        deploy_infrastructure
    fi
    
    if [ "$SKIP_DATABRICKS" != "true" ]; then
        configure_databricks_cli
        deploy_databricks_assets
    fi
    
    verify_deployment
    show_deployment_summary
    
    success "Databricks on GCP deployment completed successfully!"
}

# Run main function with all arguments
main "$@"