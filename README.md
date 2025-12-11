# Databricks on GCP - End-to-End Analytics Platform

A comprehensive data analytics platform built with Databricks on Google Cloud Platform, with automated infrastructure deployment, data pipelines, and monitoring.

## Quick Start

```bash
# Setup GCP credentials
gcloud auth application-default login

# Deploy infrastructure
cd infrastructure
terraform init
terraform apply

# Deploy Databricks workspace
./scripts/deploy-databricks.sh

# Run sample pipeline
databricks jobs run-now --job-id <job-id>
```

## Project Overview

This repository contains a comprehensive data analytics solution using:

- Google Cloud Platform**: Infrastructure and storage
- Databricks**: Analytics and ML workspaces
- Terraform**: Infrastructure as Code
- Apache Spark**: Distributed data processing
- Delta Lake**: Data lakehouse architecture
- MLflow**: ML lifecycle management

## Architecture

### Infrastructure Components

- GCP Project**: Isolated environment for resources
- VPC Network**: Secure networking with private subnets
- Cloud Storage**: Data lake storage buckets
- Cloud SQL**: Metadata and configuration storage
- BigQuery**: Data warehouse for analytics
- Cloud Monitoring**: Observability and alerting

### Databricks Components

- Workspace**: Collaborative analytics environment
- Clusters**: Auto-scaling compute resources
- Jobs**: Automated pipeline execution
- Notebooks**: Interactive data exploration
- ML Experiments**: Model training and tracking

## Project Structure

```
databricks-gcp/
├── README.md                    # Project overview
├── infrastructure/              # Terraform IaC
│   ├── main.tf                  # Main infrastructure
│   ├── variables.tf             # Configuration variables
│   ├── outputs.tf               # Resource outputs
│   ├── gcp.tf                   # GCP provider config
│   ├── network.tf               # VPC and networking
│   ├── storage.tf               # Cloud Storage buckets
│   ├── databricks.tf            # Databricks workspace
│   └── monitoring.tf            # Logging and monitoring
├── pipelines/                   # Data pipeline code
│   ├── etl/                     # Extract, Transform, Load
│   ├── ml/                      # Machine Learning
│   └── streaming/               # Real-time processing
├── notebooks/                   # Databricks notebooks
│   ├── data_exploration.py      # Data analysis
│   ├── feature_engineering.py  # ML feature prep
│   └── model_training.py       # ML model development
├── scripts/                     # Automation scripts
│   ├── deploy-databricks.sh     # Workspace deployment
│   ├── setup-environment.sh     # Environment setup
│   └── cleanup-resources.sh     # Resource cleanup
├── monitoring/                  # Observability config
│   ├── dashboards/              # Monitoring dashboards
│   ├── alerts/                  # Alert configurations
│   └── logs/                    # Log analysis
└── tests/                       # Testing framework
    ├── unit/                    # Unit tests
    ├── integration/             # Integration tests
    └── e2e/                     # End-to-end tests
```

## Prerequisites

### Required Tools

- Google Cloud SDK**: `gcloud` CLI
- Terraform**: >= 1.0
- Databricks CLI**: For workspace management
- Python**: >= 3.8 for pipeline development
- Docker**: For containerized deployments

### Required Permissions

```bash
# GCP IAM roles needed
roles/compute.admin
roles/storage.admin
roles/bigquery.admin
roles/iam.serviceAccountAdmin
roles/monitoring.admin
```

##  Installation

### 1. Environment Setup

```bash
# Clone repository
git clone <repository-url>
cd databricks-gcp

# Setup GCP authentication
gcloud auth application-default login
gcloud config set project <your-project-id>

# Install dependencies
pip install -r requirements.txt
```

### 2. Infrastructure Deployment

```bash
cd infrastructure

# Initialize Terraform
terraform init

# Review planned changes
terraform plan -var="project_id=your-project-id"

# Deploy infrastructure
terraform apply
```

### 3. Databricks Configuration

```bash
# Configure Databricks CLI
databricks configure

# Deploy workspace resources
./scripts/deploy-databricks.sh
```

## Configuration

### Environment Variables

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
export DATABRICKS_HOST="https://your-workspace.cloud.databricks.com"
export DATABRICKS_TOKEN="your-access-token"
```

### Terraform Variables

Create `infrastructure/terraform.tfvars`:

```hcl
project_id = "your-project-id"
region = "us-central1"
environment = "dev"

databricks_account_id = "your-account-id"
databricks_workspace_name = "analytics-workspace"

# Storage configuration
data_lake_bucket = "your-datalake-bucket"
warehouse_dataset = "analytics_warehouse"

# Network configuration
vpc_cidr = "10.0.0.0/16"
private_subnet_cidr = "10.0.1.0/24"
public_subnet_cidr = "10.0.2.0/24"
```

## Data Pipelines

### ETL Pipelines

- Bronze Layer**: Raw data ingestion from various sources
- Silver Layer**: Cleaned and validated data
- Gold Layer**: Business-ready aggregated data

### ML Pipelines

- Feature Engineering**: Automated feature extraction
- Model Training**: Distributed ML model development
- Model Serving**: Real-time prediction endpoints

### Streaming Pipelines

- Real-time Ingestion**: Kafka/Pub/Sub integration
- Stream Processing**: Apache Spark Streaming
- Real-time Analytics**: Live dashboards and alerts

##  Monitoring and Observability

### Infrastructure Monitoring

- GCP Monitoring**: Resource utilization and health
- Custom Dashboards**: Business metrics visualization
- Alerting**: Proactive issue detection

### Pipeline Monitoring

- Job Execution**: Success/failure tracking
- Data Quality**: Automated validation checks
- Performance**: Query and processing metrics

##  Testing

### Unit Tests

```bash
# Run Python unit tests
cd tests/unit
python -m pytest

# Run Spark tests
cd tests/spark
python -m pytest test_transformations.py
```

### Integration Tests

```bash
# Test pipeline integration
cd tests/integration
python -m pytest test_pipeline_integration.py
```

### End-to-End Tests

```bash
# Run full pipeline tests
cd tests/e2e
python -m pytest test_complete_pipeline.py
```

##  Cost Optimization

### Infrastructure Costs

- Compute**: Auto-scaling Databricks clusters
- Storage**: Tiered storage with lifecycle policies
- Network**: Optimized data transfer patterns

### Cost Monitoring

- Budget Alerts**: Automated cost notifications
- Resource Tagging**: Detailed cost attribution
- Usage Analytics**: Optimization recommendations

## Security

### Access Control

- IAM Integration**: GCP Identity and Access Management
- Service Accounts**: Principle of least privilege
- Network Security**: VPC and firewall rules

### Data Security

- Encryption**: At-rest and in-transit encryption
- Data Classification**: Sensitive data handling
- Audit Logging**: Comprehensive access tracking

## Deployment

### CI/CD Pipeline

```yaml
# GitHub Actions example
name: Deploy Databricks Pipeline
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v1
      
      - name: Deploy Infrastructure
        run: |
          cd infrastructure
          terraform init
          terraform apply -auto-approve
      
      - name: Deploy Databricks
        run: ./scripts/deploy-databricks.sh
```

### Production Deployment

```bash
# Production deployment
terraform workspace select prod
terraform apply -var-file="prod.tfvars"
```

## Documentation

- Architecture Guide**: Detailed system design
- API Reference**: Databricks and GCP APIs
- Troubleshooting**: Common issues and solutions
- Best Practices**: Development guidelines

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-pipeline`
3. Commit changes: `git commit -m 'Add amazing pipeline feature'`
4. Push to branch: `git push origin feature/amazing-pipeline`
5. Submit pull request

## Support

### Getting Help

- Review documentation in `/docs` directory
- Check troubleshooting guides
- Examine monitoring dashboards for issues
- Review logs in Cloud Logging

### Common Issues

- Authentication**: Verify GCP credentials and Databricks tokens
- Permissions**: Check IAM roles and service accounts
- Network**: Validate VPC and firewall configurations
- Quotas**: Monitor GCP resource quotas

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Built for scalable data analytics on Google Cloud Platform with Databricks**
