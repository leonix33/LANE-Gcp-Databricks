#!/bin/bash

# Security Tools Setup Script
# Installs and configures security and cost optimization tools

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Setting up Databricks security and cost optimization tools..."

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r "$PROJECT_ROOT/security/requirements.txt"

# Create necessary directories
mkdir -p "$PROJECT_ROOT/logs/security"
mkdir -p "$PROJECT_ROOT/reports/security"
mkdir -p "$PROJECT_ROOT/reports/cost"

# Make scripts executable
chmod +x "$PROJECT_ROOT/security/tools/security-monitor.sh"
chmod +x "$PROJECT_ROOT/security/tools/databricks-security-scanner.py"
chmod +x "$PROJECT_ROOT/monitoring/cost-optimization/cost-analyzer.py"

# Create configuration from template
if [[ ! -f "$PROJECT_ROOT/security/config/monitor-config.json.local" ]]; then
    cp "$PROJECT_ROOT/security/config/monitor-config.json" "$PROJECT_ROOT/security/config/monitor-config.json.local"
    echo "Created local configuration file. Please update with your credentials:"
    echo "  $PROJECT_ROOT/security/config/monitor-config.json.local"
fi

echo "Security tools setup completed!"
echo ""
echo "Next steps:"
echo "1. Update security/config/monitor-config.json.local with your Databricks credentials"
echo "2. Run security scan: ./security/tools/security-monitor.sh --scan-only"
echo "3. Run cost analysis: python3 monitoring/cost-optimization/cost-analyzer.py --help"
echo "4. Set up automated monitoring with cron"

