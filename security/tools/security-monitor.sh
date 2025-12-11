#!/bin/bash

# Databricks Security Monitoring Script
# Automated security scanning and compliance checking

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/security/config/monitor-config.json"
LOG_DIR="$PROJECT_ROOT/logs/security"
REPORT_DIR="$PROJECT_ROOT/reports/security"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create directories
mkdir -p "$LOG_DIR" "$REPORT_DIR"

log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/security-monitor.log"
}

error() {
    log "${RED}ERROR: $1${NC}"
}

warn() {
    log "${YELLOW}WARNING: $1${NC}"
}

info() {
    log "${BLUE}INFO: $1${NC}"
}

success() {
    log "${GREEN}SUCCESS: $1${NC}"
}

check_dependencies() {
    info "Checking dependencies..."
    
    # Check for required tools
    local deps=("python3" "jq" "curl")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency '$dep' is not installed"
            exit 1
        fi
    done
    
    # Check for Python packages
    if ! python3 -c "import requests, pandas, yaml" &> /dev/null; then
        error "Required Python packages are missing. Install with: pip install requests pandas pyyaml"
        exit 1
    fi
    
    success "All dependencies are available"
}

load_config() {
    info "Loading configuration..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Validate JSON configuration
    if ! jq . "$CONFIG_FILE" > /dev/null 2>&1; then
        error "Invalid JSON in configuration file"
        exit 1
    fi
    
    # Extract configuration values
    WORKSPACE_URL=$(jq -r '.workspace_url' "$CONFIG_FILE")
    TOKEN=$(jq -r '.access_token' "$CONFIG_FILE")
    SCAN_INTERVAL=$(jq -r '.scan_interval_hours // 24' "$CONFIG_FILE")
    
    if [[ "$WORKSPACE_URL" == "null" ]] || [[ "$TOKEN" == "null" ]]; then
        error "Missing required configuration: workspace_url and access_token"
        exit 1
    fi
    
    success "Configuration loaded successfully"
}

run_security_scan() {
    info "Running security scan..."
    
    local timestamp=$(date +'%Y%m%d_%H%M%S')
    local report_file="$REPORT_DIR/security_scan_$timestamp.json"
    
    # Run security scanner
    python3 "$SCRIPT_DIR/databricks-security-scanner.py" \
        --workspace-url "$WORKSPACE_URL" \
        --token "$TOKEN" \
        --output "$report_file" \
        --verbose
    
    if [[ $? -eq 0 ]]; then
        success "Security scan completed: $report_file"
        
        # Parse results for immediate alerts
        local compliance_score=$(jq -r '.compliance_score' "$report_file")
        local critical_issues=$(jq -r '[.security_checks[] | select(.status == "FAIL")] | length' "$report_file")
        
        info "Compliance Score: $compliance_score%"
        
        if (( $(echo "$compliance_score < 70" | bc -l) )); then
            warn "Low compliance score detected: $compliance_score%"
            send_alert "COMPLIANCE" "Low compliance score: $compliance_score%" "$report_file"
        fi
        
        if [[ "$critical_issues" -gt 0 ]]; then
            warn "$critical_issues critical security issues found"
            send_alert "SECURITY" "$critical_issues critical issues detected" "$report_file"
        fi
        
        # Update latest report symlink
        ln -sf "$report_file" "$REPORT_DIR/latest_security_report.json"
        
    else
        error "Security scan failed"
        return 1
    fi
}

run_cost_analysis() {
    info "Running cost optimization analysis..."
    
    local timestamp=$(date +'%Y%m%d_%H%M%S')
    local report_file="$REPORT_DIR/cost_analysis_$timestamp.json"
    
    # Run cost analyzer
    python3 "$PROJECT_ROOT/monitoring/cost-optimization/cost-analyzer.py" \
        --workspace-url "$WORKSPACE_URL" \
        --token "$TOKEN" \
        --output "$report_file" \
        --verbose
    
    if [[ $? -eq 0 ]]; then
        success "Cost analysis completed: $report_file"
        
        # Parse results for cost alerts
        local potential_savings=$(jq -r '.summary.potential_monthly_savings' "$report_file")
        local optimization_priority=$(jq -r '.summary.optimization_priority' "$report_file")
        
        info "Potential Monthly Savings: \$$(printf "%.2f" "$potential_savings")"
        info "Optimization Priority: $optimization_priority"
        
        if [[ "$optimization_priority" == "HIGH" ]]; then
            warn "High cost optimization potential detected"
            send_alert "COST" "High cost optimization potential: \$$potential_savings/month" "$report_file"
        fi
        
        # Update latest report symlink
        ln -sf "$report_file" "$REPORT_DIR/latest_cost_report.json"
        
    else
        error "Cost analysis failed"
        return 1
    fi
}

check_compliance_rules() {
    info "Checking compliance rules..."
    
    local rules_file="$PROJECT_ROOT/security/policies/compliance-rules.yaml"
    local latest_scan="$REPORT_DIR/latest_security_report.json"
    
    if [[ ! -f "$latest_scan" ]]; then
        warn "No recent security scan available, skipping compliance check"
        return 1
    fi
    
    # Simple compliance checking (in a real implementation, this would be more sophisticated)
    local failed_checks=$(jq '[.security_checks[] | select(.status == "FAIL")] | length' "$latest_scan")
    local warning_checks=$(jq '[.security_checks[] | select(.status == "WARN")] | length' "$latest_scan")
    
    info "Compliance Status: $failed_checks failures, $warning_checks warnings"
    
    if [[ "$failed_checks" -gt 0 ]]; then
        warn "Compliance violations detected"
        return 1
    fi
    
    success "All compliance checks passed"
}

send_alert() {
    local alert_type="$1"
    local message="$2"
    local report_file="$3"
    
    info "Sending $alert_type alert: $message"
    
    # Check if notification configuration exists
    local notification_config=$(jq -r '.notifications // empty' "$CONFIG_FILE")
    
    if [[ -z "$notification_config" ]] || [[ "$notification_config" == "null" ]]; then
        warn "No notification configuration found"
        return 1
    fi
    
    # Send email notification (if configured)
    local email=$(jq -r '.notifications.email // empty' "$CONFIG_FILE")
    if [[ -n "$email" ]] && [[ "$email" != "null" ]]; then
        echo "Alert: $message" | mail -s "Databricks $alert_type Alert" "$email" 2>/dev/null || warn "Failed to send email alert"
    fi
    
    # Send Slack notification (if configured)
    local slack_webhook=$(jq -r '.notifications.slack_webhook // empty' "$CONFIG_FILE")
    if [[ -n "$slack_webhook" ]] && [[ "$slack_webhook" != "null" ]]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"Databricks $alert_type Alert: $message\"}" \
            "$slack_webhook" 2>/dev/null || warn "Failed to send Slack alert"
    fi
}

cleanup_old_reports() {
    info "Cleaning up old reports..."
    
    # Keep reports for 30 days
    find "$REPORT_DIR" -name "*.json" -mtime +30 -delete 2>/dev/null || true
    find "$LOG_DIR" -name "*.log" -mtime +30 -delete 2>/dev/null || true
    
    success "Cleanup completed"
}

generate_dashboard() {
    info "Generating security dashboard..."
    
    local dashboard_file="$REPORT_DIR/security_dashboard.html"
    local latest_security="$REPORT_DIR/latest_security_report.json"
    local latest_cost="$REPORT_DIR/latest_cost_report.json"
    
    if [[ ! -f "$latest_security" ]] || [[ ! -f "$latest_cost" ]]; then
        warn "Missing recent reports, skipping dashboard generation"
        return 1
    fi
    
    # Generate simple HTML dashboard
    cat > "$dashboard_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Databricks Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .good { border-left: 5px solid #4CAF50; }
        .warning { border-left: 5px solid #FF9800; }
        .critical { border-left: 5px solid #f44336; }
        .header { background: #2196F3; color: white; padding: 20px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Databricks Security Dashboard</h1>
        <p>Last updated: $(date)</p>
    </div>
    
    <div class="metric good">
        <h3>Compliance Score</h3>
        <p>$(jq -r '.compliance_score' "$latest_security")%</p>
    </div>
    
    <div class="metric warning">
        <h3>Potential Monthly Savings</h3>
        <p>\$$(jq -r '.summary.potential_monthly_savings' "$latest_cost")</p>
    </div>
    
    <div class="metric">
        <h3>Security Recommendations</h3>
        <ul>
$(jq -r '.recommendations[]' "$latest_security" | sed 's/^/            <li>/' | sed 's/$/<\/li>/')
        </ul>
    </div>
</body>
</html>
EOF
    
    success "Dashboard generated: $dashboard_file"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --scan-only        Run security scan only"
    echo "  --cost-only        Run cost analysis only"
    echo "  --compliance-only  Run compliance check only"
    echo "  --dashboard-only   Generate dashboard only"
    echo "  --config FILE      Use custom configuration file"
    echo "  --help             Show this help message"
}

# Main execution
main() {
    local scan_only=false
    local cost_only=false
    local compliance_only=false
    local dashboard_only=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --scan-only)
                scan_only=true
                shift
                ;;
            --cost-only)
                cost_only=true
                shift
                ;;
            --compliance-only)
                compliance_only=true
                shift
                ;;
            --dashboard-only)
                dashboard_only=true
                shift
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    info "Starting Databricks security monitoring..."
    
    check_dependencies
    load_config
    
    if [[ "$dashboard_only" == true ]]; then
        generate_dashboard
        exit 0
    fi
    
    if [[ "$compliance_only" == true ]]; then
        check_compliance_rules
        exit 0
    fi
    
    if [[ "$cost_only" == true ]]; then
        run_cost_analysis
        exit 0
    fi
    
    if [[ "$scan_only" == true ]]; then
        run_security_scan
        exit 0
    fi
    
    # Run full monitoring suite
    run_security_scan
    run_cost_analysis
    check_compliance_rules
    generate_dashboard
    cleanup_old_reports
    
    success "Security monitoring completed successfully"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi