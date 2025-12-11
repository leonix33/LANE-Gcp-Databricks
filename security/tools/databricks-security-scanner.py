#!/usr/bin/env python3
"""
Databricks Security Scanner
Open source security assessment tool for Databricks workspaces
"""

import json
import requests
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Any

class DatabricksSecurityScanner:
    def __init__(self, workspace_url: str, token: str):
        self.workspace_url = workspace_url.rstrip('/')
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def check_workspace_security(self) -> Dict[str, Any]:
        """Comprehensive security assessment of Databricks workspace"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'workspace_url': self.workspace_url,
            'security_checks': {
                'access_controls': self.check_access_controls(),
                'network_security': self.check_network_security(),
                'encryption': self.check_encryption_settings(),
                'audit_logging': self.check_audit_logging(),
                'secret_management': self.check_secret_management(),
                'cluster_security': self.check_cluster_security(),
                'user_permissions': self.check_user_permissions()
            },
            'compliance_score': 0,
            'recommendations': []
        }
        
        # Calculate compliance score
        results['compliance_score'] = self.calculate_compliance_score(results['security_checks'])
        results['recommendations'] = self.generate_recommendations(results['security_checks'])
        
        return results
    
    def check_access_controls(self) -> Dict[str, Any]:
        """Check workspace access control configuration"""
        try:
            # Check workspace access control enablement
            response = self.session.get(f'{self.workspace_url}/api/2.0/workspace-conf')
            workspace_config = response.json() if response.status_code == 200 else {}
            
            access_control_enabled = workspace_config.get('enableWorkspaceAccessControl', False)
            table_access_control = workspace_config.get('enableTableAccessControl', False)
            
            return {
                'workspace_access_control': access_control_enabled,
                'table_access_control': table_access_control,
                'status': 'PASS' if access_control_enabled and table_access_control else 'FAIL',
                'details': workspace_config
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def check_network_security(self) -> Dict[str, Any]:
        """Analyze network security configuration"""
        try:
            # Check for network policies and VPC configurations
            response = self.session.get(f'{self.workspace_url}/api/2.0/clusters/list')
            clusters = response.json().get('clusters', []) if response.status_code == 200 else []
            
            secure_clusters = 0
            total_clusters = len(clusters)
            
            for cluster in clusters:
                aws_attributes = cluster.get('aws_attributes', {})
                if aws_attributes.get('zone_id') and aws_attributes.get('instance_profile_arn'):
                    secure_clusters += 1
            
            security_ratio = secure_clusters / total_clusters if total_clusters > 0 else 0
            
            return {
                'secure_clusters': secure_clusters,
                'total_clusters': total_clusters,
                'security_ratio': security_ratio,
                'status': 'PASS' if security_ratio >= 0.8 else 'FAIL'
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def check_encryption_settings(self) -> Dict[str, Any]:
        """Verify encryption configuration"""
        try:
            response = self.session.get(f'{self.workspace_url}/api/2.0/workspace-conf')
            config = response.json() if response.status_code == 200 else {}
            
            encryption_enabled = config.get('enableCustomerManagedKeys', False)
            
            return {
                'customer_managed_keys': encryption_enabled,
                'status': 'PASS' if encryption_enabled else 'WARN',
                'details': 'Customer-managed keys provide additional security'
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def check_audit_logging(self) -> Dict[str, Any]:
        """Check audit logging configuration"""
        try:
            # Check if audit logs are enabled and properly configured
            response = self.session.get(f'{self.workspace_url}/api/2.0/workspace-conf')
            config = response.json() if response.status_code == 200 else {}
            
            audit_log_enabled = config.get('enableAuditLog', False)
            
            return {
                'audit_logging_enabled': audit_log_enabled,
                'status': 'PASS' if audit_log_enabled else 'FAIL',
                'details': 'Audit logging is essential for compliance and security monitoring'
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def check_secret_management(self) -> Dict[str, Any]:
        """Analyze secret management practices"""
        try:
            response = self.session.get(f'{self.workspace_url}/api/2.0/secrets/scopes/list')
            scopes = response.json().get('scopes', []) if response.status_code == 200 else []
            
            secure_scopes = sum(1 for scope in scopes if scope.get('backend_type') == 'AZURE_KEYVAULT')
            total_scopes = len(scopes)
            
            return {
                'secret_scopes': total_scopes,
                'secure_scopes': secure_scopes,
                'status': 'PASS' if secure_scopes == total_scopes and total_scopes > 0 else 'WARN',
                'details': 'Use external secret management services for enhanced security'
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def check_cluster_security(self) -> Dict[str, Any]:
        """Analyze cluster security configuration"""
        try:
            response = self.session.get(f'{self.workspace_url}/api/2.0/clusters/list')
            clusters = response.json().get('clusters', []) if response.status_code == 200 else []
            
            secure_clusters = 0
            issues = []
            
            for cluster in clusters:
                cluster_name = cluster.get('cluster_name', 'Unknown')
                
                # Check for security best practices
                if not cluster.get('enable_elastic_disk', True):
                    issues.append(f"Cluster '{cluster_name}': Elastic disk not enabled")
                
                if cluster.get('autotermination_minutes', 0) == 0:
                    issues.append(f"Cluster '{cluster_name}': Auto-termination not configured")
                
                # Check for latest Databricks Runtime
                runtime_version = cluster.get('spark_version', '')
                if 'LTS' not in runtime_version:
                    issues.append(f"Cluster '{cluster_name}': Not using LTS runtime")
                
                if len(issues) == 0:
                    secure_clusters += 1
            
            return {
                'secure_clusters': secure_clusters,
                'total_clusters': len(clusters),
                'security_issues': issues,
                'status': 'PASS' if len(issues) == 0 else 'WARN'
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def check_user_permissions(self) -> Dict[str, Any]:
        """Analyze user permissions and access patterns"""
        try:
            response = self.session.get(f'{self.workspace_url}/api/2.0/preview/scim/v2/Users')
            users = response.json().get('Resources', []) if response.status_code == 200 else []
            
            admin_users = sum(1 for user in users if user.get('active', False) and 
                            any(group.get('display') == 'admins' for group in user.get('groups', [])))
            
            total_active_users = sum(1 for user in users if user.get('active', False))
            admin_ratio = admin_users / total_active_users if total_active_users > 0 else 0
            
            return {
                'total_users': total_active_users,
                'admin_users': admin_users,
                'admin_ratio': admin_ratio,
                'status': 'PASS' if admin_ratio <= 0.2 else 'WARN',
                'details': 'Limit admin privileges following principle of least privilege'
            }
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}
    
    def calculate_compliance_score(self, checks: Dict[str, Any]) -> float:
        """Calculate overall compliance score based on security checks"""
        total_checks = 0
        passed_checks = 0
        
        for check_name, result in checks.items():
            total_checks += 1
            if result.get('status') == 'PASS':
                passed_checks += 1
        
        return (passed_checks / total_checks * 100) if total_checks > 0 else 0
    
    def generate_recommendations(self, checks: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on failed checks"""
        recommendations = []
        
        for check_name, result in checks.items():
            if result.get('status') in ['FAIL', 'WARN']:
                if check_name == 'access_controls':
                    recommendations.append('Enable workspace and table access controls')
                elif check_name == 'network_security':
                    recommendations.append('Configure VPC and proper network security settings')
                elif check_name == 'encryption':
                    recommendations.append('Implement customer-managed encryption keys')
                elif check_name == 'audit_logging':
                    recommendations.append('Enable comprehensive audit logging')
                elif check_name == 'secret_management':
                    recommendations.append('Use external secret management services')
                elif check_name == 'cluster_security':
                    recommendations.append('Review cluster security configurations')
                elif check_name == 'user_permissions':
                    recommendations.append('Review and minimize administrative privileges')
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Databricks Security Scanner')
    parser.add_argument('--workspace-url', required=True, help='Databricks workspace URL')
    parser.add_argument('--token', required=True, help='Databricks access token')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    scanner = DatabricksSecurityScanner(args.workspace_url, args.token)
    results = scanner.check_workspace_security()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Security assessment results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    print(f"\nCompliance Score: {results['compliance_score']:.1f}%")
    if results['recommendations']:
        print("\nRecommendations:")
        for i, rec in enumerate(results['recommendations'], 1):
            print(f"{i}. {rec}")

if __name__ == '__main__':
    main()