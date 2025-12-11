#!/usr/bin/env python3
"""
Databricks Cost Optimization Analyzer
Analyzes Databricks usage patterns and provides cost optimization recommendations
"""

import json
import requests
import argparse
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

class DatabricksCostAnalyzer:
    def __init__(self, workspace_url: str, token: str):
        self.workspace_url = workspace_url.rstrip('/')
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def analyze_cluster_utilization(self, days: int = 30) -> Dict[str, Any]:
        """Analyze cluster utilization patterns for cost optimization"""
        try:
            # Get cluster list
            clusters_response = self.session.get(f'{self.workspace_url}/api/2.0/clusters/list')
            clusters = clusters_response.json().get('clusters', [])
            
            analysis = {
                'total_clusters': len(clusters),
                'underutilized_clusters': [],
                'oversized_clusters': [],
                'idle_clusters': [],
                'cost_optimization_potential': 0,
                'recommendations': []
            }
            
            for cluster in clusters:
                cluster_id = cluster.get('cluster_id')
                cluster_name = cluster.get('cluster_name', 'Unknown')
                
                # Analyze cluster configuration
                node_type = cluster.get('node_type_id', '')
                num_workers = cluster.get('num_workers', 0)
                autoscale = cluster.get('autoscale', {})
                
                # Check for potential issues
                issues = self.analyze_cluster_configuration(cluster)
                if issues:
                    if 'underutilized' in issues:
                        analysis['underutilized_clusters'].append({
                            'name': cluster_name,
                            'id': cluster_id,
                            'issues': issues,
                            'potential_savings': self.estimate_cluster_savings(cluster)
                        })
                    
                    if 'oversized' in issues:
                        analysis['oversized_clusters'].append({
                            'name': cluster_name,
                            'id': cluster_id,
                            'issues': issues,
                            'potential_savings': self.estimate_cluster_savings(cluster)
                        })
                    
                    if 'idle' in issues:
                        analysis['idle_clusters'].append({
                            'name': cluster_name,
                            'id': cluster_id,
                            'issues': issues,
                            'potential_savings': self.estimate_cluster_savings(cluster)
                        })
            
            # Calculate total optimization potential
            analysis['cost_optimization_potential'] = sum([
                sum(cluster.get('potential_savings', 0) for cluster in analysis['underutilized_clusters']),
                sum(cluster.get('potential_savings', 0) for cluster in analysis['oversized_clusters']),
                sum(cluster.get('potential_savings', 0) for cluster in analysis['idle_clusters'])
            ])
            
            # Generate recommendations
            analysis['recommendations'] = self.generate_cost_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_cluster_configuration(self, cluster: Dict[str, Any]) -> List[str]:
        """Analyze individual cluster configuration for cost issues"""
        issues = []
        
        # Check auto-termination
        auto_termination = cluster.get('autotermination_minutes', 0)
        if auto_termination == 0:
            issues.append('No auto-termination configured')
        elif auto_termination > 120:  # More than 2 hours
            issues.append('Long auto-termination period')
        
        # Check cluster size
        num_workers = cluster.get('num_workers', 0)
        autoscale = cluster.get('autoscale', {})
        
        if not autoscale and num_workers > 10:
            issues.append('oversized')
        
        # Check for expensive instance types
        node_type = cluster.get('node_type_id', '')
        if any(expensive_type in node_type.lower() for expensive_type in ['large', 'xlarge', 'gpu']):
            issues.append('expensive_instance_type')
        
        # Check runtime version (older versions might be less efficient)
        runtime_version = cluster.get('spark_version', '')
        if not any(version in runtime_version for version in ['10.', '11.', '12.']):
            issues.append('outdated_runtime')
        
        # Check cluster state
        state = cluster.get('state', '')
        if state in ['PENDING', 'RESTARTING'] and cluster.get('last_activity_time', 0) < (datetime.now().timestamp() - 3600):
            issues.append('idle')
        
        return issues
    
    def estimate_cluster_savings(self, cluster: Dict[str, Any]) -> float:
        """Estimate potential cost savings for a cluster"""
        # Simple cost estimation based on cluster configuration
        # This is a rough estimate - actual costs depend on usage patterns
        
        num_workers = cluster.get('num_workers', 0)
        node_type = cluster.get('node_type_id', '')
        
        # Basic hourly cost estimates (these should be updated based on actual pricing)
        base_cost_per_hour = {
            'small': 0.5,
            'medium': 1.0,
            'large': 2.0,
            'xlarge': 4.0,
            'gpu': 8.0
        }
        
        # Determine cost category based on instance type
        cost_category = 'medium'  # default
        for category in base_cost_per_hour.keys():
            if category in node_type.lower():
                cost_category = category
                break
        
        hourly_cost = base_cost_per_hour[cost_category] * (num_workers + 1)  # +1 for driver
        
        # Estimate savings based on optimization potential
        # This is a simplified calculation
        potential_reduction = 0.3  # 30% potential savings on average
        monthly_hours = 720  # Average hours per month
        
        return hourly_cost * monthly_hours * potential_reduction
    
    def analyze_job_efficiency(self) -> Dict[str, Any]:
        """Analyze job execution efficiency"""
        try:
            # Get jobs list
            jobs_response = self.session.get(f'{self.workspace_url}/api/2.0/jobs/list')
            jobs = jobs_response.json().get('jobs', [])
            
            analysis = {
                'total_jobs': len(jobs),
                'inefficient_jobs': [],
                'optimization_opportunities': []
            }
            
            for job in jobs:
                job_id = job.get('job_id')
                job_name = job.get('settings', {}).get('name', 'Unknown')
                
                # Analyze job configuration
                inefficiencies = self.analyze_job_configuration(job)
                if inefficiencies:
                    analysis['inefficient_jobs'].append({
                        'name': job_name,
                        'id': job_id,
                        'issues': inefficiencies
                    })
            
            # Generate optimization opportunities
            analysis['optimization_opportunities'] = self.generate_job_optimizations(analysis)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_job_configuration(self, job: Dict[str, Any]) -> List[str]:
        """Analyze job configuration for efficiency issues"""
        issues = []
        settings = job.get('settings', {})
        
        # Check timeout settings
        timeout_seconds = settings.get('timeout_seconds', 0)
        if timeout_seconds == 0:
            issues.append('No timeout configured')
        
        # Check max concurrent runs
        max_concurrent_runs = settings.get('max_concurrent_runs', 1)
        if max_concurrent_runs > 5:
            issues.append('High concurrent runs may cause resource contention')
        
        # Check schedule efficiency
        schedule = settings.get('schedule', {})
        if schedule and schedule.get('quartz_cron_expression', '').count('*') > 3:
            issues.append('Frequent scheduling may be inefficient')
        
        return issues
    
    def generate_cost_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate cost optimization recommendations"""
        recommendations = []
        
        if analysis['underutilized_clusters']:
            recommendations.append('Enable auto-scaling on underutilized clusters to reduce costs during low usage')
        
        if analysis['oversized_clusters']:
            recommendations.append('Right-size oversized clusters to match actual workload requirements')
        
        if analysis['idle_clusters']:
            recommendations.append('Configure auto-termination for idle clusters (recommend 30-60 minutes)')
        
        if analysis['cost_optimization_potential'] > 1000:  # Significant savings potential
            recommendations.append('Consider using spot instances for non-critical workloads')
            recommendations.append('Implement cluster policies to prevent overprovisioning')
            recommendations.append('Review and optimize job schedules to reduce resource overlap')
        
        recommendations.extend([
            'Use pool-based clusters for better resource utilization',
            'Implement Delta Lake for improved storage efficiency',
            'Consider photon acceleration for SQL workloads',
            'Monitor and optimize data transfer costs',
            'Use appropriate storage classes for different data access patterns'
        ])
        
        return recommendations
    
    def generate_job_optimizations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate job optimization recommendations"""
        optimizations = []
        
        if analysis['inefficient_jobs']:
            optimizations.extend([
                'Optimize Spark configurations for better performance',
                'Implement proper partitioning strategies',
                'Use broadcast joins for small lookup tables',
                'Enable adaptive query execution',
                'Optimize file sizes and formats (prefer Parquet/Delta)',
                'Implement proper caching strategies'
            ])
        
        return optimizations
    
    def generate_cost_report(self, days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive cost optimization report"""
        report = {
            'analysis_date': datetime.now().isoformat(),
            'period_days': days,
            'cluster_analysis': self.analyze_cluster_utilization(days),
            'job_analysis': self.analyze_job_efficiency(),
            'summary': {}
        }
        
        # Calculate summary metrics
        cluster_savings = report['cluster_analysis'].get('cost_optimization_potential', 0)
        total_clusters = report['cluster_analysis'].get('total_clusters', 0)
        inefficient_jobs = len(report['job_analysis'].get('inefficient_jobs', []))
        
        report['summary'] = {
            'potential_monthly_savings': cluster_savings,
            'clusters_needing_optimization': len(report['cluster_analysis'].get('underutilized_clusters', [])) + 
                                           len(report['cluster_analysis'].get('oversized_clusters', [])) + 
                                           len(report['cluster_analysis'].get('idle_clusters', [])),
            'total_clusters': total_clusters,
            'jobs_needing_optimization': inefficient_jobs,
            'optimization_priority': 'HIGH' if cluster_savings > 5000 else 'MEDIUM' if cluster_savings > 1000 else 'LOW'
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Databricks Cost Optimization Analyzer')
    parser.add_argument('--workspace-url', required=True, help='Databricks workspace URL')
    parser.add_argument('--token', required=True, help='Databricks access token')
    parser.add_argument('--days', type=int, default=30, help='Analysis period in days')
    parser.add_argument('--output', help='Output file for report (JSON format)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    analyzer = DatabricksCostAnalyzer(args.workspace_url, args.token)
    report = analyzer.generate_cost_report(args.days)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Cost optimization report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))
    
    # Print summary
    summary = report['summary']
    print(f"\nCost Optimization Summary:")
    print(f"Potential Monthly Savings: ${summary['potential_monthly_savings']:.2f}")
    print(f"Clusters Needing Optimization: {summary['clusters_needing_optimization']}/{summary['total_clusters']}")
    print(f"Jobs Needing Optimization: {summary['jobs_needing_optimization']}")
    print(f"Optimization Priority: {summary['optimization_priority']}")

if __name__ == '__main__':
    main()