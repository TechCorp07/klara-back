"""
Security automation tools for Klararety platform.
Implements scheduled security scanning and CI/CD integration.
"""
import os
import logging
import json
from datetime import datetime, timedelta
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from celery import shared_task
from security.scanner import SecurityScanner

logger = logging.getLogger('security')

class SecurityAutomation:
    """
    Automates security scanning and reporting processes.
    Integrates with CI/CD pipelines and provides scheduled scanning.
    """
    
    def __init__(self, notification_emails=None, output_dir=None):
        """
        Initialize the security automation.
        
        Args:
            notification_emails (list, optional): List of email addresses to notify
            output_dir (str, optional): Directory to store scan results
        """
        self.notification_emails = notification_emails or getattr(settings, 'SECURITY_NOTIFICATION_EMAILS', [])
        self.output_dir = output_dir or os.path.join(settings.BASE_DIR, 'security_scans')
        self.scanner = SecurityScanner(output_dir=self.output_dir)
        self.threshold_critical = getattr(settings, 'SECURITY_THRESHOLD_CRITICAL', 0)
        self.threshold_high = getattr(settings, 'SECURITY_THRESHOLD_HIGH', 3)
        self.threshold_medium = getattr(settings, 'SECURITY_THRESHOLD_MEDIUM', 10)
        
    def run_scheduled_scan(self):
        """
        Run a scheduled security scan.
        
        Returns:
            dict: Scan results
        """
        logger.info("Starting scheduled security scan")
        
        # Run full scan
        results = self.scanner.run_full_scan()
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = os.path.join(self.output_dir, f"scheduled_scan_{timestamp}.json")
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        # Check thresholds and send notifications
        self._process_scan_results(results, results_file, scan_type="scheduled")
        
        return results
    
    def run_ci_scan(self, commit_hash=None, branch=None):
        """
        Run a security scan as part of CI/CD pipeline.
        
        Args:
            commit_hash (str, optional): Git commit hash
            branch (str, optional): Git branch name
            
        Returns:
            dict: Scan results and CI/CD status
        """
        logger.info(f"Starting CI/CD security scan for commit {commit_hash} on branch {branch}")
        
        # Run dependency and code scans only for CI
        results = {}
        results['dependency_scan'] = self.scanner.run_dependency_scan()
        results['code_scan'] = self.scanner.run_code_scan()
        
        # Generate summary
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        
        for scan_type, result in results.items():
            if result.get('status') == 'warning':
                if 'critical' in result.get('message', '').lower():
                    critical_issues += 1
                elif 'high' in result.get('message', '').lower():
                    high_issues += 1
                else:
                    medium_issues += 1
        
        # Determine CI/CD status
        ci_status = 'success'
        ci_message = "Security scan passed"
        
        if critical_issues > self.threshold_critical:
            ci_status = 'failed'
            ci_message = f"Security scan failed: {critical_issues} critical issues found (threshold: {self.threshold_critical})"
        elif high_issues > self.threshold_high:
            ci_status = 'failed'
            ci_message = f"Security scan failed: {high_issues} high issues found (threshold: {self.threshold_high})"
        elif medium_issues > self.threshold_medium:
            ci_status = 'warning'
            ci_message = f"Security scan warning: {medium_issues} medium issues found (threshold: {self.threshold_medium})"
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = os.path.join(self.output_dir, f"ci_scan_{timestamp}.json")
        
        full_results = {
            'status': ci_status,
            'message': ci_message,
            'results': results,
            'commit_hash': commit_hash,
            'branch': branch,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(results_file, 'w') as f:
            json.dump(full_results, f, indent=2)
            
        # Check thresholds and send notifications
        self._process_scan_results(full_results, results_file, scan_type="ci")
        
        return full_results
    
    def run_pre_deployment_scan(self, environment, version=None):
        """
        Run a comprehensive security scan before deployment.
        
        Args:
            environment (str): Target environment (e.g., 'staging', 'production')
            version (str, optional): Version being deployed
            
        Returns:
            dict: Scan results and deployment recommendation
        """
        logger.info(f"Starting pre-deployment security scan for {environment} environment, version {version}")
        
        # Run full scan
        results = self.scanner.run_full_scan()
        
        # Determine deployment recommendation
        deploy_status = 'proceed'
        deploy_message = "Deployment can proceed"
        
        # Extract issue counts
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        
        for scan_type, result in results.get('results', {}).items():
            if result.get('status') == 'warning':
                if 'critical' in result.get('message', '').lower():
                    critical_issues += 1
                elif 'high' in result.get('message', '').lower():
                    high_issues += 1
                else:
                    medium_issues += 1
        
        # Apply stricter thresholds for production
        if environment == 'production':
            if critical_issues > 0:
                deploy_status = 'block'
                deploy_message = f"Deployment blocked: {critical_issues} critical issues found"
            elif high_issues > 0:
                deploy_status = 'warning'
                deploy_message = f"Deployment warning: {high_issues} high issues found"
        else:
            if critical_issues > 0:
                deploy_status = 'warning'
                deploy_message = f"Deployment warning: {critical_issues} critical issues found"
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = os.path.join(self.output_dir, f"pre_deployment_scan_{environment}_{timestamp}.json")
        
        full_results = {
            'status': deploy_status,
            'message': deploy_message,
            'results': results,
            'environment': environment,
            'version': version,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(results_file, 'w') as f:
            json.dump(full_results, f, indent=2)
            
        # Check thresholds and send notifications
        self._process_scan_results(full_results, results_file, scan_type="pre-deployment")
        
        return full_results
    
    def _process_scan_results(self, results, results_file, scan_type="scheduled"):
        """
        Process scan results, check thresholds, and send notifications.
        
        Args:
            results (dict): Scan results
            results_file (str): Path to results file
            scan_type (str): Type of scan (scheduled, ci, pre-deployment)
        """
        # Extract status
        status = results.get('status')
        message = results.get('message')
        
        # Log results
        if status in ['critical', 'high', 'failed', 'block']:
            logger.error(f"{scan_type.capitalize()} security scan {status}: {message}")
        elif status in ['medium', 'warning']:
            logger.warning(f"{scan_type.capitalize()} security scan {status}: {message}")
        else:
            logger.info(f"{scan_type.capitalize()} security scan {status}: {message}")
        
        # Send notifications if needed
        if status in ['critical', 'high', 'failed', 'block'] and self.notification_emails:
            self._send_notification(results, results_file, scan_type)
    
    def _send_notification(self, results, results_file, scan_type):
        """
        Send email notification about security scan results.
        
        Args:
            results (dict): Scan results
            results_file (str): Path to results file
            scan_type (str): Type of scan
        """
        status = results.get('status')
        message = results.get('message')
        
        subject = f"[SECURITY] {scan_type.capitalize()} security scan {status}"
        
        # Build email body
        body = f"""
Security Scan Alert

Type: {scan_type.capitalize()} scan
Status: {status}
Message: {message}
Timestamp: {results.get('timestamp')}

Results file: {results_file}

"""
        
        # Add details for different scan types
        if scan_type == "ci":
            body += f"""
Commit: {results.get('commit_hash')}
Branch: {results.get('branch')}
"""
        elif scan_type == "pre-deployment":
            body += f"""
Environment: {results.get('environment')}
Version: {results.get('version')}
"""
        
        # Add scan details
        body += "\nScan Details:\n"
        for scan_name, scan_result in results.get('results', {}).items():
            body += f"\n{scan_name}: {scan_result.get('status')}"
            body += f"\n{scan_result.get('message')}\n"
        
        # Send email
        try:
            send_mail(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,
                self.notification_emails,
                fail_silently=False,
            )
            logger.info(f"Security notification sent to {', '.join(self.notification_emails)}")
        except Exception as e:
            logger.error(f"Failed to send security notification: {e}")


@shared_task
def run_scheduled_security_scan():
    """
    Celery task to run scheduled security scan.
    """
    automation = SecurityAutomation()
    return automation.run_scheduled_scan()


@shared_task
def run_ci_security_scan(commit_hash=None, branch=None):
    """
    Celery task to run CI/CD security scan.
    """
    automation = SecurityAutomation()
    return automation.run_ci_scan(commit_hash, branch)


@shared_task
def run_pre_deployment_security_scan(environment, version=None):
    """
    Celery task to run pre-deployment security scan.
    """
    automation = SecurityAutomation()
    return automation.run_pre_deployment_scan(environment, version)
