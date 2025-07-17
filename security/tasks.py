# security/tasks.py
from __future__ import absolute_import, unicode_literals
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.mail import send_mail, mail_admins
from django.conf import settings
from django.contrib.auth import get_user_model
from celery import shared_task

from .models import (
    SecurityThreat, VulnerabilityAssessment, Vulnerability,
    SecurityIncident, NetworkMonitor, FileIntegrityMonitor,
    ComplianceReport
)
from .services.threat_detection import ThreatDetectionService
from .services.vulnerability_scanner import VulnerabilityScanner
from .services.compliance_reporter import ComplianceReporter
from .services.incident_response import IncidentResponseService

User = get_user_model()
logger = logging.getLogger('security.tasks')


@shared_task
def run_threat_detection_scan():
    """
    Task to run comprehensive threat detection scan.
    Runs every 30 minutes during business hours, hourly outside business hours.
    """
    logger.info("Starting threat detection scan")
    
    try:
        # Run comprehensive threat detection
        detected_threats = ThreatDetectionService.run_comprehensive_threat_scan()
        
        # Process critical threats immediately
        critical_threats = [t for t in detected_threats if t.severity == 'critical']
        
        if critical_threats:
            # Create incidents for critical threats
            for threat in critical_threats:
                try:
                    incident = IncidentResponseService.create_incident_from_threat(threat)
                    logger.info(f"Created incident {incident.incident_id} for critical threat {threat.id}")
                except Exception as e:
                    logger.error(f"Error creating incident for threat {threat.id}: {str(e)}")
        
        # Update monitoring metrics
        _update_threat_metrics(detected_threats)
        
        result = {
            'total_threats': len(detected_threats),
            'critical_threats': len(critical_threats),
            'scan_time': timezone.now().isoformat()
        }
        
        logger.info(f"Threat detection scan completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in threat detection scan: {str(e)}")
        
        # Send alert to security team
        try:
            mail_admins(
                subject="Threat Detection Scan Failed",
                message=f"The threat detection scan failed with error: {str(e)}",
                fail_silently=True
            )
        except:
            pass
        
        return {'error': str(e)}


@shared_task
def run_vulnerability_scan(assessment_id):
    """
    Task to run vulnerability scan for a specific assessment.
    """
    logger.info(f"Starting vulnerability scan for assessment {assessment_id}")
    
    try:
        scanner = VulnerabilityScanner()
        assessment = scanner.run_scan(assessment_id)
        
        # Check for critical vulnerabilities
        critical_vulns = Vulnerability.objects.filter(
            assessment=assessment,
            severity='critical'
        ).count()
        
        # Send alerts for critical vulnerabilities
        if critical_vulns > 0:
            _send_critical_vulnerability_alert(assessment, critical_vulns)
        
        result = {
            'assessment_id': str(assessment.id),
            'status': assessment.status,
            'total_vulnerabilities': assessment.total_vulnerabilities,
            'critical_vulnerabilities': critical_vulns,
            'scan_duration': assessment.duration_seconds
        }
        
        logger.info(f"Vulnerability scan completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in vulnerability scan {assessment_id}: {str(e)}")
        return {'error': str(e)}


@shared_task
def generate_security_report(report_id):
    """
    Task to generate security compliance report.
    """
    logger.info(f"Starting security report generation for {report_id}")
    
    try:
        reporter = ComplianceReporter()
        report = reporter.generate_compliance_report(report_id)
        
        # Send report to stakeholders
        _distribute_compliance_report(report)
        
        result = {
            'report_id': str(report.id),
            'report_type': report.report_type,
            'compliance_score': report.compliance_score,
            'status': report.status
        }
        
        logger.info(f"Security report generated: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error generating security report {report_id}: {str(e)}")
        return {'error': str(e)}


@shared_task
def check_system_integrity():
    """
    Task to check system integrity and file changes.
    Runs every hour.
    """
    logger.info("Starting system integrity check")
    
    try:
        # Check for unauthorized file changes
        suspicious_changes = FileIntegrityMonitor.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=1),
            is_critical_file=True,
            is_authorized_change=False
        )
        
        change_count = suspicious_changes.count()
        
        if change_count > 0:
            # Create security threat for unauthorized changes
            threat = SecurityThreat.objects.create(
                threat_type=SecurityThreat.ThreatType.SYSTEM_INTRUSION,
                severity=SecurityThreat.Severity.HIGH if change_count > 5 else SecurityThreat.Severity.MEDIUM,
                title=f"Unauthorized System File Changes Detected",
                description=f"{change_count} unauthorized changes to critical system files",
                detection_source="System Integrity Monitor",
                threat_indicators={
                    'change_count': change_count,
                    'detection_type': 'file_integrity_violation'
                }
            )
            
            logger.warning(f"Created threat {threat.id} for {change_count} unauthorized file changes")
        
        # Check system resource usage anomalies
        anomalies = _check_resource_anomalies()
        
        result = {
            'suspicious_file_changes': change_count,
            'resource_anomalies': len(anomalies),
            'check_time': timezone.now().isoformat()
        }
        
        logger.info(f"System integrity check completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in system integrity check: {str(e)}")
        return {'error': str(e)}


@shared_task
def monitor_network_traffic():
    """
    Task to monitor and analyze network traffic patterns.
    Runs every 15 minutes.
    """
    logger.info("Starting network traffic monitoring")
    
    try:
        # Get recent network alerts
        recent_alerts = NetworkMonitor.objects.filter(
            timestamp__gte=timezone.now() - timedelta(minutes=15),
            is_false_positive=False
        )
        
        alert_count = recent_alerts.count()
        
        # Check for traffic anomalies
        anomalies = _analyze_traffic_patterns(recent_alerts)
        
        # Create threats for significant anomalies
        for anomaly in anomalies:
            if anomaly['severity'] in ['high', 'critical']:
                threat = SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.SUSPICIOUS_ACTIVITY,
                    severity=SecurityThreat.Severity.HIGH if anomaly['severity'] == 'high' else SecurityThreat.Severity.CRITICAL,
                    title=f"Network Traffic Anomaly: {anomaly['type']}",
                    description=anomaly['description'],
                    source_ip=anomaly.get('source_ip'),
                    detection_source="Network Traffic Monitor",
                    threat_indicators=anomaly
                )
                
                logger.warning(f"Created threat {threat.id} for network anomaly")
        
        result = {
            'network_alerts': alert_count,
            'anomalies_detected': len(anomalies),
            'high_severity_anomalies': len([a for a in anomalies if a['severity'] in ['high', 'critical']]),
            'monitoring_time': timezone.now().isoformat()
        }
        
        logger.info(f"Network traffic monitoring completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in network traffic monitoring: {str(e)}")
        return {'error': str(e)}


@shared_task
def cleanup_old_security_data():
    """
    Task to clean up old security data based on retention policies.
    Runs weekly.
    """
    logger.info("Starting security data cleanup")
    
    try:
        # Get retention periods from settings
        threat_retention_days = getattr(settings, 'SECURITY_THREAT_RETENTION_DAYS', 365)
        incident_retention_days = getattr(settings, 'SECURITY_INCIDENT_RETENTION_DAYS', 2190)  # 6 years
        network_retention_days = getattr(settings, 'NETWORK_MONITOR_RETENTION_DAYS', 90)
        file_monitor_retention_days = getattr(settings, 'FILE_MONITOR_RETENTION_DAYS', 90)
        
        cutoff_dates = {
            'threats': timezone.now() - timedelta(days=threat_retention_days),
            'incidents': timezone.now() - timedelta(days=incident_retention_days),
            'network': timezone.now() - timedelta(days=network_retention_days),
            'files': timezone.now() - timedelta(days=file_monitor_retention_days)
        }
        
        # Clean up old data
        cleanup_counts = {}
        
        # Clean resolved threats older than retention period
        old_threats = SecurityThreat.objects.filter(
            detection_time__lt=cutoff_dates['threats'],
            status__in=['resolved', 'false_positive']
        )
        cleanup_counts['threats'] = old_threats.count()
        old_threats.delete()
        
        # Clean old network monitor data
        old_network_data = NetworkMonitor.objects.filter(
            timestamp__lt=cutoff_dates['network']
        )
        cleanup_counts['network_alerts'] = old_network_data.count()
        old_network_data.delete()
        
        # Clean old file integrity data
        old_file_data = FileIntegrityMonitor.objects.filter(
            timestamp__lt=cutoff_dates['files'],
            is_critical_file=False  # Keep critical file changes longer
        )
        cleanup_counts['file_changes'] = old_file_data.count()
        old_file_data.delete()
        
        logger.info(f"Security data cleanup completed: {cleanup_counts}")
        return cleanup_counts
        
    except Exception as e:
        logger.error(f"Error in security data cleanup: {str(e)}")
        return {'error': str(e)}


@shared_task
def security_health_check():
    """
    Task to perform security system health check.
    Runs every hour.
    """
    logger.info("Starting security health check")
    
    try:
        health_status = {
            'timestamp': timezone.now().isoformat(),
            'threat_detection': True,
            'vulnerability_scanning': True,
            'incident_response': True,
            'compliance_monitoring': True,
            'network_monitoring': True,
            'file_integrity': True,
            'overall_status': 'healthy',
            'issues': []
        }
        
        # Check threat detection system
        recent_threat_scans = SecurityThreat.objects.filter(
            detection_time__gte=timezone.now() - timedelta(hours=2)
        ).exists()
        
        if not recent_threat_scans:
            health_status['threat_detection'] = False
            health_status['issues'].append("No recent threat detection activity")
        
        # Check vulnerability scanning
        recent_vuln_scans = VulnerabilityAssessment.objects.filter(
            started_at__gte=timezone.now() - timedelta(days=7)
        ).exists()
        
        if not recent_vuln_scans:
            health_status['vulnerability_scanning'] = False
            health_status['issues'].append("No vulnerability scans in past 7 days")
        
        # Check for unresolved critical incidents
        critical_incidents = SecurityIncident.objects.filter(
            priority='critical',
            status__in=['reported', 'investigating', 'containment']
        ).count()
        
        if critical_incidents > 5:
            health_status['incident_response'] = False
            health_status['issues'].append(f"{critical_incidents} unresolved critical incidents")
        
        # Check network monitoring
        recent_network_data = NetworkMonitor.objects.filter(
            timestamp__gte=timezone.now() - timedelta(minutes=30)
        ).exists()
        
        if not recent_network_data:
            health_status['network_monitoring'] = False
            health_status['issues'].append("No recent network monitoring data")
        
        # Determine overall status
        failed_systems = [k for k, v in health_status.items() if isinstance(v, bool) and not v]
        
        if len(failed_systems) > 2:
            health_status['overall_status'] = 'critical'
        elif len(failed_systems) > 0:
            health_status['overall_status'] = 'warning'
        
        # Send alerts for degraded health
        if health_status['overall_status'] != 'healthy':
            _send_health_alert(health_status)
        
        logger.info(f"Security health check completed: {health_status['overall_status']}")
        return health_status
        
    except Exception as e:
        logger.error(f"Error in security health check: {str(e)}")
        return {'error': str(e), 'overall_status': 'critical'}


@shared_task
def generate_daily_security_summary():
    """
    Task to generate daily security summary report.
    Runs every day at 6 AM.
    """
    logger.info("Generating daily security summary")
    
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        start_time = timezone.make_aware(datetime.combine(yesterday, datetime.min.time()))
        end_time = timezone.make_aware(datetime.combine(yesterday, datetime.max.time()))
        
        # Collect daily metrics
        daily_metrics = {
            'date': yesterday.isoformat(),
            'threats_detected': SecurityThreat.objects.filter(
                detection_time__gte=start_time,
                detection_time__lte=end_time
            ).count(),
            'incidents_created': SecurityIncident.objects.filter(
                reported_at__gte=start_time,
                reported_at__lte=end_time
            ).count(),
            'vulnerabilities_found': Vulnerability.objects.filter(
                first_discovered__gte=start_time,
                first_discovered__lte=end_time
            ).count(),
            'network_alerts': NetworkMonitor.objects.filter(
                timestamp__gte=start_time,
                timestamp__lte=end_time,
                is_false_positive=False
            ).count(),
            'critical_events': SecurityThreat.objects.filter(
                detection_time__gte=start_time,
                detection_time__lte=end_time,
                severity='critical'
            ).count()
        }
        
        # Send summary to security team
        _send_daily_summary(daily_metrics)
        
        logger.info(f"Daily security summary generated: {daily_metrics}")
        return daily_metrics
        
    except Exception as e:
        logger.error(f"Error generating daily security summary: {str(e)}")
        return {'error': str(e)}


# Helper functions

def _update_threat_metrics(detected_threats):
    """Update threat detection metrics."""
    try:
        # This would update metrics in a monitoring system
        # For now, just log the metrics
        threat_counts = {}
        for threat in detected_threats:
            threat_type = threat.threat_type
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        logger.info(f"Threat metrics updated: {threat_counts}")
        
    except Exception as e:
        logger.error(f"Error updating threat metrics: {str(e)}")


def _send_critical_vulnerability_alert(assessment, critical_count):
    """Send alert for critical vulnerabilities."""
    try:
        # Get security team emails
        security_emails = User.objects.filter(
            role__in=['admin', 'security'],
            is_active=True,
            email__isnull=False
        ).values_list('email', flat=True)
        
        if not security_emails:
            return
        
        subject = f"CRITICAL VULNERABILITIES DETECTED: {critical_count} found"
        message = f"""
CRITICAL SECURITY VULNERABILITIES DETECTED

Assessment: {assessment.target}
Scan Type: {assessment.get_scan_type_display()}
Completed: {assessment.completed_at.strftime('%Y-%m-%d %H:%M:%S')}

CRITICAL VULNERABILITIES: {critical_count}
Total Vulnerabilities: {assessment.total_vulnerabilities}

Please review the vulnerability assessment immediately and prioritize remediation.

Access the security dashboard for detailed vulnerability information.

This is an automated alert from Klararety Security System.
"""
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=list(security_emails),
            fail_silently=True
        )
        
    except Exception as e:
        logger.error(f"Error sending critical vulnerability alert: {str(e)}")


def _distribute_compliance_report(report):
    """Distribute compliance report to stakeholders."""
    try:
        # Get compliance team emails
        compliance_emails = User.objects.filter(
            role='compliance',
            is_active=True,
            email__isnull=False
        ).values_list('email', flat=True)
        
        # Add management emails for certain report types
        if report.report_type in ['hipaa', 'soc2']:
            management_emails = getattr(settings, 'COMPLIANCE_MANAGEMENT_EMAILS', [])
            compliance_emails = list(compliance_emails) + management_emails
        
        if not compliance_emails:
            return
        
        subject = f"{report.get_report_type_display()} Compliance Report - {report.compliance_score}%"
        message = f"""
{report.get_report_type_display().upper()} COMPLIANCE REPORT GENERATED

Report Period: {report.period_start.strftime('%Y-%m-%d')} to {report.period_end.strftime('%Y-%m-%d')}
Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}

COMPLIANCE SCORE: {report.compliance_score}%

Total Controls: {report.total_controls}
Passed Controls: {report.passed_controls}
Failed Controls: {report.failed_controls}

{'🟢 COMPLIANT' if report.compliance_score >= 90 else '🟡 NEEDS ATTENTION' if report.compliance_score >= 70 else '🔴 NON-COMPLIANT'}

The detailed report is available in the compliance dashboard.

This is an automated notification from Klararety Security System.
"""
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=list(set(compliance_emails)),
            fail_silently=True
        )
        
    except Exception as e:
        logger.error(f"Error distributing compliance report: {str(e)}")


def _check_resource_anomalies():
    """Check for system resource anomalies."""
    anomalies = []
    
    try:
        # This would integrate with system monitoring tools
        # For now, return simulated anomalies
        import random
        
        if random.random() < 0.1:  # 10% chance of anomaly
            anomalies.append({
                'type': 'high_cpu_usage',
                'description': 'Unusual CPU usage pattern detected',
                'severity': 'medium'
            })
        
    except Exception as e:
        logger.error(f"Error checking resource anomalies: {str(e)}")
    
    return anomalies


def _analyze_traffic_patterns(network_alerts):
    """Analyze network traffic patterns for anomalies."""
    anomalies = []
    
    try:
        # Group alerts by source IP
        ip_counts = {}
        for alert in network_alerts:
            ip = alert.source_ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Check for high-volume sources
        for ip, count in ip_counts.items():
            if count > 20:  # More than 20 alerts in 15 minutes
                anomalies.append({
                    'type': 'high_volume_traffic',
                    'description': f'High volume of alerts from IP {ip}: {count} alerts in 15 minutes',
                    'severity': 'high' if count > 50 else 'medium',
                    'source_ip': ip,
                    'alert_count': count
                })
        
    except Exception as e:
        logger.error(f"Error analyzing traffic patterns: {str(e)}")
    
    return anomalies


def _send_health_alert(health_status):
    """Send security system health alert."""
    try:
        admin_emails = User.objects.filter(
            role='admin',
            is_active=True,
            email__isnull=False
        ).values_list('email', flat=True)
        
        if not admin_emails:
            return
        
        subject = f"SECURITY SYSTEM HEALTH: {health_status['overall_status'].upper()}"
        message = f"""
SECURITY SYSTEM HEALTH ALERT

Overall Status: {health_status['overall_status'].upper()}
Check Time: {health_status['timestamp']}

System Status:
- Threat Detection: {'✓' if health_status['threat_detection'] else '✗'}
- Vulnerability Scanning: {'✓' if health_status['vulnerability_scanning'] else '✗'}
- Incident Response: {'✓' if health_status['incident_response'] else '✗'}
- Network Monitoring: {'✓' if health_status['network_monitoring'] else '✗'}

Issues Detected:
{chr(10).join(['- ' + issue for issue in health_status['issues']]) if health_status['issues'] else '- None'}

Please investigate and resolve any system issues immediately.

This is an automated alert from Klararety Security System.
"""
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=list(admin_emails),
            fail_silently=True
        )
        
    except Exception as e:
        logger.error(f"Error sending health alert: {str(e)}")


def _send_daily_summary(metrics):
    """Send daily security summary."""
    try:
        # Get security team emails
        security_emails = User.objects.filter(
            role__in=['admin', 'security', 'compliance'],
            is_active=True,
            email__isnull=False
        ).values_list('email', flat=True)
        
        if not security_emails:
            return
        
        subject = f"Daily Security Summary - {metrics['date']}"
        
        # Calculate status indicator
        if metrics['critical_events'] > 0:
            status_indicator = "🔴 HIGH ALERT"
        elif metrics['threats_detected'] > 10 or metrics['incidents_created'] > 0:
            status_indicator = "🟡 ATTENTION REQUIRED"
        else:
            status_indicator = "🟢 NORMAL"
        
        message = f"""
DAILY SECURITY SUMMARY

Date: {metrics['date']}
Status: {status_indicator}

SECURITY METRICS:
- Threats Detected: {metrics['threats_detected']}
- Critical Events: {metrics['critical_events']}
- Security Incidents: {metrics['incidents_created']}
- Vulnerabilities Found: {metrics['vulnerabilities_found']}
- Network Alerts: {metrics['network_alerts']}

{f"⚠️  {metrics['critical_events']} critical security events require immediate attention!" if metrics['critical_events'] > 0 else ""}

Access the security dashboard for detailed information and response coordination.

This is an automated summary from Klararety Security System.
"""
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=list(security_emails),
            fail_silently=True
        )
        
    except Exception as e:
        logger.error(f"Error sending daily summary: {str(e)}")
