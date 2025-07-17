# security/services/integration_service.py

import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count

from klararety import settings

from ..models import SecurityThreat, SecurityIncident, NetworkMonitor
from audit.models import AuditEvent, PHIAccessLog, SecurityAuditLog
from audit.utils import log_phi_access

User = get_user_model()
logger = logging.getLogger('security.integration')


class SecurityAuditIntegration:
    """
    Service for integrating security monitoring with audit logging.
    Ensures all security events are properly logged for compliance.
    """
    
    @staticmethod
    def log_security_event(event_type, user=None, description="", severity="medium", 
                          ip_address=None, user_agent=None, additional_data=None):
        """
        Log security event to audit system.
        
        Args:
            event_type: Type of security event
            user: User associated with event (if any)
            description: Description of the event
            severity: Severity level (low, medium, high, critical)
            ip_address: IP address associated with event
            user_agent: User agent string
            additional_data: Additional data to log
        """
        try:
            # Create audit event
            AuditEvent.objects.create(
                user=user,
                event_type=AuditEvent.EventType.ACCESS,  # Map to appropriate audit event type
                resource_type='SecurityEvent',
                resource_id='',
                description=description,
                ip_address=ip_address,
                user_agent=user_agent or '',
                additional_data=additional_data or {}
            )
            
            # Create security audit log
            SecurityAuditLog.objects.create(
                user=user,
                event_type=SecurityAuditLog.EventType.SECURITY_CHANGE,  # Map appropriately
                description=description,
                severity=severity,
                ip_address=ip_address,
                user_agent=user_agent or '',
                additional_data=additional_data or {}
            )
            
            logger.info(f"Logged security event: {event_type} for user {user}")
            
        except Exception as e:
            logger.error(f"Error logging security event: {str(e)}")
    
    @staticmethod
    def log_threat_detection(threat):
        """Log threat detection event."""
        try:
            SecurityAuditIntegration.log_security_event(
                event_type="threat_detected",
                user=threat.affected_user,
                description=f"Security threat detected: {threat.title}",
                severity=threat.severity,
                ip_address=threat.source_ip,
                additional_data={
                    'threat_id': str(threat.id),
                    'threat_type': threat.threat_type,
                    'detection_source': threat.detection_source,
                    'threat_indicators': threat.threat_indicators
                }
            )
        except Exception as e:
            logger.error(f"Error logging threat detection: {str(e)}")
    
    @staticmethod
    def log_incident_creation(incident):
        """Log security incident creation."""
        try:
            SecurityAuditIntegration.log_security_event(
                event_type="incident_created",
                user=incident.reported_by,
                description=f"Security incident created: {incident.incident_id} - {incident.title}",
                severity=incident.priority,
                additional_data={
                    'incident_id': incident.incident_id,
                    'incident_type': incident.incident_type,
                    'affected_systems': incident.affected_systems,
                    'impact_assessment': incident.impact_assessment
                }
            )
        except Exception as e:
            logger.error(f"Error logging incident creation: {str(e)}")
    
    @staticmethod
    def log_vulnerability_scan(assessment):
        """Log vulnerability scan completion."""
        try:
            SecurityAuditIntegration.log_security_event(
                event_type="vulnerability_scan",
                user=assessment.initiated_by,
                description=f"Vulnerability scan completed: {assessment.target} ({assessment.total_vulnerabilities} vulnerabilities found)",
                severity="low" if assessment.critical_count == 0 else "high",
                additional_data={
                    'assessment_id': str(assessment.id),
                    'scan_type': assessment.scan_type,
                    'target': assessment.target,
                    'total_vulnerabilities': assessment.total_vulnerabilities,
                    'critical_count': assessment.critical_count
                }
            )
        except Exception as e:
            logger.error(f"Error logging vulnerability scan: {str(e)}")
    
    @staticmethod
    def log_compliance_report_generation(report):
        """Log compliance report generation."""
        try:
            SecurityAuditIntegration.log_security_event(
                event_type="compliance_report_generated",
                user=report.generated_by,
                description=f"{report.get_report_type_display()} compliance report generated (Score: {report.compliance_score}%)",
                severity="low",
                additional_data={
                    'report_id': str(report.id),
                    'report_type': report.report_type,
                    'compliance_score': report.compliance_score,
                    'period_start': report.period_start.isoformat(),
                    'period_end': report.period_end.isoformat()
                }
            )
        except Exception as e:
            logger.error(f"Error logging compliance report generation: {str(e)}")


class SecurityMetricsCollector:
    """
    Service for collecting security metrics for reporting and analysis.
    """
    
    @staticmethod
    def collect_security_dashboard_metrics(days=30):
        """Collect comprehensive security metrics for dashboard."""
        try:
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            metrics = {
                'collection_time': end_date.isoformat(),
                'period_days': days,
                
                # Threat metrics
                'threats': {
                    'total': SecurityThreat.objects.filter(
                        detection_time__gte=start_date
                    ).count(),
                    'by_severity': dict(
                        SecurityThreat.objects.filter(
                            detection_time__gte=start_date
                        ).values_list('severity').annotate(
                            count=Count('id')
                        )
                    ),
                    'by_type': dict(
                        SecurityThreat.objects.filter(
                            detection_time__gte=start_date
                        ).values_list('threat_type').annotate(
                            count=Count('id')
                        )
                    ),
                    'active': SecurityThreat.objects.filter(
                        status__in=['detected', 'investigating']
                    ).count()
                },
                
                # Incident metrics
                'incidents': {
                    'total': SecurityIncident.objects.filter(
                        reported_at__gte=start_date
                    ).count(),
                    'by_priority': dict(
                        SecurityIncident.objects.filter(
                            reported_at__gte=start_date
                        ).values_list('priority').annotate(
                            count=Count('id')
                        )
                    ),
                    'by_type': dict(
                        SecurityIncident.objects.filter(
                            reported_at__gte=start_date
                        ).values_list('incident_type').annotate(
                            count=Count('id')
                        )
                    ),
                    'active': SecurityIncident.objects.filter(
                        status__in=['reported', 'investigating', 'containment']
                    ).count()
                },
                
                # Network metrics
                'network': {
                    'total_alerts': NetworkMonitor.objects.filter(
                        timestamp__gte=start_date,
                        is_false_positive=False
                    ).count(),
                    'by_severity': dict(
                        NetworkMonitor.objects.filter(
                            timestamp__gte=start_date,
                            is_false_positive=False
                        ).values_list('severity').annotate(
                            count=Count('id')
                        )
                    ),
                    'by_alert_type': dict(
                        NetworkMonitor.objects.filter(
                            timestamp__gte=start_date,
                            is_false_positive=False
                        ).values_list('alert_type').annotate(
                            count=Count('id')
                        )
                    )
                },
                
                # Security posture metrics
                'posture': {
                    'threat_response_time_avg': SecurityMetricsCollector._calculate_avg_response_time(),
                    'incident_resolution_rate': SecurityMetricsCollector._calculate_resolution_rate(),
                    'false_positive_rate': SecurityMetricsCollector._calculate_false_positive_rate(),
                    'vulnerability_remediation_rate': SecurityMetricsCollector._calculate_remediation_rate()
                }
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting security metrics: {str(e)}")
            return {}
    
    @staticmethod
    def _calculate_avg_response_time():
        """Calculate average threat response time in hours."""
        try:
            resolved_threats = SecurityThreat.objects.filter(
                resolved_at__isnull=False,
                detection_time__isnull=False
            )
            
            if not resolved_threats.exists():
                return 0
            
            total_time = 0
            count = 0
            
            for threat in resolved_threats:
                response_time = threat.resolved_at - threat.detection_time
                total_time += response_time.total_seconds()
                count += 1
            
            avg_seconds = total_time / count if count > 0 else 0
            return round(avg_seconds / 3600, 2)  # Convert to hours
            
        except Exception as e:
            logger.error(f"Error calculating response time: {str(e)}")
            return 0
    
    @staticmethod
    def _calculate_resolution_rate():
        """Calculate incident resolution rate percentage."""
        try:
            last_30_days = timezone.now() - timedelta(days=30)
            
            total_incidents = SecurityIncident.objects.filter(
                reported_at__gte=last_30_days
            ).count()
            
            resolved_incidents = SecurityIncident.objects.filter(
                reported_at__gte=last_30_days,
                status='closed'
            ).count()
            
            if total_incidents == 0:
                return 100  # No incidents = 100% resolution rate
            
            return round((resolved_incidents / total_incidents) * 100, 1)
            
        except Exception as e:
            logger.error(f"Error calculating resolution rate: {str(e)}")
            return 0
    
    @staticmethod
    def _calculate_false_positive_rate():
        """Calculate false positive rate for threats."""
        try:
            last_30_days = timezone.now() - timedelta(days=30)
            
            total_threats = SecurityThreat.objects.filter(
                detection_time__gte=last_30_days
            ).count()
            
            false_positives = SecurityThreat.objects.filter(
                detection_time__gte=last_30_days,
                status='false_positive'
            ).count()
            
            if total_threats == 0:
                return 0
            
            return round((false_positives / total_threats) * 100, 1)
            
        except Exception as e:
            logger.error(f"Error calculating false positive rate: {str(e)}")
            return 0
    
    @staticmethod
    def _calculate_remediation_rate():
        """Calculate vulnerability remediation rate."""
        try:
            from ..models import Vulnerability
            
            last_30_days = timezone.now() - timedelta(days=30)
            
            total_vulns = Vulnerability.objects.filter(
                first_discovered__gte=last_30_days
            ).count()
            
            fixed_vulns = Vulnerability.objects.filter(
                first_discovered__gte=last_30_days,
                status='fixed'
            ).count()
            
            if total_vulns == 0:
                return 100  # No vulnerabilities = 100% remediation rate
            
            return round((fixed_vulns / total_vulns) * 100, 1)
            
        except Exception as e:
            logger.error(f"Error calculating remediation rate: {str(e)}")
            return 0


class SecurityAlertManager:
    """
    Service for managing security alerts and notifications.
    """
    
    @staticmethod
    def send_threat_alert(threat, recipients=None):
        """Send threat alert to security team."""
        try:
            from django.core.mail import send_mail
            
            if not recipients:
                recipients = SecurityAlertManager._get_security_team_emails()
            
            if not recipients:
                logger.warning("No recipients for threat alert")
                return
            
            subject = f"SECURITY THREAT: {threat.get_severity_display().upper()} - {threat.title}"
            
            message = f"""
SECURITY THREAT DETECTED

Threat ID: {threat.id}
Severity: {threat.get_severity_display()}
Type: {threat.get_threat_type_display()}
Status: {threat.get_status_display()}

Title: {threat.title}
Description: {threat.description}

Detection Time: {threat.detection_time.strftime('%Y-%m-%d %H:%M:%S')}
Detection Source: {threat.detection_source}

{f'Source IP: {threat.source_ip}' if threat.source_ip else ''}
{f'Target IP: {threat.target_ip}' if threat.target_ip else ''}
{f'Affected User: {threat.affected_user.username}' if threat.affected_user else ''}

Please investigate immediately through the security dashboard.

This is an automated alert from Klararety Security System.
"""
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=True
            )
            
            logger.info(f"Sent threat alert for {threat.id}")
            
        except Exception as e:
            logger.error(f"Error sending threat alert: {str(e)}")
    
    @staticmethod
    def _get_security_team_emails():
        """Get security team email addresses."""
        try:
            return list(
                User.objects.filter(
                    role__in=['admin', 'security'],
                    is_active=True,
                    email__isnull=False
                ).values_list('email', flat=True)
            )
        except Exception as e:
            logger.error(f"Error getting security team emails: {str(e)}")
            return []


class SecurityComplianceExporter:
    """
    Service for exporting security data for compliance audits.
    """
    
    @staticmethod
    def export_security_audit_trail(start_date, end_date, export_format='json'):
        """Export comprehensive security audit trail."""
        try:
            audit_data = {
                'export_metadata': {
                    'generated_at': timezone.now().isoformat(),
                    'period_start': start_date.isoformat(),
                    'period_end': end_date.isoformat(),
                    'export_format': export_format
                },
                'security_events': [],
                'threat_detections': [],
                'incident_responses': [],
                'vulnerability_scans': [],
                'compliance_activities': []
            }
            
            # Export security audit logs
            security_logs = SecurityAuditLog.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            ).order_by('timestamp')
            
            for log in security_logs:
                audit_data['security_events'].append({
                    'id': str(log.id),
                    'timestamp': log.timestamp.isoformat(),
                    'event_type': log.event_type,
                    'severity': log.severity,
                    'description': log.description,
                    'user': log.user.username if log.user else None,
                    'ip_address': log.ip_address,
                    'resolved': log.resolved
                })
            
            # Export threat detections
            threats = SecurityThreat.objects.filter(
                detection_time__gte=start_date,
                detection_time__lte=end_date
            ).order_by('detection_time')
            
            for threat in threats:
                audit_data['threat_detections'].append({
                    'id': str(threat.id),
                    'detection_time': threat.detection_time.isoformat(),
                    'threat_type': threat.threat_type,
                    'severity': threat.severity,
                    'status': threat.status,
                    'title': threat.title,
                    'description': threat.description,
                    'source_ip': threat.source_ip,
                    'detection_source': threat.detection_source,
                    'resolved_at': threat.resolved_at.isoformat() if threat.resolved_at else None
                })
            
            # Export incidents
            incidents = SecurityIncident.objects.filter(
                reported_at__gte=start_date,
                reported_at__lte=end_date
            ).order_by('reported_at')
            
            for incident in incidents:
                audit_data['incident_responses'].append({
                    'incident_id': incident.incident_id,
                    'reported_at': incident.reported_at.isoformat(),
                    'incident_type': incident.incident_type,
                    'priority': incident.priority,
                    'status': incident.status,
                    'title': incident.title,
                    'impact_assessment': incident.impact_assessment,
                    'closed_at': incident.closed_at.isoformat() if incident.closed_at else None
                })
            
            return audit_data
            
        except Exception as e:
            logger.error(f"Error exporting security audit trail: {str(e)}")
            return None