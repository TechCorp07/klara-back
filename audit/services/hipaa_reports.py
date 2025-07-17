import logging
import csv
import io
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.db.models import Count, Q
from ..models import (
    AuditEvent, 
    PHIAccessLog, 
    SecurityAuditLog, 
    ComplianceReport
)

logger = logging.getLogger(__name__)


class HIPAAReportService:
    """Service for generating HIPAA compliance reports."""
    
    @staticmethod
    def schedule_report(report_type, report_date=None, generated_by=None, parameters=None):
        from ..tasks import generate_compliance_report
        """
        Schedule a HIPAA compliance report for generation.
        
        Args:
            report_type: Type of report to generate
            report_date: Date for the report (defaults to today)
            generated_by: User who requested the report
            parameters: Additional parameters for the report
            
        Returns:
            ComplianceReport: The created report object
        """
        if report_date is None:
            report_date = timezone.now().date()
            
        if parameters is None:
            parameters = {}
            
        # Create the report record
        report = ComplianceReport.objects.create(
            report_type=report_type,
            report_date=report_date,
            generated_by=generated_by,
            parameters=parameters,
            status=ComplianceReport.Status.PENDING
        )
        
        # Schedule the report generation task
        generate_compliance_report.delay(str(report.id))
        
        return report
    
    @staticmethod
    def get_report(report_id):
        """
        Get a report by ID.
        
        Args:
            report_id: The ID of the report
            
        Returns:
            ComplianceReport: The report object or None if not found
        """
        try:
            return ComplianceReport.objects.get(id=report_id)
        except ComplianceReport.DoesNotExist:
            return None
    
    @staticmethod
    def generate_phi_access_summary(start_date=None, end_date=None):
        """
        Generate a summary of PHI access.
        
        Args:
            start_date: Start date for the summary (defaults to 30 days ago)
            end_date: End date for the summary (defaults to today)
            
        Returns:
            dict: Summary statistics
        """
        if end_date is None:
            end_date = timezone.now().date()
            
        if start_date is None:
            start_date = end_date - timedelta(days=30)
            
        start_datetime = datetime.combine(start_date, datetime.min.time())
        end_datetime = datetime.combine(end_date, datetime.max.time())
        
        # Get PHI access logs in the date range
        phi_logs = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Calculate summary statistics
        total_accesses = phi_logs.count()
        access_by_type = phi_logs.values('access_type').annotate(count=Count('id'))
        access_by_user_role = {}
        
        # Group by user role
        for log in phi_logs:
            if log.user and hasattr(log.user, 'role'):
                role = log.user.role
                access_by_user_role[role] = access_by_user_role.get(role, 0) + 1
                
        # Calculate accesses without proper reason
        missing_reason = phi_logs.filter(Q(reason='') | Q(reason__isnull=True)).count()
        
        return {
            'total_accesses': total_accesses,
            'access_by_type': {item['access_type']: item['count'] for item in access_by_type},
            'access_by_user_role': access_by_user_role,
            'missing_reason': missing_reason,
            'start_date': start_date,
            'end_date': end_date
        }
    
    @staticmethod
    def generate_security_incident_summary(start_date=None, end_date=None):
        """
        Generate a summary of security incidents.
        
        Args:
            start_date: Start date for the summary (defaults to 30 days ago)
            end_date: End date for the summary (defaults to today)
            
        Returns:
            dict: Summary statistics
        """
        if end_date is None:
            end_date = timezone.now().date()
            
        if start_date is None:
            start_date = end_date - timedelta(days=30)
            
        start_datetime = datetime.combine(start_date, datetime.min.time())
        end_datetime = datetime.combine(end_date, datetime.max.time())
        
        # Get security logs in the date range
        security_logs = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Calculate summary statistics
        total_incidents = security_logs.count()
        incidents_by_type = security_logs.values('event_type').annotate(count=Count('id'))
        incidents_by_severity = security_logs.values('severity').annotate(count=Count('id'))
        unresolved_incidents = security_logs.filter(resolved=False).count()
        
        # Calculate critical unresolved incidents
        critical_unresolved = security_logs.filter(
            resolved=False, 
            severity=SecurityAuditLog.Severity.CRITICAL
        ).count()
        
        # Calculate time to resolution
        resolution_times = []
        for log in security_logs.filter(resolved=True, resolved_at__isnull=False):
            resolution_time = (log.resolved_at - log.timestamp).total_seconds() / 3600  # hours
            resolution_times.append(resolution_time)
            
        avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0
        
        return {
            'total_incidents': total_incidents,
            'incidents_by_type': {item['event_type']: item['count'] for item in incidents_by_type},
            'incidents_by_severity': {item['severity']: item['count'] for item in incidents_by_severity},
            'unresolved_incidents': unresolved_incidents,
            'critical_unresolved': critical_unresolved,
            'avg_resolution_time_hours': avg_resolution_time,
            'start_date': start_date,
            'end_date': end_date
        }
    
    @staticmethod
    def generate_compliance_dashboard_data():
        """
        Generate data for a HIPAA compliance dashboard.
        
        Returns:
            dict: Dashboard data
        """
        today = timezone.now().date()
        thirty_days_ago = today - timedelta(days=30)
        ninety_days_ago = today - timedelta(days=90)
        
        # Get PHI access summary for last 30 days
        phi_summary_30 = HIPAAReportService.generate_phi_access_summary(
            start_date=thirty_days_ago,
            end_date=today
        )
        
        # Get security incident summary for last 30 days
        security_summary_30 = HIPAAReportService.generate_security_incident_summary(
            start_date=thirty_days_ago,
            end_date=today
        )
        
        # Get unresolved security incidents
        unresolved_security = SecurityAuditLog.objects.filter(resolved=False)
        critical_security = unresolved_security.filter(severity=SecurityAuditLog.Severity.CRITICAL)
        
        # Calculate audit event statistics
        total_events_30 = AuditEvent.objects.filter(
            timestamp__gte=datetime.combine(thirty_days_ago, datetime.min.time()),
            timestamp__lte=datetime.combine(today, datetime.max.time())
        ).count()
        
        total_events_90 = AuditEvent.objects.filter(
            timestamp__gte=datetime.combine(ninety_days_ago, datetime.min.time()),
            timestamp__lte=datetime.combine(today, datetime.max.time())
        ).count()
        
        # Get recent compliance reports
        recent_reports = ComplianceReport.objects.filter(
            report_date__gte=thirty_days_ago
        ).order_by('-report_date')[:5]
        
        return {
            'phi_access_summary': phi_summary_30,
            'security_incident_summary': security_summary_30,
            'unresolved_security_count': unresolved_security.count(),
            'critical_security_count': critical_security.count(),
            'audit_events_30_days': total_events_30,
            'audit_events_90_days': total_events_90,
            'recent_reports': [
                {
                    'id': str(report.id),
                    'report_type': report.get_report_type_display(),
                    'report_date': report.report_date,
                    'status': report.get_status_display(),
                    'file_url': report.file_url
                }
                for report in recent_reports
            ]
        }

class HIPAAComplianceReporter:
    """
    Enhanced HIPAA compliance reporting service with comprehensive report types
    and compliance metrics specifically tailored for healthcare platforms.
    """
    
    @staticmethod
    def generate_patient_access_report(patient_id, start_date=None, end_date=None):
        """
        Generate a report of all PHI access events for a specific patient.
        
        Args:
            patient_id: ID of the patient
            start_date: Start date for report period
            end_date: End date for report period
            
        Returns:
            dict: Report data
        """
        from django.utils import timezone
        from django.db.models import Count, Q
        from audit.models import PHIAccessLog
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        
        # Set default date range if not provided
        if end_date is None:
            end_date = timezone.now().date()
        if start_date is None:
            start_date = end_date - timezone.timedelta(days=30)
        
        # Convert to datetime for database query
        start_datetime = timezone.datetime.combine(start_date, timezone.datetime.min.time())
        end_datetime = timezone.datetime.combine(end_date, timezone.datetime.max.time())
        
        # Get patient user
        try:
            patient = User.objects.get(id=patient_id)
        except User.DoesNotExist:
            return {
                'error': f"Patient with ID {patient_id} not found",
                'status': 'error'
            }
        
        # Get access logs for this patient
        access_logs = PHIAccessLog.objects.filter(
            patient=patient,
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Summarize access data
        total_accesses = access_logs.count()
        access_by_type = access_logs.values('access_type').annotate(count=Count('id'))
        access_by_user = access_logs.values('user__username', 'user__role').annotate(count=Count('id'))
        access_by_record_type = access_logs.values('record_type').annotate(count=Count('id'))
        
        # Trend of access over time (grouped by day)
        from django.db.models.functions import TruncDay
        access_trend = access_logs.annotate(
            day=TruncDay('timestamp')
        ).values('day').annotate(count=Count('id')).order_by('day')
        
        # Format for return
        return {
            'patient_id': patient_id,
            'patient_name': patient.get_full_name(),
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'total_accesses': total_accesses,
            'access_by_type': {item['access_type']: item['count'] for item in access_by_type},
            'access_by_user': [
                {
                    'username': item['user__username'], 
                    'role': item['user__role'],
                    'count': item['count']
                } 
                for item in access_by_user
            ],
            'access_by_record_type': {item['record_type']: item['count'] for item in access_by_record_type},
            'access_trend': [
                {
                    'date': item['day'].strftime('%Y-%m-%d'),
                    'count': item['count']
                }
                for item in access_trend
            ],
            'status': 'success'
        }
    
    @staticmethod
    def generate_minimum_necessary_report(start_date=None, end_date=None):
        """
        Generate a report to assess compliance with HIPAA's minimum necessary rule.
        Identifies potential excessive PHI access patterns.
        
        Args:
            start_date: Start date for report period
            end_date: End date for report period
            
        Returns:
            dict: Report data highlighting potential minimum necessary violations
        """
        from django.utils import timezone
        from django.db.models import Count, Q, F
        from audit.models import PHIAccessLog
        
        # Set default date range if not provided
        if end_date is None:
            end_date = timezone.now().date()
        if start_date is None:
            start_date = end_date - timezone.timedelta(days=30)
        
        # Convert to datetime for database query
        start_datetime = timezone.datetime.combine(start_date, timezone.datetime.min.time())
        end_datetime = timezone.datetime.combine(end_date, timezone.datetime.max.time())
        
        # Get all access logs for the period
        access_logs = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Identify users with unusually high access counts
        user_access_counts = access_logs.values('user').annotate(count=Count('id'))
        total_users = user_access_counts.count()
        if total_users == 0:
            avg_access_count = 0
        else:
            total_accesses = sum(item['count'] for item in user_access_counts)
            avg_access_count = total_accesses / total_users
        
        # Users with access counts 2x the average
        high_volume_users = user_access_counts.filter(count__gt=avg_access_count * 2)
        
        # Users accessing patient records outside their normal patient list
        from django.contrib.auth import get_user_model
        User = get_user_model()
        providers = User.objects.filter(role='provider')
        
        unusual_access_patterns = []
        for provider in providers:
            # Get provider's typical patients (from medical records or appointments)
            from healthcare.models import MedicalRecord
            from telemedicine.models import Appointment
            
            typical_patients = set()
            
            # Add patients from medical records where provider is primary
            for record in MedicalRecord.objects.filter(primary_physician=provider):
                typical_patients.add(record.patient_id)
                
            # Add patients from appointments
            for appt in Appointment.objects.filter(provider=provider):
                typical_patients.add(appt.patient_id)
            
            # Find accesses to patients outside this list
            unusual_accesses = access_logs.filter(
                user=provider
            ).exclude(
                patient_id__in=typical_patients
            )
            
            if unusual_accesses.exists():
                unusual_patients = unusual_accesses.values('patient').distinct().count()
                unusual_access_patterns.append({
                    'provider_id': provider.id,
                    'provider_name': provider.get_full_name(),
                    'unusual_access_count': unusual_accesses.count(),
                    'unusual_patients_count': unusual_patients
                })
        
        # Identify users accessing multiple patients in rapid succession
        from django.db.models.functions import Extract
        
        # Group access logs by user and hour
        rapid_access_patterns = access_logs.annotate(
            hour=Extract('timestamp', 'hour'),
            day=Extract('timestamp', 'day'),
            month=Extract('timestamp', 'month'),
            year=Extract('timestamp', 'year')
        ).values(
            'user', 'hour', 'day', 'month', 'year'
        ).annotate(
            access_count=Count('id'),
            patient_count=Count('patient', distinct=True)
        ).filter(
            patient_count__gt=10  # More than 10 different patients in an hour
        )
        
        return {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'total_access_logs': access_logs.count(),
            'average_access_per_user': avg_access_count,
            'high_volume_users': [
                {
                    'user_id': item['user'],
                    'access_count': item['count'],
                    'times_above_average': item['count'] / avg_access_count if avg_access_count > 0 else 0
                }
                for item in high_volume_users
            ],
            'unusual_access_patterns': unusual_access_patterns,
            'rapid_access_patterns': [
                {
                    'user_id': item['user'],
                    'datetime': f"{item['year']}-{item['month']}-{item['day']} {item['hour']}:00",
                    'access_count': item['access_count'],
                    'unique_patients': item['patient_count']
                }
                for item in rapid_access_patterns
            ],
            'status': 'success'
        }
    
    @staticmethod
    def generate_data_sharing_report(start_date=None, end_date=None):
        """
        Generate a report of PHI data sharing activities.
        
        Args:
            start_date: Start date for report period
            end_date: End date for report period
            
        Returns:
            dict: Report data on PHI sharing
        """
        from django.utils import timezone
        from django.db.models import Count, Q
        from audit.models import PHIAccessLog, AuditEvent
        
        # Set default date range if not provided
        if end_date is None:
            end_date = timezone.now().date()
        if start_date is None:
            start_date = end_date - timezone.timedelta(days=30)
        
        # Convert to datetime for database query
        start_datetime = timezone.datetime.combine(start_date, timezone.datetime.min.time())
        end_datetime = timezone.datetime.combine(end_date, timezone.datetime.max.time())
        
        # Get all PHI sharing events
        phi_sharing = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            access_type=PHIAccessLog.AccessType.SHARE
        )
        
        # Other export events
        export_events = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            access_type=PHIAccessLog.AccessType.EXPORT
        )
        
        # Get sharing events from general audit log
        export_audit_events = AuditEvent.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            event_type=AuditEvent.EventType.EXPORT
        )
        
        # Analyze results
        sharing_by_user = phi_sharing.values('user__username', 'user__role').annotate(count=Count('id'))
        sharing_by_record_type = phi_sharing.values('record_type').annotate(count=Count('id'))
        
        return {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'phi_sharing_events': phi_sharing.count(),
            'phi_export_events': export_events.count(),
            'total_export_events': export_audit_events.count(),
            'sharing_by_user': [
                {
                    'username': item['user__username'],
                    'role': item['user__role'],
                    'count': item['count']
                }
                for item in sharing_by_user
            ],
            'sharing_by_record_type': {
                item['record_type']: item['count'] for item in sharing_by_record_type
            },
            'status': 'success'
        }
    
    @staticmethod
    def generate_security_risk_assessment():
        """
        Generate a security risk assessment report based on audit logs.
        
        Returns:
            dict: Security risk assessment data
        """
        from django.utils import timezone
        from django.db.models import Count, Q
        from audit.models import SecurityAuditLog
        
        # Time periods for analysis
        now = timezone.now()
        last_30_days = now - timezone.timedelta(days=30)
        last_90_days = now - timezone.timedelta(days=90)
        
        # Get security incidents
        recent_incidents = SecurityAuditLog.objects.filter(timestamp__gte=last_30_days)
        
        # Break down by severity
        severity_counts = recent_incidents.values('severity').annotate(count=Count('id'))
        
        # Break down by event type
        event_type_counts = recent_incidents.values('event_type').annotate(count=Count('id'))
        
        # Unresolved critical incidents
        unresolved_critical = SecurityAuditLog.objects.filter(
            resolved=False,
            severity=SecurityAuditLog.Severity.CRITICAL
        )
        
        # Incident trends over time
        from django.db.models.functions import TruncWeek
        incident_trend = SecurityAuditLog.objects.filter(
            timestamp__gte=last_90_days
        ).annotate(
            week=TruncWeek('timestamp')
        ).values('week').annotate(count=Count('id')).order_by('week')
        
        # Failed login attempts
        failed_logins = SecurityAuditLog.objects.filter(
            timestamp__gte=last_30_days,
            event_type=SecurityAuditLog.EventType.LOGIN_FAILED
        )
        
        # Get a count of repeat offenders (users with multiple failed logins)
        repeat_login_failures = failed_logins.values('additional_data__username').annotate(
            count=Count('id')
        ).filter(count__gt=3)
        
        # Suspicious access patterns
        suspicious_access = SecurityAuditLog.objects.filter(
            timestamp__gte=last_30_days,
            event_type=SecurityAuditLog.EventType.SUSPICIOUS_ACCESS
        )
        
        # Permission violations
        permission_violations = SecurityAuditLog.objects.filter(
            timestamp__gte=last_30_days,
            event_type=SecurityAuditLog.EventType.PERMISSION_VIOLATION
        )
        
        # Calculate risk score
        risk_factors = {
            'has_unresolved_critical': unresolved_critical.exists(),
            'high_severity_count': sum(item['count'] for item in severity_counts if item['severity'] in ['high', 'critical']),
            'suspicious_access_count': suspicious_access.count(),
            'permission_violations_count': permission_violations.count(),
            'repeat_login_failures': repeat_login_failures.count()
        }
        
        # Simple risk score calculation
        risk_score = 0
        if risk_factors['has_unresolved_critical']:
            risk_score += 30
        risk_score += min(risk_factors['high_severity_count'] * 5, 30)
        risk_score += min(risk_factors['suspicious_access_count'] * 2, 20)
        risk_score += min(risk_factors['permission_violations_count'] * 3, 15)
        risk_score += min(risk_factors['repeat_login_failures'] * 1, 5)
        
        risk_level = 'Low'
        if risk_score > 70:
            risk_level = 'Critical'
        elif risk_score > 50:
            risk_level = 'High'
        elif risk_score > 30:
            risk_level = 'Medium'
        
        return {
            'assessment_date': now.date().isoformat(),
            'overall_risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recent_incidents_count': recent_incidents.count(),
            'unresolved_critical_count': unresolved_critical.count(),
            'severity_breakdown': {
                item['severity']: item['count'] for item in severity_counts
            },
            'event_type_breakdown': {
                item['event_type']: item['count'] for item in event_type_counts
            },
            'incident_trend': [
                {
                    'week': item['week'].strftime('%Y-%m-%d'),
                    'count': item['count']
                }
                for item in incident_trend
            ],
            'failed_logins_count': failed_logins.count(),
            'repeat_login_failures_count': repeat_login_failures.count(),
            'suspicious_access_count': suspicious_access.count(),
            'permission_violations_count': permission_violations.count(),
            'status': 'success'
        }
    
    @staticmethod
    def generate_hipaa_dashboard_metrics():
        """
        Generate key metrics for a HIPAA compliance dashboard.
        
        Returns:
            dict: Dashboard metrics
        """
        from django.utils import timezone
        from django.db.models import Count, Q
        from audit.models import PHIAccessLog, SecurityAuditLog, AuditEvent
        
        # Time periods
        now = timezone.now()
        today = now.date()
        yesterday = today - timezone.timedelta(days=1)
        last_7_days = now - timezone.timedelta(days=7)
        last_30_days = now - timezone.timedelta(days=30)
        
        # Access metrics
        total_phi_access_30d = PHIAccessLog.objects.filter(timestamp__gte=last_30_days).count()
        total_phi_access_7d = PHIAccessLog.objects.filter(timestamp__gte=last_7_days).count()
        
        # Compare periods for trend
        total_phi_access_prev_30d = PHIAccessLog.objects.filter(
            timestamp__lt=last_30_days,
            timestamp__gte=last_30_days - timezone.timedelta(days=30)
        ).count()
        
        phi_access_trend = total_phi_access_30d - total_phi_access_prev_30d
        
        # PHI access without reason
        phi_access_no_reason = PHIAccessLog.objects.filter(
            Q(reason='') | Q(reason='No reason provided'),
            timestamp__gte=last_30_days,
        ).count()
        
        # Security incidents
        security_incidents_30d = SecurityAuditLog.objects.filter(timestamp__gte=last_30_days).count()
        security_incidents_7d = SecurityAuditLog.objects.filter(timestamp__gte=last_7_days).count()
        
        # Calculate incident trend
        security_incidents_prev_30d = SecurityAuditLog.objects.filter(
            timestamp__lt=last_30_days,
            timestamp__gte=last_30_days - timezone.timedelta(days=30)
        ).count()
        
        security_trend = security_incidents_30d - security_incidents_prev_30d
        
        # Get active unresolved critical incidents
        unresolved_critical = SecurityAuditLog.objects.filter(
            resolved=False,
            severity=SecurityAuditLog.Severity.CRITICAL
        ).count()
        
        # Failed login attempts today
        failed_logins_today = SecurityAuditLog.objects.filter(
            timestamp__gte=timezone.datetime.combine(today, timezone.datetime.min.time()),
            event_type=SecurityAuditLog.EventType.LOGIN_FAILED
        ).count()
        
        # User activity metrics
        active_users_today = AuditEvent.objects.filter(
            timestamp__gte=timezone.datetime.combine(today, timezone.datetime.min.time())
        ).values('user').distinct().count()
        
        active_users_yesterday = AuditEvent.objects.filter(
            timestamp__gte=timezone.datetime.combine(yesterday, timezone.datetime.min.time()),
            timestamp__lt=timezone.datetime.combine(today, timezone.datetime.min.time())
        ).values('user').distinct().count()
        
        return {
            'timestamp': now.isoformat(),
            'phi_access': {
                'last_30_days': total_phi_access_30d,
                'last_7_days': total_phi_access_7d,
                'trend': phi_access_trend,
                'trend_percentage': (phi_access_trend / total_phi_access_prev_30d * 100) if total_phi_access_prev_30d > 0 else 0,
                'without_reason_count': phi_access_no_reason,
                'without_reason_percentage': (phi_access_no_reason / total_phi_access_30d * 100) if total_phi_access_30d > 0 else 0
            },
            'security': {
                'incidents_30d': security_incidents_30d,
                'incidents_7d': security_incidents_7d,
                'trend': security_trend,
                'trend_percentage': (security_trend / security_incidents_prev_30d * 100) if security_incidents_prev_30d > 0 else 0,
                'unresolved_critical': unresolved_critical,
                'failed_logins_today': failed_logins_today
            },
            'user_activity': {
                'active_users_today': active_users_today,
                'active_users_yesterday': active_users_yesterday,
                'change': active_users_today - active_users_yesterday
            },
            'status': 'success'
        }
