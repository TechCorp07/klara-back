from __future__ import absolute_import, unicode_literals
import io
import csv
import json
import logging
from datetime import datetime, timedelta
from statistics import mean, stdev
from django.utils import timezone
from django.db.models import Count, Q, F
from django.core.mail import send_mail, mail_admins
from django.conf import settings
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from celery import shared_task

from .models import (
    AuditEvent, PHIAccessLog, SecurityAuditLog, 
    ComplianceReport, AuditExport
)
from .services.security_alerts import SecurityAlertService
from .services.export_service import ExportService

logger = logging.getLogger(__name__)
User = get_user_model()

@shared_task
def monitor_suspicious_access_patterns():
    """
    Task to monitor for suspicious access patterns and generate security alerts.
    
    This task runs regular checks for unusual access patterns that might
    indicate security concerns such as unauthorized access or data snooping.
    """
    logger.info("Starting suspicious access pattern check")
    
    try:
        # Call the security alert service to detect suspicious activity
        alerts = SecurityAlertService.detect_suspicious_activity()
        
        logger.info(f"Suspicious access pattern check completed: {len(alerts)} alerts generated")
        return f"Monitoring completed successfully. {len(alerts)} alerts generated."
        
    except Exception as e:
        logger.error(f"Error in suspicious access pattern check: {str(e)}")
        return f"Error in monitoring: {str(e)}"


@shared_task
def generate_audit_export(export_id):
    """
    Task to generate an audit export asynchronously.
    
    Args:
        export_id: ID of the AuditExport to generate
    """
    logger.info(f"Starting audit export generation: {export_id}")
    
    try:
        export = AuditExport.objects.get(id=export_id)
        
        # Determine export type from filters
        export_type = export.filters.get('export_type', 'events')
        
        if export_type == 'phi':
            result = ExportService.generate_phi_access_export(export)
        elif export_type == 'security':
            result = ExportService.generate_security_audit_export(export)
        else:
            result = ExportService.generate_audit_export(export)
            
        if result:
            logger.info(f"Export completed successfully: {export_id}")
            return f"Export {export_id} completed successfully"
        else:
            logger.error(f"Export failed: {export_id}")
            return f"Export {export_id} failed"
            
    except AuditExport.DoesNotExist:
        logger.error(f"Export not found: {export_id}")
        return f"Export {export_id} not found"
    except Exception as e:
        logger.error(f"Error generating export {export_id}: {str(e)}")
        return f"Error generating export {export_id}: {str(e)}"


@shared_task
def generate_daily_compliance_report():
    """
    Task to generate a daily HIPAA compliance report.
    
    This task summarizes the previous day's compliance-related activities
    and sends a report to compliance officers.
    """
    logger.info("Starting daily compliance report generation")
    
    try:
        now = timezone.now()
        report_date = now.date() - timedelta(days=1)  # Report for yesterday
        
        # Create the report record
        report = ComplianceReport.objects.create(
            report_type=ComplianceReport.ReportType.DAILY_AUDIT,
            report_date=report_date,
            status=ComplianceReport.Status.PROCESSING,
            parameters={
                'start_date': report_date.isoformat(),
                'end_date': report_date.isoformat(),
                'report_name': f"Daily HIPAA Compliance Report {report_date.isoformat()}"
            }
        )
        
        # Time window for report
        start_datetime = datetime.combine(report_date, datetime.min.time())
        end_datetime = datetime.combine(report_date, datetime.max.time())
        
        # Get statistics for the day
        phi_access_count = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        security_events_count = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        audit_events_count = AuditEvent.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        # PHI access without reason - HIPAA compliance issue
        no_reason_count = PHIAccessLog.objects.filter(
            Q(reason='') | Q(reason='No reason provided'),
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        # High severity security events
        high_severity_count = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            severity__in=[SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]
        ).count()
        
        # Access by user role
        access_by_role = {}
        for role_choice in User._meta.get_field('role').choices:
            role = role_choice[0]
            count = PHIAccessLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime,
                user__role=role
            ).count()
            access_by_role[role] = count
        
        # Generate summary for report
        summary = {
            'date': report_date.isoformat(),
            'phi_access_count': phi_access_count,
            'security_events_count': security_events_count,
            'audit_events_count': audit_events_count,
            'missing_reason_count': no_reason_count,
            'missing_reason_percentage': (no_reason_count / phi_access_count * 100) if phi_access_count > 0 else 0,
            'high_severity_count': high_severity_count,
            'access_by_role': access_by_role
        }
        
        # Generate CSV file
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        
        # Write header and summary
        writer.writerow(['Daily HIPAA Compliance Report'])
        writer.writerow([f"Date: {report_date.isoformat()}"])
        writer.writerow([])
        
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Total PHI Access Events', phi_access_count])
        writer.writerow(['Total Security Events', security_events_count])
        writer.writerow(['Total Audit Events', audit_events_count])
        writer.writerow(['PHI Access without Reason', no_reason_count])
        writer.writerow(['High Severity Security Events', high_severity_count])
        writer.writerow([])
        
        # Write access by role
        writer.writerow(['PHI Access by Role'])
        for role, count in access_by_role.items():
            writer.writerow([role, count])
        writer.writerow([])
        
        # Write recent high severity security events
        writer.writerow(['Recent High Severity Security Events'])
        writer.writerow(['Timestamp', 'Event Type', 'Severity', 'Description', 'Resolved'])
        
        high_severity_events = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            severity__in=[SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]
        ).order_by('-timestamp')
        
        for event in high_severity_events:
            writer.writerow([
                event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                event.get_event_type_display(),
                event.get_severity_display(),
                event.description,
                'Yes' if event.resolved else 'No'
            ])
        
        # Save the CSV to storage
        filename = f"daily_compliance_report_{report_date.isoformat()}.csv"
        file_path = f"compliance_reports/{filename}"
        
        default_storage.save(file_path, ContentFile(csv_buffer.getvalue().encode('utf-8')))
        
        # Set the file URL and update report
        if hasattr(settings, 'MEDIA_URL'):
            file_url = f"{settings.MEDIA_URL}{file_path}"
        else:
            file_url = file_path
            
        report.file_url = file_url
        report.status = ComplianceReport.Status.COMPLETED
        report.notes = f"Daily compliance report for {report_date.isoformat()}"
        report.save()
        
        # Send email to compliance officers
        compliance_emails = getattr(settings, 'COMPLIANCE_OFFICER_EMAILS', [])
        if compliance_emails:
            try:
                # Format email with report summary
                context = {
                    'summary': summary,
                    'report': report,
                    'app_name': getattr(settings, 'APP_NAME', 'Klararety Health'),
                    'dashboard_url': getattr(settings, 'COMPLIANCE_DASHBOARD_URL', ''),
                    'report_type': 'Daily Compliance Report',
                    'report_date': report_date.isoformat(),
                    'status': report.get_status_display(),
                    'generated_by': 'System',
                    'file_url': file_url,
                    'recipient_name': 'Compliance Officer'
                }
                
                # Render email content from templates
                html_message = render_to_string('audit/email/compliance_report.html', context)
                text_message = render_to_string('audit/email/compliance_report.txt', context)
                
                send_mail(
                    subject=f"Daily HIPAA Compliance Report {report_date.isoformat()}",
                    message=text_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=compliance_emails,
                    html_message=html_message,
                    fail_silently=True
                )
            except Exception as e:
                logger.error(f"Error sending compliance report email: {str(e)}")
        
        logger.info(f"Daily compliance report generated successfully")
        return "Daily compliance report generated successfully"
        
    except Exception as e:
        logger.error(f"Error generating daily compliance report: {str(e)}")
        return f"Error generating report: {str(e)}"


@shared_task
def generate_weekly_compliance_report():
    """
    Task to generate a weekly HIPAA compliance report.
    
    This task generates a comprehensive weekly report on HIPAA compliance
    metrics and sends it to compliance officers.
    """
    logger.info("Starting weekly compliance report generation")
    
    try:
        now = timezone.now()
        report_date = now.date()
        
        # Define time window - last 7 days
        end_date = report_date - timedelta(days=1)  # Yesterday
        start_date = end_date - timedelta(days=6)   # 7 days total
        
        # Generate report record
        report = ComplianceReport.objects.create(
            report_type=ComplianceReport.ReportType.WEEKLY_AUDIT,
            report_date=report_date,
            status=ComplianceReport.Status.PROCESSING,
            parameters={
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'report_name': f"Weekly HIPAA Compliance Report {start_date.isoformat()} to {end_date.isoformat()}"
            }
        )
        
        # Convert to datetime for database queries
        start_datetime = datetime.combine(start_date, datetime.min.time())
        end_datetime = datetime.combine(end_date, datetime.max.time())
        
        # Get statistics for report period
        phi_access_count = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        security_events_count = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        audit_events_count = AuditEvent.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        # PHI access without reason
        no_reason_count = PHIAccessLog.objects.filter(
            Q(reason='') | Q(reason='No reason provided'),
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        ).count()
        
        # High severity security events
        high_severity_count = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            severity__in=[SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]
        ).count()
        
        # Break down events by type
        security_by_type = {}
        for event_type, _ in SecurityAuditLog.EventType.choices:
            count = SecurityAuditLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime,
                event_type=event_type
            ).count()
            if count > 0:
                security_by_type[event_type] = count
            
        # Access by user role
        access_by_role = {}
        for role_choice in User._meta.get_field('role').choices:
            role = role_choice[0]
            count = PHIAccessLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime,
                user__role=role
            ).count()
            if count > 0:
                access_by_role[role] = count
        
        # Generate summary information for report
        summary = {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'phi_access_count': phi_access_count,
            'security_events_count': security_events_count,
            'audit_events_count': audit_events_count,
            'missing_reason_count': no_reason_count,
            'missing_reason_percentage': (no_reason_count / phi_access_count * 100) if phi_access_count > 0 else 0,
            'high_severity_count': high_severity_count,
            'security_by_type': security_by_type,
            'access_by_role': access_by_role
        }
        
        # Generate CSV content
        # Create CSV file in memory
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        
        # Write header
        writer.writerow(['Weekly HIPAA Compliance Report'])
        writer.writerow([f"Period: {start_date.isoformat()} to {end_date.isoformat()}"])
        writer.writerow([])
        
        # Write summary statistics
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Total PHI Access Events', phi_access_count])
        writer.writerow(['Total Security Events', security_events_count])
        writer.writerow(['Total Audit Events', audit_events_count])
        writer.writerow(['PHI Access without Reason', no_reason_count])
        writer.writerow(['High Severity Security Events', high_severity_count])
        writer.writerow([])
        
        # Write security events by type
        writer.writerow(['Security Events by Type'])
        for event_type, count in security_by_type.items():
            # Get display name for event type
            display_name = dict(SecurityAuditLog.EventType.choices).get(event_type, event_type)
            writer.writerow([display_name, count])
        writer.writerow([])
        
        # Write PHI access by role
        writer.writerow(['PHI Access by Role'])
        for role, count in access_by_role.items():
            # Get display name for role
            display_name = dict(User._meta.get_field('role').choices).get(role, role)
            writer.writerow([display_name, count])
        writer.writerow([])
        
        # Security events details
        writer.writerow(['Recent High Severity Security Events'])
        writer.writerow(['Timestamp', 'Event Type', 'Severity', 'User', 'Description'])
        
        high_severity_events = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime,
            severity__in=[SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]
        ).order_by('-timestamp')[:25]  # Limit to 25 most recent
        
        for event in high_severity_events:
            writer.writerow([
                event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                event.get_event_type_display(),
                event.get_severity_display(),
                event.user.username if event.user else 'Anonymous',
                event.description
            ])
        
        # Save the CSV to storage
        filename = f"weekly_compliance_report_{start_date.isoformat()}_{end_date.isoformat()}.csv"
        file_path = f"compliance_reports/{filename}"
        
        default_storage.save(file_path, ContentFile(csv_buffer.getvalue().encode('utf-8')))
        
        # Set the file URL
        if hasattr(settings, 'MEDIA_URL'):
            file_url = f"{settings.MEDIA_URL}{file_path}"
        else:
            file_url = file_path
            
        # Update report with results
        report.file_url = file_url
        report.status = ComplianceReport.Status.COMPLETED
        report.notes = f"Weekly compliance report for {start_date.isoformat()} to {end_date.isoformat()}"
        report.save()
        
        # Send email notification to compliance officers
        compliance_emails = getattr(settings, 'COMPLIANCE_OFFICER_EMAILS', [])
        if compliance_emails:
            try:
                # Format email with report highlights
                context = {
                    'summary': summary,
                    'report': report,
                    'app_name': getattr(settings, 'APP_NAME', 'Klararety Health'),
                    'dashboard_url': getattr(settings, 'COMPLIANCE_DASHBOARD_URL', ''),
                    'report_type': 'Weekly Compliance Report',
                    'report_date': f"{start_date.isoformat()} to {end_date.isoformat()}",
                    'status': report.get_status_display(),
                    'generated_by': 'System',
                    'file_url': file_url,
                    'recipient_name': 'Compliance Officer'
                }
                
                # Render email content from templates
                html_message = render_to_string('audit/email/compliance_report.html', context)
                text_message = render_to_string('audit/email/compliance_report.txt', context)
                
                send_mail(
                    subject=f"Weekly HIPAA Compliance Report {end_date.isoformat()}",
                    message=text_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=compliance_emails,
                    html_message=html_message,
                    fail_silently=True
                )
            except Exception as e:
                logger.error(f"Error sending compliance report email: {str(e)}")
        
        logger.info(f"Weekly compliance report generated successfully")
        return "Weekly compliance report generated successfully"
        
    except Exception as e:
        logger.error(f"Error generating weekly compliance report: {str(e)}")
        
        # Try to update report status if it was created
        if 'report' in locals():
            report.status = ComplianceReport.Status.FAILED
            report.notes = f"Error generating report: {str(e)}"
            report.save()
            
        return f"Error generating report: {str(e)}"


@shared_task
def check_expired_compliance_reports():
    """
    Task to identify reports that are due for renewal.
    
    This task finds compliance reports that need to be renewed
    according to regulatory requirements and sends notifications.
    """
    logger.info("Starting compliance report expiration check")
    
    try:
        now = timezone.now()
        
        # Calculate expiration thresholds - reports older than regulatory requirements
        # HIPAA typically requires annual assessments
        annual_threshold = now.date() - timedelta(days=365)
        quarterly_threshold = now.date() - timedelta(days=90)
        
        # Find reports that need renewal
        expired_reports = ComplianceReport.objects.filter(
            Q(report_date__lt=annual_threshold, report_type__in=[
                ComplianceReport.ReportType.SECURITY_INCIDENTS,
                ComplianceReport.ReportType.SYSTEM_ACCESS
            ]) | 
            Q(report_date__lt=quarterly_threshold, report_type__in=[
                ComplianceReport.ReportType.USER_ACTIVITY
            ])
        )
        
        # Group by report type
        expired_by_type = {}
        for report in expired_reports:
            if report.report_type not in expired_by_type:
                expired_by_type[report.report_type] = []
            expired_by_type[report.report_type].append(report)
        
        # If no expired reports, we're done
        if not expired_reports.exists():
            logger.info("No compliance reports due for renewal")
            return "No reports due for renewal"
        
        # Send notification email
        compliance_emails = getattr(settings, 'COMPLIANCE_OFFICER_EMAILS', [])
        if compliance_emails:
            try:
                message = "The following compliance reports are due for renewal:\n\n"
                html_message = "<p>The following compliance reports are due for renewal:</p><ul>"
                
                for report_type, reports in expired_by_type.items():
                    report_type_display = dict(ComplianceReport.ReportType.choices).get(report_type, report_type)
                    message += f"\n{report_type_display} Reports:\n"
                    html_message += f"<li><strong>{report_type_display} Reports:</strong><ul>"
                    
                    for report in reports:
                        days_expired = (now.date() - report.report_date).days
                        message += f"- Report from {report.report_date.isoformat()}, expired by {days_expired} days\n"
                        html_message += f"<li>Report from {report.report_date.isoformat()}, expired by {days_expired} days</li>"
                    
                    html_message += "</ul></li>"
                
                html_message += "</ul>"
                html_message += "<p>Please generate new compliance reports to maintain HIPAA compliance.</p>"
                
                send_mail(
                    subject="HIPAA Compliance Reports Due for Renewal",
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=compliance_emails,
                    html_message=html_message,
                    fail_silently=True
                )
            except Exception as e:
                logger.error(f"Error sending report expiration email: {str(e)}")
        
        return f"Found {expired_reports.count()} reports due for renewal"
        
    except Exception as e:
        logger.error(f"Error checking for expired compliance reports: {str(e)}")
        return f"Error checking expired reports: {str(e)}"


@shared_task
def cleanup_old_audit_exports():
    """
    Task to clean up old audit exports that are no longer needed.
    
    Deletes export files and records older than the retention period.
    """
    logger.info("Starting cleanup of old audit exports")
    
    try:
        # Get retention period from settings
        retention_days = getattr(settings, 'AUDIT_EXPORT_RETENTION_DAYS', 90)
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        # Find old exports
        old_exports = AuditExport.objects.filter(
            created_at__lt=cutoff_date,
            status=AuditExport.Status.COMPLETED  # Only delete completed exports
        )
        
        deleted_count = 0
        for export in old_exports:
            # Delete file if it exists
            if export.file_url:
                try:
                    # Extract file path from URL
                    url_path = export.file_url
                    if hasattr(settings, 'MEDIA_URL') and settings.MEDIA_URL in url_path:
                        file_path = url_path.replace(settings.MEDIA_URL, '')
                    else:
                        file_path = url_path
                        
                    # Delete file if it exists
                    if default_storage.exists(file_path):
                        default_storage.delete(file_path)
                        logger.info(f"Deleted export file: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting export file {export.file_url}: {str(e)}")
            
            # Delete export record
            export.delete()
            deleted_count += 1
        
        logger.info(f"Deleted {deleted_count} old audit exports")
        return f"Deleted {deleted_count} old audit exports"
        
    except Exception as e:
        logger.error(f"Error cleaning up old audit exports: {str(e)}")
        return f"Error cleaning up old audit exports: {str(e)}"


@shared_task
def verify_audit_integrity():
    """
    Task to verify the integrity of audit logs.
    
    Checks for:
    - Missing records in sequential time periods
    - Unexpected gaps in timestamps
    - Unusual patterns in log volume
    - Modified timestamps or data tampering
    
    This is essential for HIPAA compliance to ensure audit logs are complete and accurate.
    """
    logger.info("Starting audit integrity verification")
    
    try:
        issues = []
        
        # Check for timestamp gaps in audit events
        issues.extend(_check_timestamp_gaps(AuditEvent, 'Audit Events'))
        issues.extend(_check_timestamp_gaps(PHIAccessLog, 'PHI Access Logs'))
        issues.extend(_check_timestamp_gaps(SecurityAuditLog, 'Security Logs'))
        
        # Check for unusual volume changes
        issues.extend(_check_volume_anomalies(AuditEvent, 'Audit Events'))
        issues.extend(_check_volume_anomalies(PHIAccessLog, 'PHI Access Logs'))
        issues.extend(_check_volume_anomalies(SecurityAuditLog, 'Security Logs'))
        
        # Report any integrity issues
        if issues:
            _report_integrity_issues(issues)
            return f"Audit integrity verification completed with {len(issues)} issues found"
        
        logger.info("Audit integrity verification completed successfully - no issues found")
        return "Audit integrity verification completed successfully - no issues found"
        
    except Exception as e:
        logger.error(f"Error during audit integrity verification: {str(e)}")
        
        # Send alert about the failure
        subject = "ALERT: Audit Integrity Verification Failed"
        message = f"""
        The audit integrity verification process failed with the following error:
        
        {str(e)}
        
        This could indicate a problem with the audit logging system that requires immediate attention.
        """
        
        try:
            mail_admins(
                subject=subject,
                message=message,
                fail_silently=True
            )
        except Exception as mail_err:
            logger.error(f"Failed to send admin email about integrity verification failure: {str(mail_err)}")
            
        return f"Error in audit integrity verification: {str(e)}"


@shared_task
def generate_compliance_report(report_id):
    from .services.hipaa_reports import HIPAAComplianceReporter
    """
    Task to generate a compliance report from the queue.
    
    Args:
        report_id: ID of the ComplianceReport to generate
    """
    logger.info(f"Starting compliance report generation: {report_id}")
    
    try:
        report = ComplianceReport.objects.get(id=report_id)
        report.status = ComplianceReport.Status.PROCESSING
        report.save(update_fields=['status'])
        
        # Generate report based on type
        if report.report_type == ComplianceReport.ReportType.DAILY_AUDIT:
            report_date = report.report_date
            start_date = end_date = report_date
        elif report.report_type == ComplianceReport.ReportType.WEEKLY_AUDIT:
            report_date = report.report_date
            end_date = report_date - timedelta(days=1)  # Yesterday
            start_date = end_date - timedelta(days=6)   # 7 days total
        else:
            # Get dates from parameters
            params = report.parameters or {}
            start_date = params.get('start_date')
            end_date = params.get('end_date')
            
            if start_date:
                start_date = datetime.fromisoformat(start_date).date()
            else:
                start_date = report.report_date - timedelta(days=30)
                
            if end_date:
                end_date = datetime.fromisoformat(end_date).date()
            else:
                end_date = report.report_date
        
        # Check report type and generate appropriate report
        if report.report_type == ComplianceReport.ReportType.PHI_ACCESS:
            # Generate PHI access report
            report_data = HIPAAComplianceReporter.generate_phi_access_summary(start_date, end_date)
            filename = f"phi_access_report_{start_date.isoformat()}_{end_date.isoformat()}.csv"
            
            # Generate CSV
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            
            writer.writerow(['PHI Access Report'])
            writer.writerow([f"Period: {start_date.isoformat()} to {end_date.isoformat()}"])
            writer.writerow([])
            
            writer.writerow(['Total PHI Accesses', report_data['total_accesses']])
            writer.writerow([])
            
            writer.writerow(['Access by Type'])
            for access_type, count in report_data['access_by_type'].items():
                writer.writerow([access_type, count])
            writer.writerow([])
            
            writer.writerow(['Access by User Role'])
            for role, count in report_data['access_by_user_role'].items():
                writer.writerow([role, count])
            writer.writerow([])
            
            writer.writerow(['Access Without Reason', report_data['missing_reason']])
            writer.writerow([])
            
        elif report.report_type == ComplianceReport.ReportType.SECURITY_INCIDENTS:
            # Generate security incidents report
            report_data = HIPAAComplianceReporter.generate_security_incident_summary(start_date, end_date)
            filename = f"security_incidents_report_{start_date.isoformat()}_{end_date.isoformat()}.json"
            
            # Generate JSON file
            json_content = json.dumps(report_data, indent=2)
            
        elif report.report_type == ComplianceReport.ReportType.USER_ACTIVITY:
            # For user activity reports, we need a specific user
            params = report.parameters or {}
            username = params.get('username')
            
            if not username:
                report.status = ComplianceReport.Status.FAILED
                report.notes = "Username parameter is required for user activity reports"
                report.save(update_fields=['status', 'notes'])
                return f"Failed to generate report {report_id}: Missing username parameter"
                
            # Get user
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                report.status = ComplianceReport.Status.FAILED
                report.notes = f"User '{username}' not found"
                report.save(update_fields=['status', 'notes'])
                return f"Failed to generate report {report_id}: User not found"
                
            # Generate user activity report
            from .management.commands.audit_admin import Command
            command = Command()
            output = io.StringIO()
            command.stdout = output
            command.analyze_user({'username': username, 'days': (end_date - start_date).days})
            
            report_text = output.getvalue()
            filename = f"user_activity_{username}_{start_date.isoformat()}_{end_date.isoformat()}.txt"
            
            # Save as text file
            file_path = f"compliance_reports/{filename}"
            default_storage.save(file_path, ContentFile(report_text.encode('utf-8')))
            
            # Set file URL
            if hasattr(settings, 'MEDIA_URL'):
                file_url = f"{settings.MEDIA_URL}{file_path}"
            else:
                file_url = file_path
                
            # Update report status
            report.status = ComplianceReport.Status.COMPLETED
            report.file_url = file_url
            report.notes = f"User activity report for {username} from {start_date.isoformat()} to {end_date.isoformat()}"
            report.save()
            
            return f"Generated user activity report for {username}"
            
        elif report.report_type == ComplianceReport.ReportType.SYSTEM_ACCESS:
            # System access report - uses security audit logs
            # Generate CSV
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            
            writer.writerow(['System Access Audit Report'])
            writer.writerow([f"Period: {start_date.isoformat()} to {end_date.isoformat()}"])
            writer.writerow([])
            
            # Convert to datetime for database queries
            start_datetime = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
            
            # Login statistics
            login_events = AuditEvent.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime,
                event_type=AuditEvent.EventType.LOGIN
            )
            
            login_count = login_events.count()
            
            # Failed login attempts
            failed_logins = SecurityAuditLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime,
                event_type=SecurityAuditLog.EventType.LOGIN_FAILED
            )
            
            failed_count = failed_logins.count()
            
            # Access by role
            writer.writerow(['System Access Summary'])
            writer.writerow(['Successful Logins', login_count])
            writer.writerow(['Failed Login Attempts', failed_count])
            writer.writerow([])
            
            # Login by user role
            login_by_role = {}
            for role_choice in User._meta.get_field('role').choices:
                role = role_choice[0]
                role_display = role_choice[1]
                count = login_events.filter(user__role=role).count()
                login_by_role[role_display] = count
            
            writer.writerow(['Logins by User Role'])
            for role, count in login_by_role.items():
                writer.writerow([role, count])
            writer.writerow([])
            
            # Top users by login count
            writer.writerow(['Top 10 Users by Login Count'])
            writer.writerow(['Username', 'Role', 'Login Count'])
            
            top_users = (
                login_events
                .values('user__username', 'user__role')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            )
            
            for user in top_users:
                username = user['user__username']
                role = dict(User._meta.get_field('role').choices).get(user['user__role'], user['user__role'])
                count = user['count']
                writer.writerow([username, role, count])
            
            writer.writerow([])
            
            # Login attempt details
            writer.writerow(['Recent Failed Login Attempts'])
            writer.writerow(['Timestamp', 'IP Address', 'Username'])
            
            recent_failures = failed_logins.order_by('-timestamp')[:25]
            for failure in recent_failures:
                username = (failure.additional_data or {}).get('username', 'Unknown')
                writer.writerow([
                    failure.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    failure.ip_address or 'Unknown',
                    username
                ])
                
            filename = f"system_access_report_{start_date.isoformat()}_{end_date.isoformat()}.csv"
            
        elif report.report_type == ComplianceReport.ReportType.DAILY_AUDIT:
            # Daily audit - process separately
            generate_daily_compliance_report.delay()
            return f"Started daily compliance report generation for {report_date}"
            
        elif report.report_type == ComplianceReport.ReportType.WEEKLY_AUDIT:
            # Weekly audit - process separately
            generate_weekly_compliance_report.delay()
            return f"Started weekly compliance report generation for period ending {report_date}"
            
        else:
            # Custom report
            # Default to a combined report with summary statistics
            # Build a general summary CSV
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            
            writer.writerow(['HIPAA Compliance Summary Report'])
            writer.writerow([f"Period: {start_date.isoformat()} to {end_date.isoformat()}"])
            writer.writerow([])
            
            # Convert to datetime for database queries
            start_datetime = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
            
            # Get statistics
            phi_access_count = PHIAccessLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime
            ).count()
            
            security_events_count = SecurityAuditLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime
            ).count()
            
            audit_events_count = AuditEvent.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime
            ).count()
            
            # PHI access without reason
            no_reason_count = PHIAccessLog.objects.filter(
                Q(reason='') | Q(reason='No reason provided'),
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime
            ).count()
            
            # High severity security events
            high_severity_count = SecurityAuditLog.objects.filter(
                timestamp__gte=start_datetime,
                timestamp__lte=end_datetime,
                severity__in=[SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]
            ).count()
            
            # Write summary statistics
            writer.writerow(['Summary Statistics'])
            writer.writerow(['Total PHI Access Events', phi_access_count])
            writer.writerow(['Total Security Events', security_events_count])
            writer.writerow(['Total Audit Events', audit_events_count])
            writer.writerow(['PHI Access without Reason', no_reason_count])
            writer.writerow(['High Severity Security Events', high_severity_count])
            writer.writerow([])
            
            # Add any custom sections from parameters
            params = report.parameters or {}
            custom_sections = params.get('custom_sections', [])
            
            for section in custom_sections:
                if 'title' in section and 'content' in section:
                    writer.writerow([section['title']])
                    if isinstance(section['content'], list):
                        for item in section['content']:
                            writer.writerow([item])
                    else:
                        writer.writerow([section['content']])
                    writer.writerow([])
                    
            filename = f"custom_report_{start_date.isoformat()}_{end_date.isoformat()}.csv"
            
        # Save the report file
        file_path = f"compliance_reports/{filename}"
        
        if report.report_type == ComplianceReport.ReportType.SECURITY_INCIDENTS:
            # JSON file
            default_storage.save(file_path, ContentFile(json_content.encode('utf-8')))
        else:
            # CSV file
            default_storage.save(file_path, ContentFile(csv_buffer.getvalue().encode('utf-8')))
        
        # Set the file URL
        if hasattr(settings, 'MEDIA_URL'):
            file_url = f"{settings.MEDIA_URL}{file_path}"
        else:
            file_url = file_path
            
        # Update report status
        report.status = ComplianceReport.Status.COMPLETED
        report.file_url = file_url
        report.notes = f"Compliance report for {start_date.isoformat()} to {end_date.isoformat()}"
        report.save()
        
        # Notify the user who generated the report if appropriate
        if report.generated_by and report.generated_by.email:
            try:
                context = {
                    'report': report,
                    'app_name': getattr(settings, 'APP_NAME', 'Klararety Health'),
                    'dashboard_url': getattr(settings, 'COMPLIANCE_DASHBOARD_URL', ''),
                    'report_type': report.get_report_type_display(),
                    'report_date': f"{start_date.isoformat()} to {end_date.isoformat()}",
                    'status': report.get_status_display(),
                    'generated_by': report.generated_by.get_full_name() or report.generated_by.username,
                    'file_url': file_url,
                    'recipient_name': report.generated_by.get_full_name() or report.generated_by.username
                }
                
                # Render email content from templates
                html_message = render_to_string('audit/email/compliance_report.html', context)
                text_message = render_to_string('audit/email/compliance_report.txt', context)
                
                send_mail(
                    subject=f"{report.get_report_type_display()} Report Completed",
                    message=text_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[report.generated_by.email],
                    html_message=html_message,
                    fail_silently=True
                )
            except Exception as e:
                logger.error(f"Error sending report notification email: {str(e)}")
        
        return f"Successfully generated {report.get_report_type_display()} report (ID: {report.id})"
        
    except ComplianceReport.DoesNotExist:
        logger.error(f"Report not found: {report_id}")
        return f"Report {report_id} not found"
    except Exception as e:
        logger.error(f"Error generating compliance report {report_id}: {str(e)}")
        
        try:
            # Update report status
            report = ComplianceReport.objects.get(id=report_id)
            report.status = ComplianceReport.Status.FAILED
            report.notes = f"Error: {str(e)}"
            report.save(update_fields=['status', 'notes'])
        except Exception:
            pass
            
        return f"Error generating compliance report {report_id}: {str(e)}"


@shared_task
def cleanup_old_audit_records():
    """
    Task to clean up old audit records according to retention policy.
    
    This maintains the HIPAA-compliant retention period while preventing
    excessive database growth.
    """
    logger.info("Starting cleanup of old audit records")
    
    try:
        # Get retention periods from settings (default to 6 years for HIPAA compliance)
        audit_retention_days = getattr(settings, 'AUDIT_EVENT_RETENTION_DAYS', 2190)  # 6 years
        phi_retention_days = getattr(settings, 'PHI_ACCESS_LOG_RETENTION_DAYS', 2190)  # 6 years
        security_retention_days = getattr(settings, 'SECURITY_LOG_RETENTION_DAYS', 2190)  # 6 years
        
        # Calculate cutoff dates
        audit_cutoff_date = timezone.now() - timedelta(days=audit_retention_days)
        phi_cutoff_date = timezone.now() - timedelta(days=phi_retention_days)
        security_cutoff_date = timezone.now() - timedelta(days=security_retention_days)
        
        # Delete old records in batches to avoid locking the database for too long
        batch_size = 1000
        
        # Clean up old audit events
        audit_count = 0
        while True:
            batch = AuditEvent.objects.filter(timestamp__lt=audit_cutoff_date)[:batch_size]
            batch_count = batch.count()
            if batch_count == 0:
                break
                
            batch.delete()
            audit_count += batch_count
            
        # Clean up old PHI access logs
        phi_count = 0
        while True:
            batch = PHIAccessLog.objects.filter(timestamp__lt=phi_cutoff_date)[:batch_size]
            batch_count = batch.count()
            if batch_count == 0:
                break
                
            batch.delete()
            phi_count += batch_count
            
        # Clean up old security logs
        security_count = 0
        while True:
            batch = SecurityAuditLog.objects.filter(timestamp__lt=security_cutoff_date)[:batch_size]
            batch_count = batch.count()
            if batch_count == 0:
                break
                
            batch.delete()
            security_count += batch_count
            
        total_count = audit_count + phi_count + security_count
        logger.info(f"Deleted {total_count} old audit records: {audit_count} audit events, "
                   f"{phi_count} PHI access logs, {security_count} security logs")
        
        return f"Deleted {total_count} old audit records"
        
    except Exception as e:
        logger.error(f"Error cleaning up old audit records: {str(e)}")
        return f"Error cleaning up old audit records: {str(e)}"


def _check_timestamp_gaps(model_class, model_name):
    """
    Check for suspicious gaps in timestamps that could indicate missing records.
    
    Args:
        model_class: The model class to check
        model_name: Display name of the model for reporting
        
    Returns:
        list: Detected issues
    """
    issues = []
    
    # Get historical daily volume averages for comparison
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=30)
    
    # Use Django's date functions to extract the date portion
    from django.db.models.functions import TruncDate
    from django.db.models import Count, Avg, StdDev
    
    # Get average and standard deviation of daily record counts
    daily_stats = (
        model_class.objects
        .filter(timestamp__date__gte=start_date, timestamp__date__lt=end_date)
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(count=Count('id'))
        .aggregate(
            avg_daily_count=Avg('count'),
            stddev_daily_count=StdDev('count')
        )
    )
    
    avg_daily_count = daily_stats['avg_daily_count'] or 0
    stddev_daily_count = daily_stats['stddev_daily_count'] or 0
    
    # Check for days with zero records when we'd expect some
    if avg_daily_count > 10:  # Only check if we typically have a meaningful number of records
        daily_counts = (
            model_class.objects
            .filter(timestamp__date__gte=start_date, timestamp__date__lt=end_date)
            .annotate(date=TruncDate('timestamp'))
            .values('date')
            .annotate(count=Count('id'))
        )
        
        # Get a set of dates with records
        dates_with_records = {item['date'] for item in daily_counts}
        
        # Check each day in our range
        current_date = start_date
        while current_date < end_date:
            if current_date not in dates_with_records:
                # If it's a weekday, it's unusual to have zero records
                if current_date.weekday() < 5:  # 0-4 are Monday to Friday
                    issues.append({
                        'issue_type': 'missing_records',
                        'model': model_name,
                        'date': current_date.isoformat(),
                        'description': f"No {model_name} records found for {current_date.isoformat()}, "
                                      f"when an average of {avg_daily_count:.1f} records were expected"
                    })
            current_date += timedelta(days=1)
    
    # Check for unusual time gaps between sequential records
    try:
        # Get most recent records
        recent_records = model_class.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=2)
        ).order_by('timestamp')
        
        # Calculate typical time between records
        # If we have enough records to calculate gaps
        if recent_records.count() > 10:
            timestamps = [record.timestamp for record in recent_records]
            gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
            
            if gaps:
                avg_gap = mean(gaps)
                if len(gaps) > 1:
                    gap_stddev = stdev(gaps)
                else:
                    gap_stddev = 0
                
                # Look for unusually large gaps (over 3 standard deviations or 6 hours)
                max_gap_seconds = max(avg_gap + 3 * gap_stddev, 21600)  # At least 6 hours
                
                large_gaps = [
                    (i, gap) for i, gap in enumerate(gaps) 
                    if gap > max_gap_seconds and gap > 3600  # At least 1 hour
                ]
                
                for idx, gap in large_gaps:
                    gap_hours = gap / 3600
                    issues.append({
                        'issue_type': 'timestamp_gap',
                        'model': model_name,
                        'description': f"Unusual gap of {gap_hours:.1f} hours between records on "
                                      f"{timestamps[idx].isoformat()} and {timestamps[idx+1].isoformat()}",
                        'gap_seconds': gap
                    })
    except Exception as e:
        logger.error(f"Error checking timestamp gaps for {model_name}: {str(e)}")
    
    return issues

def _check_volume_anomalies(model_class, model_name):
    """
    Check for unusual changes in log volume that could indicate logging issues.
    
    Args:
        model_class: The model class to check
        model_name: Display name of the model for reporting
        
    Returns:
        list: Detected issues
    """
    issues = []
    
    # Get historical daily volume averages for comparison
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=30)
    yesterday = end_date - timedelta(days=1)
    
    # Use Django's date functions to extract the date portion
    from django.db.models.functions import TruncDate
    from django.db.models import Count, Avg, StdDev
    
    # Get average and standard deviation of daily record counts
    daily_stats = (
        model_class.objects
        .filter(timestamp__date__gte=start_date, timestamp__date__lt=yesterday)
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(count=Count('id'))
        .aggregate(
            avg_daily_count=Avg('count'),
            stddev_daily_count=StdDev('count')
        )
    )
    
    avg_daily_count = daily_stats['avg_daily_count'] or 0
    stddev_daily_count = daily_stats['stddev_daily_count'] or 0
    
    # Get yesterday's count
    yesterday_count = (
        model_class.objects
        .filter(timestamp__date=yesterday)
        .count()
    )
    
    # Calculate Z-score for yesterday's count
    if stddev_daily_count > 0:
        z_score = (yesterday_count - avg_daily_count) / stddev_daily_count
        
        # If Z-score is extremely high or low (> 3 or < -3), it's unusual
        if abs(z_score) > 3:
            direction = "increase" if z_score > 0 else "decrease"
            issues.append({
                'issue_type': 'volume_anomaly',
                'model': model_name,
                'date': yesterday.isoformat(),
                'description': f"Unusual {direction} in {model_name} volume on {yesterday.isoformat()}: "
                             f"{yesterday_count} records (Z-score: {z_score:.2f}), "
                             f"when normal range is {avg_daily_count:.1f} ± {stddev_daily_count:.1f}",
                'z_score': z_score,
                'count': yesterday_count,
                'average': avg_daily_count
            })
    
    # Also check for extremely low counts if we normally have significant volume
    if avg_daily_count > 50 and yesterday_count < avg_daily_count * 0.2:
        issues.append({
            'issue_type': 'low_volume',
            'model': model_name,
            'date': yesterday.isoformat(),
            'description': f"Critically low {model_name} volume on {yesterday.isoformat()}: "
                         f"Only {yesterday_count} records, when typically {avg_daily_count:.1f} expected",
            'count': yesterday_count,
            'average': avg_daily_count
        })
    
    return issues

def _report_integrity_issues(issues):
    """
    Report detected integrity issues to administrators.
    
    Args:
        issues: List of detected issues
    """
    if not issues:
        return
        
    # Log all issues
    for issue in issues:
        logger.warning(f"Audit integrity issue: {issue['description']}")
        
    # Create a security audit log entry for each issue
    from .models import SecurityAuditLog
    
    for issue in issues:
        SecurityAuditLog.objects.create(
            event_type='system_error',
            description=f"Audit integrity issue: {issue['description']}",
            severity='high',
            additional_data=issue
        )
    
    # Notify administrators
    subject = f"ALERT: {len(issues)} Audit Integrity Issues Detected"
    
    message = f"""
    The audit integrity verification process has detected {len(issues)} potential issues:
    
    """ + "\n\n".join([f"- {issue['description']}" for issue in issues]) + """
    
    These issues could indicate problems with the audit logging system or potential 
    security concerns that require investigation.
    
    Please review the security audit logs for more details.
    """
    
    try:
        mail_admins(
            subject=subject,
            message=message,
            fail_silently=True
        )
    except Exception as e:
        logger.error(f"Failed to send admin email about integrity issues: {str(e)}")
        
    # Also send to compliance officers if configured
    compliance_emails = getattr(settings, 'COMPLIANCE_OFFICER_EMAILS', [])
    if compliance_emails:
        try:
            from django.core.mail import send_mail
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=compliance_emails,
                fail_silently=True
            )
        except Exception as e:
            logger.error(f"Failed to send compliance email about integrity issues: {str(e)}")
