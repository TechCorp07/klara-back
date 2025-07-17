from __future__ import absolute_import, unicode_literals
import logging
from datetime import timedelta
from django.utils import timezone
from django.db.models import Q
from celery import shared_task

from .models import ReportConfiguration, Report, ReportScheduleLog
from .services.report_generator import ReportGeneratorService

logger = logging.getLogger('hipaa_audit')

@shared_task
def generate_scheduled_reports():
    """
    Task to check for and generate scheduled reports.
    This task should be scheduled to run periodically (e.g., every 15 minutes)
    """
    now = timezone.now()
    
    # Find configurations that need to be run
    due_configs = ReportConfiguration.objects.filter(
        Q(next_run__lte=now),
        ~Q(schedule='on_demand')
    )
    
    for config in due_configs:
        # Schedule the generation task
        generate_report.delay(config.id)
        
        logger.info(
            f"SCHEDULED_REPORT_QUEUED: Report configuration {config.id} ({config.name}) "
            f"queued for generation at {now.isoformat()}"
        )

@shared_task
def generate_report(config_id):
    """
    Task to generate a report from a configuration.
    
    Args:
        config_id: ID of the ReportConfiguration to generate
    """
    try:
        # Get the configuration
        config = ReportConfiguration.objects.get(id=config_id)
        
        # Create the report
        report = Report.objects.create(
            configuration=config,
            status=Report.Status.PENDING,
            created_by=config.created_by
        )
        
        # Update any schedule log
        schedule_log = ReportScheduleLog.objects.filter(
            configuration=config,
            status='PENDING',
            report__isnull=True
        ).first()
        
        if schedule_log:
            schedule_log.report = report
            schedule_log.save(update_fields=['report'])
        
        # Start generation
        logger.info(
            f"REPORT_GENERATION_STARTED: Report {report.report_id} from configuration "
            f"{config.id} ({config.name}) started at {timezone.now().isoformat()}"
        )
        
        # Update report status
        report.status = Report.Status.RUNNING
        report.started_at = timezone.now()
        report.save(update_fields=['status', 'started_at'])
        
        # Generate the report
        generator = ReportGeneratorService()
        results = generator.generate_report(config, config.created_by)
        
        # Update the report with results
        report.status = Report.Status.COMPLETED
        report.completed_at = timezone.now()
        report.results_json = results
        report.save(update_fields=['status', 'completed_at', 'results_json'])
        
        # Update the configuration last_run time
        config.last_run = timezone.now()
        config.save(update_fields=['last_run'])
        
        # Update schedule log if exists
        if schedule_log:
            schedule_log.status = Report.Status.COMPLETED
            schedule_log.execution_time = report.completed_at
            schedule_log.save(update_fields=['status', 'execution_time'])
        
        logger.info(
            f"REPORT_GENERATION_COMPLETED: Report {report.report_id} from configuration "
            f"{config.id} ({config.name}) completed at {report.completed_at.isoformat()}"
        )
        
        # Send notification to recipients if any
        if config.recipients.exists():
            notify_report_recipients.delay(report.id)
            
        return str(report.report_id)
        
    except ReportConfiguration.DoesNotExist:
        logger.error(f"REPORT_GENERATION_FAILED: Configuration with ID {config_id} not found")
        raise
    
    except Exception as e:
        logger.error(
            f"REPORT_GENERATION_FAILED: Configuration with ID {config_id} failed: {str(e)}"
        )
        
        # If report was created, update its status
        try:
            report.status = Report.Status.FAILED
            report.error_message = str(e)
            report.completed_at = timezone.now()
            report.save(update_fields=['status', 'error_message', 'completed_at'])
            
            # Update schedule log if exists
            if schedule_log:
                schedule_log.status = Report.Status.FAILED
                schedule_log.error_message = str(e)
                schedule_log.execution_time = report.completed_at
                schedule_log.save(update_fields=['status', 'error_message', 'execution_time'])
        except:
            pass
            
        raise

@shared_task
def clean_old_reports():
    """
    Task to clean up old reports to save storage space.
    Keeps completed reports for 90 days and failed reports for 14 days.
    This task should be scheduled to run daily.
    """
    now = timezone.now()
    
    # Get dates for deletion thresholds
    completed_threshold = now - timedelta(days=90)
    failed_threshold = now - timedelta(days=14)
    
    # Find and delete old reports
    old_completed_reports = Report.objects.filter(
        status=Report.Status.COMPLETED,
        completed_at__lt=completed_threshold
    )
    
    old_failed_reports = Report.objects.filter(
        status=Report.Status.FAILED,
        completed_at__lt=failed_threshold
    )
    
    completed_count = old_completed_reports.count()
    failed_count = old_failed_reports.count()
    
    # Delete the reports
    old_completed_reports.delete()
    old_failed_reports.delete()
    
    logger.info(
        f"OLD_REPORTS_CLEANED: Deleted {completed_count} completed reports older than "
        f"{completed_threshold.isoformat()} and {failed_count} failed reports older than "
        f"{failed_threshold.isoformat()}"
    )
    
    return {
        'completed_deleted': completed_count,
        'failed_deleted': failed_count
    }

@shared_task
def notify_report_recipients(report_id):
    """
    Task to notify recipients when a report is completed.
    
    Args:
        report_id: ID of the completed report
    """
    try:
        # Get the report
        report = Report.objects.get(id=report_id)
        
        # Check if the report is completed
        if report.status != Report.Status.COMPLETED:
            logger.warning(f"NOTIFY_SKIPPED: Report {report.report_id} is not completed.")
            return
        
        # Get the recipients
        recipients = report.configuration.recipients.all()
        
        if not recipients.exists():
            logger.info(f"NOTIFY_SKIPPED: Report {report.report_id} has no recipients.")
            return
        
        # In a real implementation, this would send emails to recipients
        # For this example, we'll just log the notification
        recipient_emails = [recipient.email for recipient in recipients]
        
        logger.info(
            f"REPORT_NOTIFICATION: Report {report.report_id} ({report.configuration.name}) "
            f"completion notification sent to: {', '.join(recipient_emails)}"
        )
        
        # Simulated email notification
        from django.core.mail import send_mail
        from django.conf import settings
        
        try:
            subject = f"Report '{report.configuration.name}' is ready"
            message = f"""
            Hello,
            
            Your report '{report.configuration.name}' has been completed and is now available.
            
            Report ID: {report.report_id}
            Report Type: {report.configuration.get_report_type_display()}
            Generated At: {report.completed_at.strftime('%Y-%m-%d %H:%M:%S')}
            
            You can view the report by logging into the Klararety Health Platform.
            
            Best regards,
            The Klararety Team
            """
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=recipient_emails,
                fail_silently=True,
            )
        except Exception as e:
            logger.error(f"EMAIL_SEND_FAILED: Failed to send email for report {report.report_id}: {str(e)}")
        
        return {
            'report_id': str(report.report_id),
            'recipients': len(recipient_emails)
        }
        
    except Report.DoesNotExist:
        logger.error(f"NOTIFY_FAILED: Report with ID {report_id} not found")
        raise
    
    except Exception as e:
        logger.error(f"NOTIFY_FAILED: Notification for report ID {report_id} failed: {str(e)}")
        raise

@shared_task
def refresh_dashboard_widgets():
    """
    Task to refresh dashboard widgets with auto-refresh settings.
    This task should be scheduled to run periodically (e.g., every 5 minutes)
    """
    from .models import DashboardWidget
    from .services.analytics import AnalyticsService
    
    now = timezone.now()
    
    # Find widgets that need to be refreshed
    # Only refresh widgets that have a non-zero refresh interval and either
    # have never been refreshed or were last refreshed more than interval minutes ago
    widgets_to_refresh = DashboardWidget.objects.filter(
        ~Q(refresh_interval=0)
    ).filter(
        Q(last_refresh__isnull=True) |
        Q(last_refresh__lt=now - timedelta(minutes=F('refresh_interval')))
    )
    
    analytics_service = AnalyticsService()
    refresh_count = 0
    
    for widget in widgets_to_refresh:
        try:
            # Get the widget owner
            user = widget.dashboard.owner
            
            # Refresh the widget data
            new_data = analytics_service.get_widget_data(
                widget.data_source,
                widget.configuration,
                user
            )
            
            # Update widget configuration with new data
            widget.configuration['data'] = new_data
            widget.last_refresh = timezone.now()
            widget.save(update_fields=['configuration', 'last_refresh'])
            
            refresh_count += 1
            
            logger.info(
                f"WIDGET_REFRESHED: Dashboard widget {widget.id} ({widget.title}) "
                f"on dashboard {widget.dashboard.id} ({widget.dashboard.name}) refreshed"
            )
            
        except Exception as e:
            logger.error(
                f"WIDGET_REFRESH_FAILED: Dashboard widget {widget.id} ({widget.title}) "
                f"on dashboard {widget.dashboard.id} ({widget.dashboard.name}) refresh failed: {str(e)}"
            )
    
    return {
        'widgets_refreshed': refresh_count,
        'total_eligible': widgets_to_refresh.count()
    }

@shared_task
def generate_critical_alerts_report():
    """Generate and send critical alerts report for rare disease patients."""
    from .services.real_time_analytics import RealTimeAnalyticsService
    from communication.services.notification_service import NotificationService
    
    # Get real-time analytics
    medication_alerts = RealTimeAnalyticsService.get_medication_adherence_alerts()
    wearable_anomalies = RealTimeAnalyticsService.get_wearable_anomalies()
    emergency_indicators = RealTimeAnalyticsService.get_emergency_indicators()
    
    # Compile critical alerts
    critical_alerts = {
        'medication_alerts': medication_alerts,
        'wearable_anomalies': wearable_anomalies,
        'emergency_indicators': emergency_indicators,
        'generated_at': timezone.now().isoformat(),
        'requires_immediate_attention': len(medication_alerts) > 0 or len(emergency_indicators) > 0
    }
    
    # Send to appropriate stakeholders if critical alerts exist
    if critical_alerts['requires_immediate_attention']:
        notification_service = NotificationService()
        
        # Get admin and compliance users
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        stakeholders = User.objects.filter(
            Q(role='admin') | Q(role='compliance') | Q(is_staff=True),
            is_active=True
        )
        
        for user in stakeholders:
            notification_service.send_critical_rare_disease_alert(
                user=user,
                alert_data=critical_alerts,
                severity_level='HIGH'
            )
    
    return f"Critical alerts processed: {len(medication_alerts + wearable_anomalies + emergency_indicators)} total alerts"

@shared_task
def generate_pharmaceutical_compliance_report(pharmco_user_id):
    """Generate compliance report for pharmaceutical companies."""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    try:
        pharmco_user = User.objects.get(id=pharmco_user_id, role='pharmco')
        
        # Generate report using regulatory export service
        from .services.regulatory_export import RegulatoryExportService
        
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=90)  # Quarterly report
        
        # Get medications associated with this pharmaceutical company
        from medication.models import Medication
        company_medications = Medication.objects.filter(
            manufacturer=pharmco_user.company_name,  # Assuming this field exists
            for_rare_condition=True
        )
        
        compliance_data = {
            'company': pharmco_user.company_name,
            'report_period': f"{start_date} to {end_date}",
            'medications_monitored': company_medications.count(),
            'adverse_events_data': {},
            'clinical_outcomes': {},
            'regulatory_status': {}
        }
        
        for medication in company_medications:
            # Generate PSUR for each medication
            psur_data = RegulatoryExportService.generate_periodic_safety_update(
                medication.id, start_date, end_date
            )
            compliance_data['adverse_events_data'][medication.name] = psur_data
        
        # Create report record
        from .models import Report, ReportConfiguration
        
        config, _ = ReportConfiguration.objects.get_or_create(
            name=f"Pharmaceutical Compliance - {pharmco_user.company_name}",
            report_type='pharmaceutical_compliance',
            created_by=pharmco_user,
            defaults={
                'description': 'Automated quarterly compliance report',
                'schedule': 'quarterly',
                'parameters': {'company_id': pharmco_user.id}
            }
        )
        
        report = Report.objects.create(
            configuration=config,
            status='COMPLETED',
            started_at=timezone.now(),
            completed_at=timezone.now(),
            results_json=compliance_data,
            created_by=pharmco_user
        )
        
        # Send notification
        from communication.services.notification_service import NotificationService
        notification_service = NotificationService()
        
        notification_service.create_notification(
            user=pharmco_user,
            title='Quarterly Compliance Report Generated',
            message=f'Your compliance report for {start_date} to {end_date} is ready for review.',
            notification_type='system',
            related_object_id=report.id,
            related_object_type='report'
        )
        
        return f"Compliance report generated for {pharmco_user.company_name}"
        
    except Exception as e:
        logger.error(f"Error generating pharmaceutical compliance report: {str(e)}")
        return f"Error: {str(e)}"
