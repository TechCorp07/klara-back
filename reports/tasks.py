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
