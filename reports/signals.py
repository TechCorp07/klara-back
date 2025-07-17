from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
import logging

from .models import ReportConfiguration, Report, ReportScheduleLog

logger = logging.getLogger('hipaa_audit')

@receiver(post_save, sender=ReportConfiguration)
def create_next_scheduled_run(sender, instance, created, **kwargs):
    """
    Create or update the next scheduled run when a report configuration is created or updated.
    This would be used by a scheduler like Celery to determine when to run reports.
    """
    # Only handle configurations with schedules
    if instance.schedule == 'on_demand':
        return
    
    # Determine the next run time based on the schedule
    now = timezone.now()
    
    # For new configurations or those without a next_run
    if created or not instance.next_run:
        if instance.schedule == 'daily':
            next_run = now + timedelta(days=1)
        elif instance.schedule == 'weekly':
            next_run = now + timedelta(days=7)
        elif instance.schedule == 'monthly':
            # Simple approximation for a month
            next_run = now + timedelta(days=30)
        elif instance.schedule == 'quarterly':
            next_run = now + timedelta(days=90)
        elif instance.schedule == 'annual':
            next_run = now + timedelta(days=365)
        elif instance.schedule == 'once':
            # For one-time reports, use the specified next_run
            next_run = instance.next_run or now
        else:
            return
        
        # Update the configuration with the next run time
        ReportConfiguration.objects.filter(id=instance.id).update(next_run=next_run)
        
        # Create a schedule log entry
        ReportScheduleLog.objects.create(
            configuration=instance,
            scheduled_time=next_run,
            status='PENDING'
        )
        
        logger.info(
            f"REPORT_SCHEDULED: Report configuration {instance.id} ({instance.name}) "
            f"scheduled for {next_run.isoformat()}"
        )

@receiver(post_save, sender=Report)
def update_schedule_log(sender, instance, created, **kwargs):
    """
    Update the schedule log entry when a report is created or updated.
    """
    if not created:
        # Find the associated schedule log if any
        schedule_logs = ReportScheduleLog.objects.filter(
            configuration=instance.configuration,
            report=instance
        )
        
        if schedule_logs.exists():
            # Update the status
            schedule_logs.update(
                status=instance.status,
                execution_time=instance.completed_at or instance.started_at
            )

@receiver(post_save, sender=Report)
def schedule_next_report(sender, instance, created, **kwargs):
    """
    Schedule the next report when a report is completed.
    """
    # Only handle completed reports for scheduled configurations
    if instance.status != 'COMPLETED' or instance.configuration.schedule == 'on_demand':
        return
    
    # Only schedule next report if this was from a scheduled run
    schedule_log = ReportScheduleLog.objects.filter(report=instance).first()
    if not schedule_log:
        return
    
    # Calculate the next run time based on the schedule
    config = instance.configuration
    last_run = instance.completed_at or timezone.now()
    
    if config.schedule == 'daily':
        next_run = last_run + timedelta(days=1)
    elif config.schedule == 'weekly':
        next_run = last_run + timedelta(days=7)
    elif config.schedule == 'monthly':
        next_run = last_run + timedelta(days=30)
    elif config.schedule == 'quarterly':
        next_run = last_run + timedelta(days=90)
    elif config.schedule == 'annual':
        next_run = last_run + timedelta(days=365)
    elif config.schedule == 'once':
        # For one-time reports, don't schedule again
        # Mark the configuration as on-demand after the one-time run
        ReportConfiguration.objects.filter(id=config.id).update(
            schedule='on_demand',
            next_run=None
        )
        return
    else:
        return
    
    # Update the configuration with the next run time
    ReportConfiguration.objects.filter(id=config.id).update(
        last_run=last_run,
        next_run=next_run
    )
    
    # Create a schedule log entry for the next run
    ReportScheduleLog.objects.create(
        configuration=config,
        scheduled_time=next_run,
        status='PENDING'
    )
    
    logger.info(
        f"NEXT_REPORT_SCHEDULED: Report configuration {config.id} ({config.name}) "
        f"next run scheduled for {next_run.isoformat()}"
    )
