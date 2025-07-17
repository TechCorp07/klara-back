import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'klararety.settings')

app = Celery('klararety')

# Using a string means the worker doesn't have to serialize the configuration
# object to child processes
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

# Configure Celery beat schedule for periodic tasks
app.conf.beat_schedule = {
    # Wearables tasks
    'sync-wearable-data-every-hour': {
        'task': 'wearables.tasks.sync_wearable_data_for_all_users',
        'schedule': 3600.0,  # Every hour
    },
    'cleanup-old-wearable-data-weekly': {
        'task': 'wearables.tasks.cleanup_old_wearable_data',
        'schedule': 604800.0,  # Every week
        'kwargs': {'days_to_keep': 90},
    },
    'check-verification-expirations': {
        'task': 'users.tasks.check_verification_expirations',
        'schedule': 86400.0,  # Every day (24 hours)
    },
    'send-daily-admin-notifications': {
        'task': 'users.tasks.send_admin_notifications',
        'schedule': 86400.0,  # Every day (24 hours)
    },
    'auto-end-expired-emergency-access': {
        'task': 'users.tasks.auto_end_expired_emergency_access',
        'schedule': 3600.0,
    },
    # Audit and compliance tasks
    'daily-compliance-report': {
        'task': 'audit.tasks.generate_daily_compliance_report',
        'schedule': 86400.0,  # Every day (24 hours)
    },
    'weekly-compliance-report': {
        'task': 'audit.tasks.generate_weekly_compliance_report',
        'schedule': 604800.0,  # Every week
    },
    'monitor-suspicious-access-patterns': {
        'task': 'audit.tasks.monitor_suspicious_access_patterns',
        'schedule': 43200.0,  # Twice daily (12 hours)
    },
    'check-expired-compliance-reports': {
        'task': 'audit.tasks.check_expired_compliance_reports',
        'schedule': 86400.0,  # Every day
    },
    'verify-audit-integrity': {
        'task': 'audit.tasks.verify_audit_integrity',
        'schedule': 86400.0,  # Every day
    },
    'cleanup-old-audit-exports': {
        'task': 'audit.tasks.cleanup_old_audit_exports',
        'schedule': 604800.0,  # Every week
    },
    'cleanup-old-audit-records': {
        'task': 'audit.tasks.cleanup_old_audit_records',
        'schedule': 2592000.0,  # Every month (30 days)
    },
    
    # Communication tasks
    'clean-old-notifications': {
        'task': 'communication.tasks.clean_old_notifications',
        'schedule': 86400.0,  # Every day
    },
    'send-daily-message-digest': {
        'task': 'communication.tasks.send_message_digest',
        'schedule': 86400.0,  # Every day
        'kwargs': {'interval': 'daily'},
    },
    'send-weekly-message-digest': {
        'task': 'communication.tasks.send_message_digest',
        'schedule': 604800.0,  # Every week
        'kwargs': {'interval': 'weekly'},
    },
    'sync-conversations': {
        'task': 'communication.tasks.sync_conversations_with_healthcare_events',
        'schedule': 14400.0,  # Every 4 hours
    },
    
    # Medication tasks
    'send-medication-reminders': {
        'task': 'medication.tasks.send_due_reminders',
        'schedule': 600.0,  # Every 10 minutes
    },
    'check-missed-doses': {
        'task': 'medication.tasks.check_missed_doses',
        'schedule': 3600.0,  # Every hour
    },
    'update-medication-adherence': {
        'task': 'medication.tasks.update_adherence_records',
        'schedule': 86400.0,  # Every day
    },
    'check-drug-interactions': {
        'task': 'medication.tasks.check_all_patient_interactions',
        'schedule': 86400.0,  # Every day
    },
    'check-expiring-prescriptions': {
        'task': 'medication.tasks.check_expiring_prescriptions',
        'schedule': 86400.0,  # Every day
    },
    'generate-medication-schedules': {
        'task': 'medication.tasks.generate_medication_schedules',
        'schedule': 86400.0,  # Every day
    },
    
    # Reports tasks
    'generate-scheduled-reports': {
        'task': 'reports.tasks.generate_scheduled_reports',
        'schedule': 900.0,  # Every 15 minutes
    },
    'clean-old-reports': {
        'task': 'reports.tasks.clean_old_reports',
        'schedule': 86400.0,  # Every day
    },
    'refresh-dashboard-widgets': {
        'task': 'reports.tasks.refresh_dashboard_widgets',
        'schedule': 300.0,  # Every 5 minutes
    },
    
    # Telemedicine tasks
    'send-appointment-reminders': {
        'task': 'telemedicine.tasks.send_appointment_reminders',
        'schedule': 3600.0,  # Every hour
    },
    'check-missed-appointments': {
        'task': 'telemedicine.tasks.check_missed_appointments',
        'schedule': 1800.0,  # Every 30 minutes
    },
    'check-prescription-expiration': {
        'task': 'telemedicine.tasks.check_prescription_expiration',
        'schedule': 86400.0,  # Every day
    },
    'generate-provider-availability': {
        'task': 'telemedicine.tasks.generate_provider_availability',
        'schedule': 86400.0,  # Every day
    },
    'clean-waiting-room': {
        'task': 'telemedicine.tasks.clean_waiting_room',
        'schedule': 1800.0,  # Every 30 minutes
    },
    'end-abandoned-consultations': {
        'task': 'telemedicine.tasks.end_abandoned_consultations',
        'schedule': 1800.0,  # Every 30 minutes
    },
    
    # Community tasks
    'moderate-flagged-content': {
        'task': 'community.tasks.moderate_flagged_content',
        'schedule': 3600.0,  # Every hour
    },
    'send-community-digest': {
        'task': 'community.tasks.send_community_digest',
        'schedule': 86400.0,  # Daily at midnight
    },
    'cleanup-old-notifications': {
        'task': 'community.tasks.cleanup_old_notifications',
        'schedule': 86400.0,  # Daily
    },
    'check-inactive-groups': {
        'task': 'community.tasks.check_inactive_groups',
        'schedule': 604800.0,  # Weekly
    },
    
}

# Configure task time limits
app.conf.task_time_limit = 3600  # 1 hour max runtime
app.conf.task_soft_time_limit = 3000  # 50 minutes soft limit

# Configure task priorities
app.conf.task_queue_max_priority = 10
app.conf.task_default_priority = 5

# Configure task routes for different queues
app.conf.task_routes = {
    # High priority tasks
    'medication.tasks.send_due_reminders': {'queue': 'high_priority', 'priority': 9},
    'communication.tasks.send_email_notification_task': {'queue': 'high_priority', 'priority': 8},
    'telemedicine.tasks.send_appointment_reminders': {'queue': 'high_priority', 'priority': 8},
    
    # Medium priority tasks
    'wearables.tasks.*': {'queue': 'medium_priority', 'priority': 5},
    'medication.tasks.check_missed_doses': {'queue': 'medium_priority', 'priority': 6},
    'telemedicine.tasks.check_missed_appointments': {'queue': 'medium_priority', 'priority': 6},
    
    # Low priority tasks
    'audit.tasks.*': {'queue': 'low_priority', 'priority': 3},
    'reports.tasks.*': {'queue': 'low_priority', 'priority': 2},
    'medication.tasks.update_adherence_records': {'queue': 'low_priority', 'priority': 3},
}

# Configure result backend and expire time
app.conf.result_expires = 3600  # Results expire after 1 hour

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
