# HIPAA Audit Configuration
from datetime import timedelta

# Main audit functionality control
AUDIT_ENABLED = True

# Paths to exclude from audit logging
AUDIT_SKIP_PATHS = [
    r'^/admin/',
    r'^/static/',
    r'^/media/',
    r'^/favicon\.ico',
    r'^/robots\.txt',
    r'^/api/docs/',
    r'^/api/schema/',
    r'^/health/',
    r'^/api/health/',
]

# Paths that contain PHI and require special logging
AUDIT_PHI_PATHS = [
    r'^/api/healthcare/',
    r'^/api/medication/',
    r'^/api/telemedicine/',
    r'^/api/patients/',
    r'^/api/providers/',
    r'^/api/appointments/',
    r'^/api/medical-records/',
    r'^/api/lab-results/',
    r'^/api/prescriptions/',
]

# Security settings
AUDIT_TRACK_FAILED_LOGINS = True
FAILED_LOGIN_THRESHOLD = 5  # Number of failures before flagging
FAILED_LOGIN_WINDOW_MINUTES = 15  # Time window for failures
ACCOUNT_LOCKOUT_THRESHOLD = 10  # Number of failures before account lockout
ACCOUNT_LOCKOUT_DURATION_MINUTES = 30  # Duration of lockout

# Data retention settings - HIPAA requires minimum 6 years
AUDIT_EVENT_RETENTION_DAYS = 2190  # 6 years
PHI_ACCESS_LOG_RETENTION_DAYS = 2190  # 6 years 
SECURITY_LOG_RETENTION_DAYS = 2190  # 6 years
AUDIT_EXPORT_RETENTION_DAYS = 90  # 3 months for exports (not the primary records)

# Business hours for after-hours detection
BUSINESS_HOURS_START = 8  # 8:00 AM
BUSINESS_HOURS_END = 18   # 6:00 PM
WEEKEND_DAYS = [5, 6]     # Saturday (5) and Sunday (6)

# VIP patient settings - patients requiring extra monitoring
VIP_PATIENT_IDS = []  # List of patient IDs requiring special monitoring

# Compliance officer emails for automated reports
COMPLIANCE_OFFICER_EMAILS = []  # List of email addresses for compliance notifications

# Email notification settings
AUDIT_EMAIL_NOTIFICATIONS = True
SECURITY_ALERT_EMAILS = []  # List of email addresses for security alerts

# Authentication requirements - standard HIPAA practices
AUTH_PASSWORD_EXPIRY_DAYS = 90  # Password expires after 90 days
AUTH_PASSWORD_MIN_LENGTH = 12  # Minimum password length
AUTH_PASSWORD_COMPLEXITY = True  # Require complex passwords
AUTH_2FA_REQUIRED_ROLES = ['admin', 'provider', 'compliance', 'researcher']  # Roles requiring 2FA

# API throttling settings for security - to prevent brute force/DoS
REST_FRAMEWORK = {
    # Existing settings...
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day',
        'audit_api': '100/hour',  # Specific throttle for audit API
        'auth': '20/hour',        # Authentication endpoints
    },
}

# Automated task scheduling - for regular compliance checks
CELERYBEAT_SCHEDULE = {
    'monitor-suspicious-activity': {
        'task': 'audit.tasks.monitor_suspicious_access_patterns',
        'schedule': timedelta(hours=6),  # Run 4 times per day
    },
    'daily-compliance-report': {
        'task': 'audit.tasks.generate_daily_compliance_report',
        'schedule': timedelta(days=1, hours=1),  # Daily at 1:00 AM
    },
    'weekly-compliance-report': {
        'task': 'audit.tasks.generate_weekly_compliance_report',
        'schedule': timedelta(days=7, hours=1),  # Weekly at 1:00 AM
    },
    'check-expired-reports': {
        'task': 'audit.tasks.check_expired_compliance_reports',
        'schedule': timedelta(days=7, hours=2),  # Weekly at 2:00 AM
    },
    'cleanup-old-audit-exports': {
        'task': 'audit.tasks.cleanup_old_audit_exports',
        'schedule': timedelta(days=30, hours=3),  # Monthly at 3:00 AM
    },
    'verify-audit-integrity': {
        'task': 'audit.tasks.verify_audit_integrity',
        'schedule': timedelta(days=7, hours=4),  # Weekly at 4:00 AM
    },
}

# Define roles with permission to access PHI
PHI_ACCESS_ROLES = ['admin', 'provider', 'compliance', 'caregiver', 'nurse', 'pharmacist']

# Minimum necessary access thresholds for alerting - HIPAA minimum necessary principle
MINIMUM_NECESSARY_THRESHOLDS = {
    'patient_count_warning': 20,      # Alert when provider accesses >20 patients in a day
    'record_count_warning': 100,      # Alert when user accesses >100 records in a day
    'rapid_access_threshold': 30,     # Alert when user accesses >30 records in an hour
    'records_per_minute_max': 10,     # Alert when user accesses >10 records per minute
    'records_per_hour_max': 50,       # Alert when user accesses >50 records per hour
}

# Sensitive resources requiring extra monitoring
SENSITIVE_RESOURCES = [
    'medical_record',
    'medication_schedule',
    'genetic_data',
    'mental_health',
    'substance_abuse',
    'hiv_status',
    'communicable_disease',
]

# Integration settings for audit health check
AUDIT_HEALTH_CHECK_ENABLED = True
AUDIT_HEALTH_CHECK_INTERVAL_HOURS = 24

# HIPAA breach notification settings
BREACH_NOTIFICATION_EMAILS = []  # Recipients for potential breach notifications

# Required reason for PHI access 
REQUIRE_PHI_ACCESS_REASON = True  # Whether to require documented reason for PHI access

# Audit log detail level
AUDIT_LOG_DETAIL_LEVEL = 'HIGH'  # Options: 'LOW', 'MEDIUM', 'HIGH'

# Emergency access (break-glass) settings
EMERGENCY_ACCESS_ENABLED = True
EMERGENCY_ACCESS_NOTIFICATION_EMAILS = []  # Recipients for emergency access notifications

# Automatic PHI access termination after inactivity
PHI_ACCESS_TIMEOUT_MINUTES = 30  # Auto-logout after inactivity

# System access monitoring
SYSTEM_ACCESS_VERIFICATION_DAYS = 90  # Verify system access permissions quarterly
