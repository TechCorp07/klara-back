from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid


class AuditEvent(models.Model):
    """
    Model for general audit events.
    Tracks API access, system events, and user actions.
    """
    class EventType(models.TextChoices):
        CREATE = 'create', 'Create'
        READ = 'read', 'Read'
        UPDATE = 'update', 'Update'
        DELETE = 'delete', 'Delete'
        LOGIN = 'login', 'Login'
        LOGOUT = 'logout', 'Logout'
        ACCESS = 'access', 'Access'
        ERROR = 'error', 'Error'
        PASSWORD_RESET = 'password_reset', 'Password Reset'
        ACCOUNT_LOCKOUT = 'account_lockout', 'Account Lockout'
        PERMISSION_CHANGE = 'permission_change', 'Permission Change'
        EXPORT = 'export', 'Export'
        SHARE = 'share', 'Share'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        related_name='audit_events',
        null=True,
        blank=True
    )
    event_type = models.CharField(max_length=20, choices=EventType.choices, db_index=True)
    resource_type = models.CharField(max_length=100, db_index=True)
    resource_id = models.CharField(max_length=100, blank=True, db_index=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    additional_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type']),
            models.Index(fields=['resource_type']),
            models.Index(fields=['user']),
            models.Index(fields=['timestamp']),
        ]
        verbose_name = 'Audit Event'
        verbose_name_plural = 'Audit Events'
    
    def __str__(self):
        """String representation of the audit event."""
        return f"{self.get_event_type_display()} {self.resource_type} by {self.user or 'Anonymous'}"


class PHIAccessLog(models.Model):
    """
    Model for tracking Protected Health Information (PHI) access.
    HIPAA requires detailed logging of all PHI access.
    """
    class AccessType(models.TextChoices):
        VIEW = 'view', 'View'
        MODIFY = 'modify', 'Modify'
        EXPORT = 'export', 'Export'
        SHARE = 'share', 'Share'
        PRINT = 'print', 'Print'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='phi_access_logs',
        null=True
    )
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='phi_accessed_logs',
        null=True
    )
    access_type = models.CharField(max_length=20, choices=AccessType.choices, db_index=True)
    reason = models.TextField(help_text="HIPAA requires a documented reason for accessing PHI")
    record_type = models.CharField(max_length=100, db_index=True)
    record_id = models.CharField(max_length=100, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    additional_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['access_type']),
            models.Index(fields=['user']),
            models.Index(fields=['patient']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['record_type', 'record_id']),
        ]
        verbose_name = 'PHI Access Log'
        verbose_name_plural = 'PHI Access Logs'
    
    def __str__(self):
        """String representation of the PHI access."""
        patient_str = self.patient.username if self.patient else "Unknown patient"
        user_str = self.user.username if self.user else "Anonymous"
        return f"{self.get_access_type_display()} of {patient_str}'s {self.record_type} by {user_str}"


class SecurityAuditLog(models.Model):
    """
    Model for tracking security-related events.
    For security alerts, threats, and potential breaches.
    """
    class EventType(models.TextChoices):
        FAILED_LOGIN = 'failed_login', 'Failed Login'
        SUCCESSFUL_LOGIN = 'successful_login', 'Successful Login'
        SUSPICIOUS_LOGIN = 'suspicious_login', 'Suspicious Login'
        UNUSUAL_ACCESS = 'unusual_access', 'Unusual Access Pattern'
        PERMISSION_VIOLATION = 'permission_violation', 'Permission Violation'
        BRUTE_FORCE_ATTEMPT = 'brute_force_attempt', 'Brute Force Attempt'
        UNUSUAL_ACTIVITY = 'unusual_activity', 'Unusual Activity'
        SYSTEM_ERROR = 'system_error', 'System Error'
        AUTH_FAILURE = 'auth_failure', 'Authentication Failure'
        AUTH_SUCCESS = 'auth_success', 'Authentication Success'
        ACCOUNT_LOCKED = 'account_locked', 'Account Locked'
        DATA_EXPORT = 'data_export', 'Data Export'
        BULK_ACCESS = 'bulk_access', 'Bulk Data Access'
        AFTER_HOURS_ACCESS = 'after_hours_access', 'After Hours Access'
        VIP_ACCESS = 'vip_access', 'VIP Record Access'
        SECURITY_CHANGE = 'security_change', 'Security Setting Change'
        API_KEY_USAGE = 'api_key_usage', 'API Key Usage'
        RAPID_ACCESS = 'rapid_access', 'Rapid Access Pattern'
        UNAUTHORIZED_ACCESS = 'unauthorized_access', 'Unauthorized Access'
        DATA_BREACH = 'data_breach', 'Data Breach'
        MALWARE_DETECTED = 'malware_detected', 'Malware Detected'
        SYSTEM_INTRUSION = 'system_intrusion', 'System Intrusion'
        PRIVILEGE_ESCALATION = 'privilege_escalation', 'Privilege Escalation'
        DATA_EXFILTRATION = 'data_exfiltration', 'Data Exfiltration'
    
    class Severity(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='security_audit_logs',
        null=True,
        blank=True
    )
    event_type = models.CharField(max_length=30, choices=EventType.choices, db_index=True)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.MEDIUM, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    additional_data = models.JSONField(default=dict, blank=True)
    resolved = models.BooleanField(default=False, db_index=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='resolved_security_logs',
        null=True,
        blank=True
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['resolved']),
            models.Index(fields=['timestamp']),
        ]
        verbose_name = 'Security Audit Log'
        verbose_name_plural = 'Security Audit Logs'
    
    def __str__(self):
        """String representation of the security event."""
        return f"{self.get_event_type_display()} - {self.get_severity_display()} severity"
    
    def resolve(self, user, notes=''):
        """Mark security issue as resolved with audit trail."""
        if user is None:
            raise ValueError("Resolver user cannot be None")
            
        self.resolved = True
        self.resolved_by = user
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save(update_fields=['resolved', 'resolved_by', 'resolved_at', 'resolution_notes'])
        
        # Log resolution as a separate audit event
        from .utils import log_security_resolution
        log_security_resolution(self, user)


class ComplianceReport(models.Model):
    """
    Model for HIPAA compliance reports.
    For scheduled and ad-hoc compliance reporting.
    """
    class ReportType(models.TextChoices):
        DAILY_AUDIT = 'daily_audit', 'Daily Audit'
        PHI_ACCESS = 'phi_access', 'PHI Access'
        SECURITY_INCIDENTS = 'security_incidents', 'Security Incidents'
        USER_ACTIVITY = 'user_activity', 'User Activity'
        SYSTEM_ACCESS = 'system_access', 'System Access'
        WEEKLY_AUDIT = 'weekly_audit', 'Weekly Audit'
        MONTHLY_AUDIT = 'monthly_audit', 'Monthly Audit'
        QUARTERLY_AUDIT = 'quarterly_audit', 'Quarterly Audit'
        ANNUAL_AUDIT = 'annual_audit', 'Annual Audit'
        CUSTOM = 'custom', 'Custom Report'
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_type = models.CharField(max_length=30, choices=ReportType.choices, db_index=True)
    report_date = models.DateField(db_index=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='generated_compliance_reports',
        null=True,
        blank=True
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    file_url = models.URLField(blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-report_date']
        indexes = [
            models.Index(fields=['report_type']),
            models.Index(fields=['report_date']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
        verbose_name = 'Compliance Report'
        verbose_name_plural = 'Compliance Reports'
    
    def __str__(self):
        """String representation of the compliance report."""
        return f"{self.get_report_type_display()} - {self.report_date}"
    
    def update_status(self, status, notes=None):
        """Update report status with optional notes."""
        if status not in dict(self.Status.choices):
            raise ValueError(f"Invalid status: {status}")
            
        self.status = status
        if notes:
            self.notes = notes
        self.save(update_fields=['status', 'notes', 'updated_at'])


class AuditExport(models.Model):
    """
    Model for audit data exports.
    For exporting audit data for reporting or investigation.
    """
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='audit_exports'
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    file_url = models.URLField(blank=True)
    filters = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['user']),
            models.Index(fields=['created_at']),
        ]
        verbose_name = 'Audit Export'
        verbose_name_plural = 'Audit Exports'
    
    def __str__(self):
        """String representation of the audit export."""
        return f"Audit Export by {self.user.username} ({self.get_status_display()})"
    
    def update_status(self, status, error_message=None, file_url=None):
        """Update export status with optional error message and file URL."""
        if status not in dict(self.Status.choices):
            raise ValueError(f"Invalid status: {status}")
            
        self.status = status
        
        if status == self.Status.COMPLETED:
            self.completed_at = timezone.now()
            if file_url:
                self.file_url = file_url
        
        if status == self.Status.FAILED and error_message:
            self.error_message = error_message
            
        self.save()
