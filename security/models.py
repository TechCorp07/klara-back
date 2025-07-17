# security/models.py
import uuid
import json
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import URLValidator
from audit.models import SecurityAuditLog


class SecurityThreat(models.Model):
    """Model for tracking detected security threats."""
    
    class ThreatType(models.TextChoices):
        MALWARE = 'malware', 'Malware Detection'
        INTRUSION = 'intrusion', 'System Intrusion'
        DATA_BREACH = 'data_breach', 'Data Breach'
        PRIVILEGE_ESCALATION = 'privilege_escalation', 'Privilege Escalation'
        BRUTE_FORCE = 'brute_force', 'Brute Force Attack'
        DDoS = 'ddos', 'DDoS Attack'
        SQL_INJECTION = 'sql_injection', 'SQL Injection'
        XSS = 'xss', 'Cross-Site Scripting'
        CSRF = 'csrf', 'Cross-Site Request Forgery'
        UNAUTHORIZED_ACCESS = 'unauthorized_access', 'Unauthorized Access'
        SUSPICIOUS_ACTIVITY = 'suspicious_activity', 'Suspicious Activity'
        VULNERABILITY_EXPLOIT = 'vulnerability_exploit', 'Vulnerability Exploitation'
        INSIDER_THREAT = 'insider_threat', 'Insider Threat'
        PHISHING = 'phishing', 'Phishing Attempt'
        RANSOMWARE = 'ransomware', 'Ransomware'
    
    class Severity(models.TextChoices):
        INFO = 'info', 'Informational'
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'
    
    class Status(models.TextChoices):
        DETECTED = 'detected', 'Detected'
        INVESTIGATING = 'investigating', 'Under Investigation'
        CONTAINED = 'contained', 'Contained'
        MITIGATED = 'mitigated', 'Mitigated'
        RESOLVED = 'resolved', 'Resolved'
        FALSE_POSITIVE = 'false_positive', 'False Positive'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    threat_type = models.CharField(max_length=30, choices=ThreatType.choices)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DETECTED)
    title = models.CharField(max_length=255)
    description = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    affected_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_threats'
    )
    detection_time = models.DateTimeField(auto_now_add=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    detection_source = models.CharField(max_length=100)  # IDS, antivirus, manual, etc.
    threat_indicators = models.JSONField(default=dict)  # IOCs, signatures, etc.
    response_actions = models.JSONField(default=list)  # Actions taken
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_threats'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_threats'
    )
    resolution_notes = models.TextField(blank=True)
    
    class Meta:
        verbose_name = 'Security Threat'
        verbose_name_plural = 'Security Threats'
        ordering = ['-detection_time']
        indexes = [
            models.Index(fields=['threat_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['detection_time']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['affected_user']),
        ]
    
    def __str__(self):
        return f"{self.get_threat_type_display()} - {self.title}"


class VulnerabilityAssessment(models.Model):
    """Model for vulnerability scanning results."""
    
    class ScanType(models.TextChoices):
        NETWORK = 'network', 'Network Scan'
        WEB_APP = 'web_app', 'Web Application Scan'
        DATABASE = 'database', 'Database Scan'
        INFRASTRUCTURE = 'infrastructure', 'Infrastructure Scan'
        CODE = 'code', 'Code Analysis'
        DEPENDENCY = 'dependency', 'Dependency Scan'
        CONFIGURATION = 'configuration', 'Configuration Review'
        COMPLIANCE = 'compliance', 'Compliance Scan'
    
    class Status(models.TextChoices):
        SCHEDULED = 'scheduled', 'Scheduled'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
        CANCELLED = 'cancelled', 'Cancelled'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.SCHEDULED)
    target = models.CharField(max_length=255)  # IP, URL, or system identifier
    scan_profile = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.IntegerField(null=True, blank=True)
    scanner_tool = models.CharField(max_length=100)  # OWASP ZAP, Nessus, etc.
    scanner_version = models.CharField(max_length=50, blank=True)
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    scan_config = models.JSONField(default=dict)
    raw_results = models.JSONField(default=dict)
    processed_results = models.JSONField(default=dict)
    total_vulnerabilities = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)
    report_file_path = models.CharField(max_length=500, blank=True)
    
    class Meta:
        verbose_name = 'Vulnerability Assessment'
        verbose_name_plural = 'Vulnerability Assessments'
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['scan_type']),
            models.Index(fields=['status']),
            models.Index(fields=['started_at']),
            models.Index(fields=['target']),
        ]
    
    def __str__(self):
        return f"{self.get_scan_type_display()} - {self.target}"


class Vulnerability(models.Model):
    """Model for individual vulnerabilities."""
    
    class Severity(models.TextChoices):
        INFO = 'info', 'Informational'
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'
    
    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        IN_PROGRESS = 'in_progress', 'In Progress'
        FIXED = 'fixed', 'Fixed'
        ACCEPTED_RISK = 'accepted_risk', 'Accepted Risk'
        FALSE_POSITIVE = 'false_positive', 'False Positive'
        WONT_FIX = 'wont_fix', 'Won\'t Fix'
        DUPLICATE = 'duplicate', 'Duplicate'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(
        VulnerabilityAssessment,
        on_delete=models.CASCADE,
        related_name='vulnerabilities'
    )
    cve_id = models.CharField(max_length=20, blank=True)  # CVE-2023-1234
    cwe_id = models.CharField(max_length=10, blank=True)  # CWE-89
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=Severity.choices)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    affected_component = models.CharField(max_length=255)
    location = models.CharField(max_length=500)  # File path, URL, etc.
    proof_of_concept = models.TextField(blank=True)
    remediation_advice = models.TextField(blank=True)
    references = models.JSONField(default=list)  # URLs, advisories, etc.
    first_discovered = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    fixed_at = models.DateTimeField(null=True, blank=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    risk_rating = models.CharField(max_length=10, blank=True)
    exploitability = models.CharField(max_length=10, blank=True)
    asset_criticality = models.CharField(max_length=10, blank=True)
    
    class Meta:
        verbose_name = 'Vulnerability'
        verbose_name_plural = 'Vulnerabilities'
        ordering = ['-cvss_score', '-first_discovered']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['first_discovered']),
            models.Index(fields=['assessment']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.get_severity_display()})"


class SecurityIncident(models.Model):
    """Model for security incident management."""
    
    class IncidentType(models.TextChoices):
        DATA_BREACH = 'data_breach', 'Data Breach'
        SYSTEM_COMPROMISE = 'system_compromise', 'System Compromise'
        MALWARE_INFECTION = 'malware_infection', 'Malware Infection'
        PHISHING_ATTACK = 'phishing_attack', 'Phishing Attack'
        INSIDER_THREAT = 'insider_threat', 'Insider Threat'
        DDOS_ATTACK = 'ddos_attack', 'DDoS Attack'
        UNAUTHORIZED_ACCESS = 'unauthorized_access', 'Unauthorized Access'
        POLICY_VIOLATION = 'policy_violation', 'Policy Violation'
        PHYSICAL_SECURITY = 'physical_security', 'Physical Security'
        OTHER = 'other', 'Other'
    
    class Priority(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'
    
    class Status(models.TextChoices):
        REPORTED = 'reported', 'Reported'
        ACKNOWLEDGED = 'acknowledged', 'Acknowledged'
        INVESTIGATING = 'investigating', 'Under Investigation'
        CONTAINMENT = 'containment', 'Containment'
        ERADICATION = 'eradication', 'Eradication'
        RECOVERY = 'recovery', 'Recovery'
        POST_INCIDENT = 'post_incident', 'Post-Incident Analysis'
        CLOSED = 'closed', 'Closed'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident_id = models.CharField(max_length=50, unique=True)  # INC-2024-001
    incident_type = models.CharField(max_length=25, choices=IncidentType.choices)
    priority = models.CharField(max_length=10, choices=Priority.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.REPORTED)
    title = models.CharField(max_length=255)
    description = models.TextField()
    discovered_at = models.DateTimeField()
    reported_at = models.DateTimeField(auto_now_add=True)
    reported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reported_incidents'
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_incidents'
    )
    team_members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='incident_team_memberships'
    )
    affected_systems = models.JSONField(default=list)
    affected_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='security_incidents'
    )
    impact_assessment = models.TextField(blank=True)
    containment_actions = models.TextField(blank=True)
    eradication_actions = models.TextField(blank=True)
    recovery_actions = models.TextField(blank=True)
    lessons_learned = models.TextField(blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    related_threats = models.ManyToManyField(SecurityThreat, blank=True)
    related_vulnerabilities = models.ManyToManyField(Vulnerability, blank=True)
    
    class Meta:
        verbose_name = 'Security Incident'
        verbose_name_plural = 'Security Incidents'
        ordering = ['-reported_at']
        indexes = [
            models.Index(fields=['incident_type']),
            models.Index(fields=['priority']),
            models.Index(fields=['status']),
            models.Index(fields=['reported_at']),
            models.Index(fields=['incident_id']),
        ]
    
    def __str__(self):
        return f"{self.incident_id} - {self.title}"


class NetworkMonitor(models.Model):
    """Model for network monitoring alerts."""
    
    class AlertType(models.TextChoices):
        SUSPICIOUS_TRAFFIC = 'suspicious_traffic', 'Suspicious Traffic'
        BANDWIDTH_ANOMALY = 'bandwidth_anomaly', 'Bandwidth Anomaly'
        UNAUTHORIZED_ACCESS = 'unauthorized_access', 'Unauthorized Access'
        PORT_SCAN = 'port_scan', 'Port Scan'
        MALICIOUS_IP = 'malicious_ip', 'Malicious IP'
        DNS_ANOMALY = 'dns_anomaly', 'DNS Anomaly'
        CONNECTION_ANOMALY = 'connection_anomaly', 'Connection Anomaly'
        FAILED_CONNECTION = 'failed_connection', 'Failed Connection'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert_type = models.CharField(max_length=25, choices=AlertType.choices)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=10, choices=SecurityThreat.Severity.choices)
    description = models.TextField()
    raw_data = models.JSONField(default=dict)
    geographic_info = models.JSONField(default=dict)
    threat_intelligence = models.JSONField(default=dict)
    is_false_positive = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = 'Network Monitor Alert'
        verbose_name_plural = 'Network Monitor Alerts'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['alert_type']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['severity']),
        ]


class FileIntegrityMonitor(models.Model):
    """Model for file integrity monitoring."""
    
    class ChangeType(models.TextChoices):
        CREATED = 'created', 'File Created'
        MODIFIED = 'modified', 'File Modified'
        DELETED = 'deleted', 'File Deleted'
        MOVED = 'moved', 'File Moved'
        PERMISSIONS_CHANGED = 'permissions_changed', 'Permissions Changed'
        OWNERSHIP_CHANGED = 'ownership_changed', 'Ownership Changed'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_path = models.TextField()
    change_type = models.CharField(max_length=20, choices=ChangeType.choices)
    timestamp = models.DateTimeField(auto_now_add=True)
    old_checksum = models.CharField(max_length=128, blank=True)
    new_checksum = models.CharField(max_length=128, blank=True)
    old_size = models.BigIntegerField(null=True, blank=True)
    new_size = models.BigIntegerField(null=True, blank=True)
    old_permissions = models.CharField(max_length=10, blank=True)
    new_permissions = models.CharField(max_length=10, blank=True)
    user_context = models.CharField(max_length=255, blank=True)
    process_name = models.CharField(max_length=255, blank=True)
    is_critical_file = models.BooleanField(default=False)
    is_authorized_change = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = 'File Integrity Monitor'
        verbose_name_plural = 'File Integrity Monitors'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['file_path']),
            models.Index(fields=['change_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['is_critical_file']),
        ]


class SecurityConfiguration(models.Model):
    """Model for security configuration settings."""
    
    class ConfigType(models.TextChoices):
        FIREWALL = 'firewall', 'Firewall Rules'
        IDS_IPS = 'ids_ips', 'IDS/IPS Settings'
        ANTIVIRUS = 'antivirus', 'Antivirus Configuration'
        BACKUP = 'backup', 'Backup Settings'
        MONITORING = 'monitoring', 'Monitoring Configuration'
        ACCESS_CONTROL = 'access_control', 'Access Control'
        ENCRYPTION = 'encryption', 'Encryption Settings'
        LOGGING = 'logging', 'Logging Configuration'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    config_type = models.CharField(max_length=20, choices=ConfigType.choices)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    configuration = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    
    class Meta:
        verbose_name = 'Security Configuration'
        verbose_name_plural = 'Security Configurations'
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['config_type']),
            models.Index(fields=['is_active']),
        ]


class ComplianceReport(models.Model):
    """Model for security compliance reports."""
    
    class ReportType(models.TextChoices):
        HIPAA = 'hipaa', 'HIPAA Compliance'
        SOC2 = 'soc2', 'SOC 2 Compliance'
        GDPR = 'gdpr', 'GDPR Compliance'
        ISO27001 = 'iso27001', 'ISO 27001 Compliance'
        NIST = 'nist', 'NIST Cybersecurity Framework'
        CUSTOM = 'custom', 'Custom Compliance'
    
    class Status(models.TextChoices):
        GENERATING = 'generating', 'Generating'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_type = models.CharField(max_length=15, choices=ReportType.choices)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.GENERATING)
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    report_data = models.JSONField(default=dict)
    file_path = models.CharField(max_length=500, blank=True)
    compliance_score = models.FloatField(null=True, blank=True)
    total_controls = models.IntegerField(default=0)
    passed_controls = models.IntegerField(default=0)
    failed_controls = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = 'Compliance Report'
        verbose_name_plural = 'Compliance Reports'
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['report_type']),
            models.Index(fields=['generated_at']),
            models.Index(fields=['status']),
        ]
