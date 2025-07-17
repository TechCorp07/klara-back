from django.db import models
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django_cryptography.fields import encrypt
import uuid

User = get_user_model()

class ReportConfiguration(models.Model):
    """Configuration for reports, defining parameters and schedules."""
    
    class ReportType(models.TextChoices):
        PATIENT_ADHERENCE = 'patient_adherence', _('Patient Medication Adherence')
        PATIENT_VITALS = 'patient_vitals', _('Patient Vitals Trends')
        PROVIDER_PERFORMANCE = 'provider_performance', _('Provider Performance')
        POPULATION_HEALTH = 'population_health', _('Population Health Metrics')
        MEDICATION_EFFICACY = 'medication_efficacy', _('Medication Efficacy')
        PHI_ACCESS = 'phi_access', _('PHI Access Audit')
        CONSENT_ACTIVITY = 'consent_activity', _('Consent Activity')
        TELEMEDICINE_USAGE = 'telemedicine_usage', _('Telemedicine Usage')
        CUSTOM = 'custom', _('Custom Report')
    
    class Schedule(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        ANNUAL = 'annual', _('Annual')
        ONCE = 'once', _('One-time')
        ON_DEMAND = 'on_demand', _('On-demand')
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    report_type = models.CharField(
        max_length=50,
        choices=ReportType.choices,
        default=ReportType.PATIENT_ADHERENCE
    )
    
    # Configuration parameters stored as JSON
    parameters = models.JSONField(default=dict, blank=True)
    
    # Scheduling and delivery
    schedule = models.CharField(
        max_length=20,
        choices=Schedule.choices,
        default=Schedule.ON_DEMAND
    )
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    
    # Access control
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_reports')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(default=False)
    
    # Access roles that can view this report
    allowed_roles = models.JSONField(default=list, blank=True)
    
    # Recipients for scheduled reports
    recipients = models.ManyToManyField(
        User, 
        related_name='subscribed_reports',
        blank=True
    )
    
    def __str__(self):
        return f"{self.name} ({self.get_report_type_display()})"
    
    def clean(self):
        """Validate that parameters match the expected schema for the report type."""
        # This would validate that the parameters JSON matches the expected schema
        # for the specific report type. In a real implementation, this would check 
        # against a schema registry.
        if self.report_type == self.ReportType.PATIENT_ADHERENCE:
            required_fields = ['time_period', 'include_demographics']
            for field in required_fields:
                if field not in self.parameters:
                    raise ValidationError(f"Missing required parameter: {field}")
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Report Configuration'
        verbose_name_plural = 'Report Configurations'


class Report(models.Model):
    """Stored report results generated from a report configuration."""
    
    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        RUNNING = 'running', _('Running')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')
        EXPIRED = 'expired', _('Expired')
    
    configuration = models.ForeignKey(
        ReportConfiguration, 
        on_delete=models.CASCADE,
        related_name='reports'
    )
    
    # Unique identifier for the report
    report_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    
    # Execution details
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Error information if failed
    error_message = models.TextField(blank=True)
    
    # Results storage options
    results_json = encrypt(models.JSONField(null=True, blank=True))
    file_path = models.CharField(max_length=255, blank=True)
    
    # Metadata
    created_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='generated_reports'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Access tracking for HIPAA compliance
    accessed_count = models.IntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Report {self.report_id} - {self.configuration.name}"
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Report'
        verbose_name_plural = 'Reports'


class Dashboard(models.Model):
    """Customizable dashboards containing multiple widgets."""
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Layout configuration
    layout = models.JSONField(default=dict, blank=True)
    
    # Access control
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='dashboards')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(default=False)
    
    # Sharing settings
    shared_with = models.ManyToManyField(
        User, 
        related_name='shared_dashboards',
        blank=True
    )
    
    def __str__(self):
        return f"{self.name} (Owner: {self.owner.username})"
    
    class Meta:
        ordering = ['-created_at']


class DashboardWidget(models.Model):
    """Individual visualization widgets for dashboards."""
    
    class WidgetType(models.TextChoices):
        LINE_CHART = 'line_chart', _('Line Chart')
        BAR_CHART = 'bar_chart', _('Bar Chart')
        PIE_CHART = 'pie_chart', _('Pie Chart')
        TABLE = 'table', _('Data Table')
        METRIC = 'metric', _('Single Metric')
        HEATMAP = 'heatmap', _('Heat Map')
        SCATTER = 'scatter', _('Scatter Plot')
        CUSTOM = 'custom', _('Custom Widget')
    
    dashboard = models.ForeignKey(Dashboard, on_delete=models.CASCADE, related_name='widgets')
    title = models.CharField(max_length=255)
    widget_type = models.CharField(
        max_length=20,
        choices=WidgetType.choices,
        default=WidgetType.LINE_CHART
    )
    
    # Configuration for this widget
    data_source = models.CharField(max_length=255)
    configuration = models.JSONField(default=dict)
    
    # Display settings
    position = models.JSONField(default=dict)  # {x, y, width, height}
    
    # Caching settings
    refresh_interval = models.IntegerField(default=0)  # In minutes, 0 = manual only
    last_refresh = models.DateTimeField(null=True, blank=True)
    
    # Access control
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.title} ({self.get_widget_type_display()})"
    
    class Meta:
        ordering = ['dashboard', 'position']


class AnalyticsMetric(models.Model):
    """Predefined metrics used in analytics dashboards."""
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Metric definition
    calculation_method = models.TextField()
    units = models.CharField(max_length=50, blank=True)
    
    # Data source and parameters
    data_source = models.CharField(max_length=255)
    parameters = models.JSONField(default=dict, blank=True)
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.name} ({self.units})"
    
    class Meta:
        ordering = ['name']


class ReportScheduleLog(models.Model):
    """Log of report generation schedules and executions."""
    
    configuration = models.ForeignKey(
        ReportConfiguration, 
        on_delete=models.CASCADE,
        related_name='schedule_logs'
    )
    
    scheduled_time = models.DateTimeField()
    execution_time = models.DateTimeField(null=True, blank=True)
    
    status = models.CharField(
        max_length=20,
        choices=Report.Status.choices,
        default=Report.Status.PENDING
    )
    
    # Link to the generated report if successful
    report = models.ForeignKey(
        Report, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='schedule_log'
    )
    
    # Error details if failed
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Schedule: {self.configuration.name} - {self.scheduled_time}"
    
    class Meta:
        ordering = ['-scheduled_time']


class DataExport(models.Model):
    """Record of data exports for HIPAA compliance tracking."""
    
    class ExportFormat(models.TextChoices):
        CSV = 'csv', _('CSV')
        EXCEL = 'excel', _('Excel')
        JSON = 'json', _('JSON')
        PDF = 'pdf', _('PDF')
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='data_exports')
    
    # Export details
    export_date = models.DateTimeField(auto_now_add=True)
    export_format = models.CharField(
        max_length=10,
        choices=ExportFormat.choices,
        default=ExportFormat.CSV
    )
    
    # Data scope
    data_type = models.CharField(max_length=100)
    parameters = models.JSONField(default=dict)
    record_count = models.IntegerField(default=0)
    
    # HIPAA compliance tracking
    export_reason = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    # File details
    file_size = models.IntegerField(default=0)  # In bytes
    file_path = models.CharField(max_length=255, blank=True)
    
    def __str__(self):
        return f"{self.data_type} export by {self.user.username} on {self.export_date}"
    
    class Meta:
        ordering = ['-export_date']
        verbose_name = 'Data Export'
        verbose_name_plural = 'Data Exports'
