from django.contrib import admin
from .models import (
    ReportConfiguration, Report, Dashboard, DashboardWidget,
    AnalyticsMetric, ReportScheduleLog, DataExport
)

@admin.register(ReportConfiguration)
class ReportConfigurationAdmin(admin.ModelAdmin):
    """Admin interface for ReportConfiguration model."""
    list_display = ('name', 'report_type', 'schedule', 'last_run', 'next_run', 'created_by', 'is_public')
    list_filter = ('report_type', 'schedule', 'is_public', 'created_at')
    search_fields = ('name', 'description', 'created_by__username')
    readonly_fields = ('created_at', 'updated_at', 'last_run')
    filter_horizontal = ('recipients',)
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'report_type', 'parameters')
        }),
        ('Scheduling', {
            'fields': ('schedule', 'last_run', 'next_run')
        }),
        ('Access Control', {
            'fields': ('created_by', 'is_public', 'allowed_roles', 'recipients')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def get_readonly_fields(self, request, obj=None):
        """Make created_by read-only except for admins."""
        readonly_fields = list(self.readonly_fields)
        if not request.user.is_superuser and obj is not None:
            readonly_fields.append('created_by')
        return readonly_fields
    
    def save_model(self, request, obj, form, change):
        """Set created_by to current user if creating a new configuration."""
        if not change and not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    """Admin interface for Report model."""
    list_display = ('report_id', 'configuration', 'status', 'started_at', 'completed_at', 'created_by')
    list_filter = ('status', 'created_at', 'configuration__report_type')
    search_fields = ('report_id', 'configuration__name', 'created_by__username')
    readonly_fields = ('report_id', 'status', 'started_at', 'completed_at', 'accessed_count', 'last_accessed', 'error_message', 'created_at')
    
    fieldsets = (
        (None, {
            'fields': ('configuration', 'report_id', 'status')
        }),
        ('Execution Details', {
            'fields': ('started_at', 'completed_at', 'error_message')
        }),
        ('Results', {
            'fields': ('results_json', 'file_path')
        }),
        ('Access Tracking', {
            'fields': ('created_by', 'created_at', 'accessed_count', 'last_accessed')
        }),
    )
    
    def get_readonly_fields(self, request, obj=None):
        """Make created_by read-only except for admins."""
        readonly_fields = list(self.readonly_fields)
        if not request.user.is_superuser and obj is not None:
            readonly_fields.append('created_by')
        return readonly_fields


@admin.register(Dashboard)
class DashboardAdmin(admin.ModelAdmin):
    """Admin interface for Dashboard model."""
    list_display = ('name', 'owner', 'is_public', 'created_at', 'updated_at')
    list_filter = ('is_public', 'created_at')
    search_fields = ('name', 'description', 'owner__username')
    readonly_fields = ('created_at', 'updated_at')
    filter_horizontal = ('shared_with',)
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'layout')
        }),
        ('Access Control', {
            'fields': ('owner', 'is_public', 'shared_with')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def get_readonly_fields(self, request, obj=None):
        """Make owner read-only except for admins."""
        readonly_fields = list(self.readonly_fields)
        if not request.user.is_superuser and obj is not None:
            readonly_fields.append('owner')
        return readonly_fields
    
    def save_model(self, request, obj, form, change):
        """Set owner to current user if creating a new dashboard."""
        if not change and not obj.owner:
            obj.owner = request.user
        super().save_model(request, obj, form, change)


@admin.register(DashboardWidget)
class DashboardWidgetAdmin(admin.ModelAdmin):
    """Admin interface for DashboardWidget model."""
    list_display = ('title', 'dashboard', 'widget_type', 'data_source', 'refresh_interval')
    list_filter = ('widget_type', 'created_at', 'dashboard')
    search_fields = ('title', 'dashboard__name', 'data_source')
    readonly_fields = ('created_at', 'updated_at', 'last_refresh')
    
    fieldsets = (
        (None, {
            'fields': ('dashboard', 'title', 'widget_type')
        }),
        ('Data Configuration', {
            'fields': ('data_source', 'configuration')
        }),
        ('Display Settings', {
            'fields': ('position', 'refresh_interval', 'last_refresh')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at')
        }),
    )


@admin.register(AnalyticsMetric)
class AnalyticsMetricAdmin(admin.ModelAdmin):
    """Admin interface for AnalyticsMetric model."""
    list_display = ('name', 'calculation_method', 'data_source', 'created_by', 'is_active')
    list_filter = ('is_active', 'created_at', 'data_source')
    search_fields = ('name', 'description', 'calculation_method')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'is_active')
        }),
        ('Metric Definition', {
            'fields': ('calculation_method', 'units', 'data_source', 'parameters')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at')
        }),
    )
    
    def get_readonly_fields(self, request, obj=None):
        """Make created_by read-only except for admins."""
        readonly_fields = list(self.readonly_fields)
        if not request.user.is_superuser and obj is not None:
            readonly_fields.append('created_by')
        return readonly_fields
    
    def save_model(self, request, obj, form, change):
        """Set created_by to current user if creating a new metric."""
        if not change and not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(ReportScheduleLog)
class ReportScheduleLogAdmin(admin.ModelAdmin):
    """Admin interface for ReportScheduleLog model."""
    list_display = ('configuration', 'scheduled_time', 'execution_time', 'status', 'report')
    list_filter = ('status', 'scheduled_time')
    search_fields = ('configuration__name', 'error_message')
    readonly_fields = ('created_at',)
    
    fieldsets = (
        (None, {
            'fields': ('configuration', 'scheduled_time', 'execution_time', 'status')
        }),
        ('Report', {
            'fields': ('report', 'error_message')
        }),
        ('Metadata', {
            'fields': ('created_at',)
        }),
    )


@admin.register(DataExport)
class DataExportAdmin(admin.ModelAdmin):
    """Admin interface for DataExport model."""
    list_display = ('user', 'data_type', 'export_format', 'export_date', 'record_count', 'file_size')
    list_filter = ('export_format', 'export_date')
    search_fields = ('user__username', 'data_type', 'export_reason')
    readonly_fields = ('export_date', 'ip_address')
    
    fieldsets = (
        (None, {
            'fields': ('user', 'export_date', 'export_format')
        }),
        ('Data Details', {
            'fields': ('data_type', 'parameters', 'record_count')
        }),
        ('HIPAA Compliance', {
            'fields': ('export_reason', 'ip_address')
        }),
        ('File Details', {
            'fields': ('file_size', 'file_path')
        }),
    )
