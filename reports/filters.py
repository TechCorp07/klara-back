from django_filters import rest_framework as filters
from django.db.models import Q
from .models import (
    ReportConfiguration, Report, Dashboard, DashboardWidget,
    AnalyticsMetric, ReportScheduleLog, DataExport
)

class ReportConfigurationFilter(filters.FilterSet):
    """Filter for ReportConfiguration model."""
    report_type = filters.CharFilter(lookup_expr='exact')
    created_by = filters.NumberFilter(field_name='created_by', lookup_expr='exact')
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = ReportConfiguration
        fields = ['report_type', 'is_public', 'schedule', 'created_by']

class ReportFilter(filters.FilterSet):
    """Filter for Report model."""
    configuration = filters.NumberFilter(field_name='configuration', lookup_expr='exact')
    created_by = filters.NumberFilter(field_name='created_by', lookup_expr='exact')
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = Report
        fields = ['configuration', 'status', 'created_by']

class DashboardFilter(filters.FilterSet):
    """Filter for Dashboard model."""
    owner = filters.NumberFilter(field_name='owner', lookup_expr='exact')
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = Dashboard
        fields = ['owner', 'is_public']

class DashboardWidgetFilter(filters.FilterSet):
    """Filter for DashboardWidget model."""
    dashboard = filters.NumberFilter(field_name='dashboard', lookup_expr='exact')
    widget_type = filters.CharFilter(lookup_expr='exact')
    
    class Meta:
        model = DashboardWidget
        fields = ['dashboard', 'widget_type', 'data_source']

class AnalyticsMetricFilter(filters.FilterSet):
    """Filter for AnalyticsMetric model."""
    created_by = filters.NumberFilter(field_name='created_by', lookup_expr='exact')
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = AnalyticsMetric
        fields = ['is_active', 'created_by', 'data_source']

class ReportScheduleLogFilter(filters.FilterSet):
    """Filter for ReportScheduleLog model."""
    configuration = filters.NumberFilter(field_name='configuration', lookup_expr='exact')
    scheduled_before = filters.DateTimeFilter(field_name='scheduled_time', lookup_expr='lte')
    scheduled_after = filters.DateTimeFilter(field_name='scheduled_time', lookup_expr='gte')
    
    class Meta:
        model = ReportScheduleLog
        fields = ['configuration', 'status', 'scheduled_time']

class DataExportFilter(filters.FilterSet):
    """Filter for DataExport model."""
    user = filters.NumberFilter(field_name='user', lookup_expr='exact')
    export_after = filters.DateTimeFilter(field_name='export_date', lookup_expr='gte')
    export_before = filters.DateTimeFilter(field_name='export_date', lookup_expr='lte')
    
    class Meta:
        model = DataExport
        fields = ['user', 'export_format', 'data_type']
