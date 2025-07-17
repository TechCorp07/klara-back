# audit/filters.py
from django_filters import rest_framework as filters
from .models import AuditEvent, PHIAccessLog, SecurityAuditLog, AuditExport

class AuditExportFilterSet(filters.FilterSet):
    # Add custom filters if needed
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')

    class Meta:
        model = AuditExport
        fields = ['user', 'status']  # Only include fields that exist in AuditExport