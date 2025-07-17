from django.utils import timezone
from django.contrib import admin
from django.contrib.admin.utils import flatten_fieldsets
from .models import (
    WearableIntegration, WearableMeasurement, 
    WithingsProfile, WithingsMeasurement, SyncLog
)


class WearableMeasurementReadOnlyInline(admin.TabularInline):
    model = WearableMeasurement  # This is just for the fields and metadata
    verbose_name_plural = "Recent Measurements (View Only)"
    extra = 0
    max_num = 0  # Don't allow new records
    can_delete = False
    
    fields = ('measurement_type', 'value', 'unit', 'measured_at')
    readonly_fields = ('measurement_type', 'value', 'unit', 'measured_at')
    
    # Critical: don't allow any actions that would try to create relationships
    def has_add_permission(self, request, obj=None):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    # This is unused but we keep it to avoid admin errors
    def get_formset(self, *args, **kwargs):
        return super().get_formset(*args, **kwargs)
    
    # Custom template to show measurements without edit controls
    template = 'admin/wearables/measurement_readonly_tabular.html'
    
    # Override this method to return measurements related to the parent object
    def get_queryset(self, request):
        """Return recent measurements for this user."""
        # Just return an empty queryset initially - we'll handle the real data in the view
        return WearableMeasurement.objects.none()
        
    # Actual rendering happens in a custom template


@admin.register(WearableIntegration)
class WearableIntegrationAdmin(admin.ModelAdmin):
    list_display = ('user', 'integration_type', 'connection_status', 'consent_granted', 'last_sync')
    list_filter = ('integration_type', 'status', 'consent_granted', 'created_at')
    search_fields = ('user__username', 'user__email', 'platform_user_id')
    readonly_fields = ('created_at', 'updated_at', 'token_expiry', 'recent_measurements')
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'integration_type', 'status', 'platform_user_id')
        }),
        ('Authentication', {
            'fields': ('token_expiry',),
            'classes': ('collapse',),
        }),
        ('Consent', {
            'fields': ('consent_granted', 'consent_date')
        }),
        ('Data Collection', {
            'fields': (
                'collect_steps', 'collect_heart_rate', 'collect_weight', 
                'collect_sleep', 'collect_blood_pressure', 'collect_oxygen', 
                'collect_blood_glucose', 'collect_activity', 'collect_temperature'
            )
        }),
        ('Recent Measurements', {
            'fields': ('recent_measurements',),
        }),
        ('Sync Information', {
            'fields': ('last_sync', 'sync_frequency')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'settings'),
            'classes': ('collapse',),
        }),
    )
    # We're using a custom readonly field instead of the inline
    # inlines = [WearableMeasurementReadOnlyInline]

    def connection_status(self, obj):
        """Display connection status with color indicators"""
        status_map = {
            'connected': '<span style="color:green;">●</span> Connected',
            'disconnected': '<span style="color:red;">●</span> Disconnected',
            'expired': '<span style="color:orange;">●</span> Token Expired',
            'error': '<span style="color:red;">●</span> Connection Error',
            'pending': '<span style="color:blue;">●</span> Pending',
        }
        return status_map.get(obj.status, obj.get_status_display())
    connection_status.short_description = "Status"
    connection_status.allow_tags = True
    
    def recent_measurements(self, obj):
        """Display recent measurements for this integration's user."""
        if not obj or not obj.user:
            return "No measurements available"
            
        measurements = WearableMeasurement.objects.filter(
            user=obj.user
        ).order_by('-measured_at')[:10]
        
        if not measurements:
            return "No measurements available"
            
        html = '<table class="measurements-table">'
        html += '<tr><th>Type</th><th>Value</th><th>Unit</th><th>Measured At</th></tr>'
        
        for m in measurements:
            html += f'<tr>'
            html += f'<td>{m.get_measurement_type_display()}</td>'
            html += f'<td>{m.value}</td>'
            html += f'<td>{m.unit}</td>'
            html += f'<td>{m.measured_at}</td>'
            html += f'</tr>'
        
        html += '</table>'
        return html
    recent_measurements.short_description = "Recent Measurements"
    recent_measurements.allow_tags = True


@admin.register(WearableMeasurement)
class WearableMeasurementAdmin(admin.ModelAdmin):
    list_display = ('user', 'measurement_type', 'value', 'unit', 'measured_at', 'integration_type')
    list_filter = ('measurement_type', 'integration_type', 'measured_at')
    search_fields = ('user__username', 'user__email', 'device_id')
    readonly_fields = ('created_at',)
    date_hierarchy = 'measured_at'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('user', 'measurement_type', 'value', 'unit', 'measured_at')
        }),
        ('Integration', {
            'fields': ('integration_type', 'external_measurement_id')
        }),
        ('Device Information', {
            'fields': ('device_id', 'device_model')
        }),
        ('Additional Data', {
            'fields': ('additional_data',)
        }),
        ('Blood Pressure', {
            'fields': ('systolic', 'diastolic'),
            'classes': ('collapse',),
        }),
        ('Healthcare Integration', {
            'fields': ('synced_to_healthcare', 'healthcare_record_id'),
            'classes': ('collapse',),
        }),
    )


@admin.register(SyncLog)
class SyncLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'integration_type', 'status', 'start_time', 'end_time', 'duration_seconds', 'measurements_synced')
    list_filter = ('status', 'integration_type', 'start_time')
    search_fields = ('user__username', 'user__email', 'error_message')
    readonly_fields = ('duration_seconds',)
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('user', 'integration_type', 'status')
        }),
        ('Timing', {
            'fields': ('start_time', 'end_time', 'duration_seconds')
        }),
        ('Data Range', {
            'fields': ('data_start_date', 'data_end_date', 'measurements_synced')
        }),
        ('Results', {
            'fields': ('error_message', 'details')
        }),
    )
    
    def duration_seconds(self, obj):
        """Display the duration of the sync operation"""
        if obj.start_time and obj.end_time:
            return (obj.end_time - obj.start_time).total_seconds()
        return None
    duration_seconds.short_description = "Duration (seconds)"


# Also register the legacy Withings models
@admin.register(WithingsProfile)
class WithingsProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'connection_status', 'last_updated')
    search_fields = ('user__username', 'user__email', 'withings_user_id')
    readonly_fields = ('created_at', 'updated_at', 'token_expiry', 'recent_measurements')
    list_filter = ('created_at', 'updated_at')
    # Same approach as WearableIntegrationAdmin - use a custom readonly field
    # inlines = [WearableMeasurementReadOnlyInline]
    
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'withings_user_id')
        }),
        ('Authentication', {
            'fields': ('access_token', 'refresh_token', 'token_expiry'),
        }),
        ('Recent Measurements', {
            'fields': ('recent_measurements',),
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
        }),
    )

    def connection_status(self, obj):
        """Display connection status based on token validity"""
        if not obj.access_token:
            return "Not Connected"
        if obj.token_expiry and obj.token_expiry < timezone.now():
            return "Token Expired"
        return "Connected"
    connection_status.short_description = "Status"

    def last_updated(self, obj):
        return obj.updated_at
    last_updated.short_description = "Last Updated"
    
    def recent_measurements(self, obj):
        """Display recent measurements for this profile's user."""
        if not obj or not obj.user:
            return "No measurements available"
            
        # Check both WearableMeasurement and WithingsMeasurement
        wearable_measurements = WearableMeasurement.objects.filter(
            user=obj.user, 
            integration_type='withings'
        ).order_by('-measured_at')[:5]
        
        withings_measurements = WithingsMeasurement.objects.filter(
            user=obj.user
        ).order_by('-measured_at')[:5]
        
        if not wearable_measurements and not withings_measurements:
            return "No measurements available"
            
        html = '<table class="measurements-table">'
        html += '<tr><th>Type</th><th>Value</th><th>Unit</th><th>Measured At</th><th>Source</th></tr>'
        
        for m in wearable_measurements:
            html += f'<tr>'
            html += f'<td>{m.get_measurement_type_display()}</td>'
            html += f'<td>{m.value}</td>'
            html += f'<td>{m.unit}</td>'
            html += f'<td>{m.measured_at}</td>'
            html += f'<td>Wearable API</td>'
            html += f'</tr>'
            
        for m in withings_measurements:
            html += f'<tr>'
            html += f'<td>{m.get_measurement_type_display()}</td>'
            html += f'<td>{m.value}</td>'
            html += f'<td>{m.unit}</td>'
            html += f'<td>{m.measured_at}</td>'
            html += f'<td>Legacy API</td>'
            html += f'</tr>'
        
        html += '</table>'
        return html
    recent_measurements.short_description = "Recent Measurements"
    recent_measurements.allow_tags = True

    def has_delete_permission(self, request, obj=None):
        """Prevent accidental deletion of profiles"""
        return False


@admin.register(WithingsMeasurement)
class WithingsMeasurementAdmin(admin.ModelAdmin):
    list_display = ('user', 'measurement_type', 'value', 'unit', 'measured_at')
    list_filter = ('measurement_type', 'measured_at')
    search_fields = ('user__username', 'withings_device_id')
    readonly_fields = ('created_at',)
    date_hierarchy = 'measured_at'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')
