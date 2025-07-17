from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    NotificationDelivery, PharmaceuticalDataExport, WearableIntegration, WearableMeasurement, 
    WithingsProfile, WithingsMeasurement, SyncLog
)

User = get_user_model()


class UserBasicSerializer(serializers.ModelSerializer):
    """Simplified user serializer for nested relationships."""
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'role', 'role_display')
        read_only_fields = ('id', 'role_display')


class WearableIntegrationSerializer(serializers.ModelSerializer):
    """Serializer for wearable device integrations."""
    user_details = UserBasicSerializer(source='user', read_only=True)
    integration_type_display = serializers.CharField(source='get_integration_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    days_since_sync = serializers.SerializerMethodField()
    
    class Meta:
        model = WearableIntegration
        fields = (
            'id', 'user', 'user_details', 'integration_type', 'integration_type_display',
            'status', 'status_display', 'platform_user_id', 'consent_granted', 
            'consent_date', 'last_sync', 'days_since_sync', 'sync_frequency',
            'collect_steps', 'collect_heart_rate', 'collect_weight', 'collect_sleep',
            'collect_blood_pressure', 'collect_oxygen', 'collect_blood_glucose',
            'collect_activity', 'collect_temperature', 'created_at', 'updated_at',
            'settings'
        )
        read_only_fields = (
            'id', 'user_details', 'integration_type_display', 'status_display',
            'created_at', 'updated_at', 'last_sync', 'days_since_sync'
        )
        extra_kwargs = {
            'access_token': {'write_only': True},
            'refresh_token': {'write_only': True},
        }
        ref_name = "WearableWearableIntegrationSerializer"
    
    def get_days_since_sync(self, obj):
        """Calculate days since last sync."""
        if not obj.last_sync:
            return None
        from django.utils import timezone
        delta = timezone.now() - obj.last_sync
        return delta.days


class WearableMeasurementSerializer(serializers.ModelSerializer):
    """Serializer for wearable measurements."""
    user_details = UserBasicSerializer(source='user', read_only=True)
    integration_type_display = serializers.CharField(source='get_integration_type_display', read_only=True)
    measurement_type_display = serializers.CharField(source='get_measurement_type_display', read_only=True)
    
    class Meta:
        model = WearableMeasurement
        fields = (
            'id', 'user', 'user_details', 'integration_type', 'integration_type_display',
            'measurement_type', 'measurement_type_display', 'value', 'unit', 'measured_at',
            'device_id', 'device_model', 'additional_data', 'synced_to_healthcare',
            'healthcare_record_id', 'systolic', 'diastolic', 'created_at'
        )
        read_only_fields = (
            'id', 'user_details', 'integration_type_display', 'measurement_type_display',
            'created_at'
        )
        ref_name = "WearableWearableMeasurementSerializer"


class WithingsProfileSerializer(serializers.ModelSerializer):
    """Serializer for Withings profiles (legacy)."""
    class Meta:
        model = WithingsProfile
        fields = ('id', 'user', 'withings_user_id', 'created_at', 'updated_at')
        read_only_fields = ('created_at', 'updated_at')


class WithingsMeasurementSerializer(serializers.ModelSerializer):
    """Serializer for Withings measurements (legacy)."""
    class Meta:
        model = WithingsMeasurement
        fields = ('id', 'user', 'measurement_type', 'value', 'unit', 'measured_at', 'withings_device_id', 'created_at')
        read_only_fields = ('created_at',)


class SyncLogSerializer(serializers.ModelSerializer):
    """Serializer for wearable sync logs."""
    user_details = UserBasicSerializer(source='user', read_only=True)
    integration_type_display = serializers.CharField(source='get_integration_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration_seconds = serializers.ReadOnlyField()
    
    class Meta:
        model = SyncLog
        fields = (
            'id', 'user', 'user_details', 'integration_type', 'integration_type_display',
            'status', 'status_display', 'start_time', 'end_time', 'duration_seconds',
            'measurements_synced', 'data_start_date', 'data_end_date', 'error_message',
            'details'
        )
        read_only_fields = (
            'id', 'user_details', 'integration_type_display', 'status_display',
            'duration_seconds'
        )


class IntegrationConnectSerializer(serializers.Serializer):
    """Serializer for wearable connection response."""
    authorize_url = serializers.URLField(required=False)
    integration_type = serializers.CharField()
    connection_instructions = serializers.CharField(required=False)
    deep_link = serializers.URLField(required=False)
    qr_code = serializers.CharField(required=False)
    mobile_instructions = serializers.CharField(required=False)
    status = serializers.CharField(default="pending")
    message = serializers.CharField(default="Ready to connect")


class IntegrationCallbackSerializer(serializers.Serializer):
    """Serializer for wearable OAuth callback."""
    code = serializers.CharField()
    state = serializers.CharField(required=False)
    integration_type = serializers.CharField()
    error = serializers.CharField(required=False)


class IntegrationConnectionStatusSerializer(serializers.Serializer):
    """Serializer for checking integration connection status."""
    is_connected = serializers.BooleanField()
    status = serializers.CharField()
    status_display = serializers.CharField()
    last_sync = serializers.DateTimeField(allow_null=True)
    next_sync_due = serializers.DateTimeField(allow_null=True)
    measurements_count = serializers.IntegerField()
    message = serializers.CharField()


class IntegrationDataFetchSerializer(serializers.Serializer):
    """Serializer for wearable data fetch response."""
    integration_type = serializers.CharField()
    status = serializers.CharField()
    measurements_synced = serializers.IntegerField()
    data_types_synced = serializers.ListField(child=serializers.CharField())
    sync_started = serializers.DateTimeField()
    sync_completed = serializers.DateTimeField()
    duration_seconds = serializers.FloatField()
    message = serializers.CharField()


class MeasurementSummarySerializer(serializers.Serializer):
    """Serializer for summarizing measurements by type."""
    measurement_type = serializers.CharField()
    measurement_type_display = serializers.CharField()
    count = serializers.IntegerField()
    latest_value = serializers.FloatField(allow_null=True)
    latest_unit = serializers.CharField(allow_null=True)
    latest_date = serializers.DateTimeField(allow_null=True)
    min_value = serializers.FloatField(allow_null=True)
    max_value = serializers.FloatField(allow_null=True)
    avg_value = serializers.FloatField(allow_null=True)


class HealthDataConsentSerializer(serializers.Serializer):
    """Serializer for updating wearable integration consent and preferences."""
    consent_granted = serializers.BooleanField(required=True)
    collect_steps = serializers.BooleanField(required=False, default=True)
    collect_heart_rate = serializers.BooleanField(required=False, default=True)
    collect_weight = serializers.BooleanField(required=False, default=True)
    collect_sleep = serializers.BooleanField(required=False, default=True)
    collect_blood_pressure = serializers.BooleanField(required=False, default=True)
    collect_oxygen = serializers.BooleanField(required=False, default=True)
    collect_blood_glucose = serializers.BooleanField(required=False, default=True)
    collect_activity = serializers.BooleanField(required=False, default=True)
    collect_temperature = serializers.BooleanField(required=False, default=True)
    sync_frequency = serializers.IntegerField(required=False, min_value=1, max_value=168)  # 1 hour to 7 days

    class Meta:
        ref_name = "WearablesHealthDataConsentSerializer"


class PharmaceuticalDataExportSerializer(serializers.ModelSerializer):
    """Serializer for pharmaceutical data exports."""
    
    class Meta:
        model = PharmaceuticalDataExport
        fields = [
            'id', 'pharmaceutical_company', 'patients', 'data_types', 
            'date_range_start', 'date_range_end', 'medication_protocols',
            'status', 'created_at', 'started_at', 'completed_at',
            'records_exported', 'file_size', 'anonymized', 'consent_verified'
        ]
        read_only_fields = [
            'id', 'pharmaceutical_company', 'status', 'created_at', 
            'started_at', 'completed_at', 'records_exported', 'file_size'
        ]

class NotificationDeliverySerializer(serializers.ModelSerializer):
    """Serializer for notification delivery tracking."""
    
    integration_display = serializers.CharField(source='integration.get_integration_type_display', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = NotificationDelivery
        fields = [
            'id', 'integration', 'integration_display', 'user', 'user_email',
            'notification_type', 'title', 'message', 'success', 'sent_at',
            'delivered_at', 'read_at', 'user_response', 'response_time',
            'metadata', 'medication_id', 'appointment_id'
        ]
        read_only_fields = [
            'id', 'integration_display', 'user_email', 'sent_at'
        ]

