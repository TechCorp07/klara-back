from django.db import models
from django.conf import settings
from django.utils import timezone
from django_cryptography.fields import encrypt

class WearableIntegration(models.Model):
    """Base model for wearable device integrations."""
    
    class IntegrationType(models.TextChoices):
        WITHINGS = 'withings', 'Withings'
        APPLE_HEALTH = 'apple_health', 'Apple Health'
        GOOGLE_FIT = 'google_fit', 'Google Fit'
        SAMSUNG_HEALTH = 'samsung_health', 'Samsung Health'
        FITBIT = 'fitbit', 'Fitbit'
        GARMIN = 'garmin', 'Garmin'
        OURA = 'oura', 'Oura Ring'
        WHOOP = 'whoop', 'Whoop'
        OTHER = 'other', 'Other'
    
    class ConnectionStatus(models.TextChoices):
        CONNECTED = 'connected', 'Connected'
        DISCONNECTED = 'disconnected', 'Disconnected'
        EXPIRED = 'expired', 'Token Expired'
        ERROR = 'error', 'Connection Error'
        PENDING = 'pending', 'Connection Pending'
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wearables_integrations')
    integration_type = models.CharField(max_length=20, choices=IntegrationType.choices)
    status = models.CharField(max_length=20, choices=ConnectionStatus.choices, default=ConnectionStatus.DISCONNECTED)
    
    # OAuth tokens (encrypted for security)
    access_token = encrypt(models.TextField(blank=True, null=True))
    refresh_token = encrypt(models.TextField(blank=True, null=True))
    token_expiry = models.DateTimeField(null=True, blank=True)
    
    # Platform-specific user ID
    platform_user_id = encrypt(models.CharField(max_length=255, blank=True, null=True))
    
    # Data collection consent
    consent_granted = models.BooleanField(default=False)
    consent_date = models.DateTimeField(null=True, blank=True)
    
    # Data collection preferences
    collect_steps = models.BooleanField(default=True)
    collect_heart_rate = models.BooleanField(default=True)
    collect_weight = models.BooleanField(default=True)
    collect_sleep = models.BooleanField(default=True)
    collect_blood_pressure = models.BooleanField(default=True)
    collect_oxygen = models.BooleanField(default=True)
    collect_blood_glucose = models.BooleanField(default=True)
    collect_activity = models.BooleanField(default=True)
    collect_temperature = models.BooleanField(default=True)
    
    # Sync information
    last_sync = models.DateTimeField(null=True, blank=True)
    sync_frequency = models.IntegerField(default=24, help_text="Hours between automatic syncs")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional settings stored as JSON
    settings = models.JSONField(default=dict, blank=True)
    
    def is_connected(self):
        """Returns True if integration is properly connected."""
        if not self.access_token:
            return False
        
        if self.status != self.ConnectionStatus.CONNECTED:
            return False
            
        if self.token_expiry and self.token_expiry < timezone.now():
            self.status = self.ConnectionStatus.EXPIRED
            self.save(update_fields=['status'])
            return False
            
        return True
    
    def update_status(self):
        """Update the status field based on current connection state."""
        if not self.access_token:
            self.status = self.ConnectionStatus.DISCONNECTED
        elif self.token_expiry and self.token_expiry < timezone.now():
            self.status = self.ConnectionStatus.EXPIRED
        else:
            self.status = self.ConnectionStatus.CONNECTED
        
        self.save(update_fields=['status'])
        return self.status
    
    def needs_sync(self):
        """Returns True if integration is due for a sync based on frequency."""
        if not self.last_sync:
            return True
            
        hours_since_sync = (timezone.now() - self.last_sync).total_seconds() / 3600
        return hours_since_sync >= self.sync_frequency
    
    class Meta:
        unique_together = ('user', 'integration_type')
        ordering = ['-updated_at']
        verbose_name = "Wearable Integration"
        verbose_name_plural = "Wearable Integrations"
    
    def __str__(self):
        return f"{self.get_integration_type_display()} integration for {self.user.username}"


class WithingsProfile(models.Model):
    """Legacy model for Withings user profiles (kept for backwards compatibility)."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='withings_profile')
    withings_user_id = models.CharField(max_length=255)
    access_token = models.CharField(max_length=255)
    refresh_token = models.CharField(max_length=255)
    token_expiry = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def is_connected(self):
        """Returns True if profile has a valid token and it's not expired."""
        return bool(self.access_token and self.refresh_token and self.token_expiry and self.token_expiry > timezone.now())

    def __str__(self):
        return f"Withings profile for {self.user.username}"


class WearableMeasurement(models.Model):
    """Model for wearable measurements from any device."""
    
    class MeasurementType(models.TextChoices):
        WEIGHT = 'weight', 'Weight'
        HEIGHT = 'height', 'Height'
        BODY_FAT = 'body_fat', 'Body Fat'
        HEART_RATE = 'heart_rate', 'Heart Rate'
        BLOOD_PRESSURE = 'blood_pressure', 'Blood Pressure'
        SLEEP = 'sleep', 'Sleep'
        STEPS = 'steps', 'Steps'
        DISTANCE = 'distance', 'Distance'
        CALORIES = 'calories', 'Calories'
        ACTIVE_MINUTES = 'active_minutes', 'Active Minutes'
        TEMPERATURE = 'temperature', 'Temperature'
        OXYGEN_SATURATION = 'oxygen_saturation', 'Oxygen Saturation'
        BLOOD_GLUCOSE = 'blood_glucose', 'Blood Glucose'
        RESPIRATORY_RATE = 'respiratory_rate', 'Respiratory Rate'
        STRESS = 'stress', 'Stress Level'
        ACTIVITY = 'activity', 'Activity'
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wearable_measurements')
    integration_type = models.CharField(max_length=20, choices=WearableIntegration.IntegrationType.choices)
    measurement_type = models.CharField(max_length=20, choices=MeasurementType.choices)
    value = models.FloatField()
    unit = models.CharField(max_length=20)
    measured_at = models.DateTimeField()
    
    # Source device information
    device_id = encrypt(models.CharField(max_length=255, blank=True))
    device_model = encrypt(models.CharField(max_length=255, blank=True))
    
    # Platform-specific measurement ID for deduplication
    external_measurement_id = encrypt(models.CharField(max_length=255, blank=True))
    
    # Additional data that varies by measurement type (e.g., sleep stages, BP systolic/diastolic)
    additional_data = models.JSONField(default=dict, blank=True)
    
    # For direct API sync with healthcare app
    synced_to_healthcare = models.BooleanField(default=False)
    healthcare_record_id = models.CharField(max_length=255, blank=True, null=True)
    
    # For blood pressure specific values
    systolic = models.FloatField(null=True, blank=True)
    diastolic = models.FloatField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-measured_at']
        verbose_name = "Wearable Measurement"
        verbose_name_plural = "Wearable Measurements"
        indexes = [
            models.Index(fields=['user', 'measurement_type', 'measured_at']),
            models.Index(fields=['integration_type', 'external_measurement_id']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['integration_type', 'external_measurement_id'],
                name='unique_external_measurement'
            )
        ]
    
    def __str__(self):
        return f"{self.get_measurement_type_display()} for {self.user.username} at {self.measured_at}"


class WithingsMeasurement(models.Model):
    """Legacy model for Withings measurements (kept for backwards compatibility)."""
    class MeasurementType(models.TextChoices):
        WEIGHT = 'weight', 'Weight'
        HEIGHT = 'height', 'Height'
        FAT_MASS = 'fat_mass', 'Fat Mass'
        HEART_RATE = 'heart_rate', 'Heart Rate'
        BLOOD_PRESSURE = 'blood_pressure', 'Blood Pressure'
        SLEEP = 'sleep', 'Sleep'
        STEPS = 'steps', 'Steps'
        TEMPERATURE = 'temperature', 'Temperature'
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='withings_measurements')
    measurement_type = models.CharField(max_length=20, choices=MeasurementType.choices)
    value = models.FloatField()
    unit = models.CharField(max_length=20)
    measured_at = models.DateTimeField()
    withings_device_id = models.CharField(max_length=255, blank=True)
    withings_measurement_id = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-measured_at']
    
    def __str__(self):
        return f"{self.measurement_type} measurement for {self.user.username}"


class SyncLog(models.Model):
    """Model for tracking wearable data sync operations."""
    
    class SyncStatus(models.TextChoices):
        SUCCESS = 'success', 'Success'
        PARTIAL = 'partial', 'Partial Success'
        FAILED = 'failed', 'Failed'
        SKIPPED = 'skipped', 'Skipped'
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wearable_sync_logs')
    integration_type = models.CharField(max_length=20, choices=WearableIntegration.IntegrationType.choices)
    status = models.CharField(max_length=10, choices=SyncStatus.choices)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    measurements_synced = models.IntegerField(default=0)
    
    # Date range of data synced
    data_start_date = models.DateTimeField(null=True, blank=True)
    data_end_date = models.DateTimeField(null=True, blank=True)
    
    error_message = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-start_time']
    
    def __str__(self):
        return f"{self.get_integration_type_display()} sync for {self.user.username} at {self.start_time}"
    
    @property
    def duration_seconds(self):
        """Calculate the duration of the sync operation in seconds."""
        return (self.end_time - self.start_time).total_seconds()
