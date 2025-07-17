# fhir/models/data_requests.py
from django.db import models
from django.conf import settings
import uuid

class PatientDataRequest(models.Model):
    """Model for tracking patient data requests from external systems."""
    
    class Status(models.TextChoices):
        INITIATED = 'initiated', 'Initiated'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        PARTIALLY_COMPLETED = 'partially_completed', 'Partially Completed'
        FAILED = 'failed', 'Failed'
        CANCELLED = 'cancelled', 'Cancelled'
    
    request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='data_requests',
        limit_choices_to={'role': 'patient'}
    )
    requesting_provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='facilitated_data_requests',
        limit_choices_to={'role': 'provider'}
    )
    
    # Request details
    data_types = models.JSONField(default=list, help_text="Types of data requested")
    date_range_start = models.DateTimeField(null=True, blank=True)
    date_range_end = models.DateTimeField(null=True, blank=True)
    external_systems = models.JSONField(default=list, help_text="External EHR systems to query")
    
    # Status tracking
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.INITIATED)
    pending_requests = models.JSONField(default=list, help_text="Pending sub-requests")
    
    # Consent tracking
    consent_provided = models.BooleanField(default=False)
    consent_date = models.DateTimeField(null=True, blank=True)
    consent_document = models.TextField(blank=True, help_text="Consent form text or URL")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Results
    retrieved_records_count = models.PositiveIntegerField(default=0)
    errors_encountered = models.JSONField(default=list)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['patient', 'status']),
            models.Index(fields=['requesting_provider', 'created_at']),
            models.Index(fields=['request_id']),
        ]
    
    def __str__(self):
        return f"Data request {self.request_id} for {self.patient.email}"


class FamilyHistoryRequest(models.Model):
    """Model for tracking family history data requests."""
    
    request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='family_history_requests',
        limit_choices_to={'role': 'patient'}
    )
    requesting_provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='facilitated_family_requests',
        limit_choices_to={'role': 'provider'}
    )
    
    # Family member information
    family_members_info = models.JSONField(default=list, help_text="Information about family members")
    pending_requests = models.JSONField(default=list, help_text="Pending family data requests")
    
    # Status and consent
    status = models.CharField(max_length=20, choices=PatientDataRequest.Status.choices, default=PatientDataRequest.Status.INITIATED)
    consent_provided = models.BooleanField(default=False)
    consent_date = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Family history request {self.request_id} for {self.patient.email}"


class ExternalDataMapping(models.Model):
    """Model for mapping external system data to FHIR resources."""
    
    # Source information
    external_system = models.CharField(max_length=50, help_text="External EHR system name")
    external_resource_type = models.CharField(max_length=100, help_text="Resource type in external system")
    external_id = models.CharField(max_length=255, help_text="ID in external system")
    
    # FHIR mapping
    fhir_resource_type = models.CharField(max_length=50, help_text="Mapped FHIR resource type")
    fhir_resource_id = models.UUIDField(help_text="ID of FHIR resource in our system")
    
    # Patient context
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='external_data_mappings',
        limit_choices_to={'role': 'patient'}
    )
    
    # Metadata
    mapping_confidence = models.FloatField(default=1.0, help_text="Confidence in mapping accuracy (0-1)")
    last_synced = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['external_system', 'external_id', 'patient']
        indexes = [
            models.Index(fields=['patient', 'external_system']),
            models.Index(fields=['fhir_resource_type', 'fhir_resource_id']),
        ]

