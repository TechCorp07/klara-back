"""
Base models for FHIR resources.
Provides common functionality for all FHIR resources.
"""
from django.db import models
import uuid


class FHIRBaseModel(models.Model):
    """
    Base model for all FHIR resources.
    Includes common fields and functionality.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identifier = models.CharField(max_length=255, unique=True, help_text="Unique identifier for this resource")
    version = models.CharField(max_length=50, default="1", help_text="Version of this resource")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # FHIR metadata
    meta = models.JSONField(default=dict, blank=True, help_text="Metadata about the resource")
    text = models.JSONField(default=dict, blank=True, help_text="Text summary of the resource")
    contained = models.JSONField(default=list, blank=True, help_text="Contained resources")
    extension = models.JSONField(default=list, blank=True, help_text="Additional content defined by implementations")
    
    class Meta:
        abstract = True
        ordering = ['-updated_at']
        
    def to_fhir(self):
        """
        Convert the Django model to a FHIR resource.
        To be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement to_fhir()")
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR resource.
        To be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement from_fhir()")
