"""
Models for FHIR Practitioner resource.
Maps to existing User model with healthcare provider profile.
"""
from django.db import models
from django.conf import settings
from fhir.models.base import FHIRBaseModel


class FHIRPractitioner(FHIRBaseModel):
    """
    FHIR Practitioner resource model.
    Represents a person who is directly or indirectly involved in the provisioning of healthcare.
    """
    # Link to Django User model
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='fhir_practitioner',
        null=True,
        blank=True,
        help_text="Link to Django User model"
    )
    
    # Basic information
    name = models.CharField(max_length=255, help_text="Practitioner's full name")
    birth_date = models.DateField(null=True, blank=True, help_text="Practitioner's date of birth")
    gender = models.CharField(
        max_length=20,
        choices=[
            ('male', 'Male'),
            ('female', 'Female'),
            ('other', 'Other'),
            ('unknown', 'Unknown')
        ],
        default='unknown',
        help_text="Practitioner's gender"
    )
    
    # Contact information
    telecom = models.JSONField(default=list, blank=True, help_text="Contact details (phone, email, etc.)")
    address = models.JSONField(default=list, blank=True, help_text="Addresses")
    
    # Professional information
    qualification = models.JSONField(default=list, blank=True, help_text="Qualifications, certifications, etc.")
    specialty = models.JSONField(default=list, blank=True, help_text="Specialties")
    
    # FHIR specific fields
    active = models.BooleanField(default=True, help_text="Whether this practitioner's record is in active use")
    communication = models.JSONField(default=list, blank=True, help_text="Languages the practitioner can use in patient communication")
    
    class Meta:
        verbose_name = "FHIR Practitioner"
        verbose_name_plural = "FHIR Practitioners"
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['active']),
        ]
    
    def __str__(self):
        return f"Practitioner: {self.name}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Practitioner resource.
        """
        resource = {
            "resourceType": "Practitioner",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "active": self.active,
            "name": [{"text": self.name}],
            "gender": self.gender,
            "telecom": self.telecom,
            "address": self.address,
            "qualification": self.qualification,
            "communication": self.communication,
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        if self.birth_date:
            resource["birthDate"] = self.birth_date.isoformat()
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Practitioner resource.
        """
        if fhir_dict.get("resourceType") != "Practitioner":
            raise ValueError("Resource type must be Practitioner")
        
        # Extract identifier
        identifier = None
        if "identifier" in fhir_dict and len(fhir_dict["identifier"]) > 0:
            identifier = fhir_dict["identifier"][0].get("value")
            
        # Extract name
        name = ""
        if "name" in fhir_dict and len(fhir_dict["name"]) > 0:
            if "text" in fhir_dict["name"][0]:
                name = fhir_dict["name"][0]["text"]
            elif "given" in fhir_dict["name"][0] and "family" in fhir_dict["name"][0]:
                given = " ".join(fhir_dict["name"][0].get("given", []))
                family = fhir_dict["name"][0].get("family", "")
                name = f"{given} {family}".strip()
        
        # Create or update practitioner
        practitioner, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "name": name,
                "gender": fhir_dict.get("gender", "unknown"),
                "birth_date": fhir_dict.get("birthDate"),
                "telecom": fhir_dict.get("telecom", []),
                "address": fhir_dict.get("address", []),
                "qualification": fhir_dict.get("qualification", []),
                "communication": fhir_dict.get("communication", []),
                "active": fhir_dict.get("active", True),
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        practitioner.save()
        return practitioner
