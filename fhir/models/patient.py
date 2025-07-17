"""
Models for FHIR Patient resource.
Maps to existing User model with patient profile.
"""
from django.db import models
from django.conf import settings
from fhir.models.base import FHIRBaseModel


class FHIRPatient(FHIRBaseModel):
    """
    FHIR Patient resource model.
    Represents demographic and other administrative information about an individual receiving care.
    """
    # Link to Django User model
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='fhir_patient',
        null=True,
        blank=True,
        help_text="Link to Django User model"
    )
    
    # Basic demographics
    name = models.CharField(max_length=255, help_text="Patient's full name")
    birth_date = models.DateField(null=True, blank=True, help_text="Patient's date of birth")
    gender = models.CharField(
        max_length=20,
        choices=[
            ('male', 'Male'),
            ('female', 'Female'),
            ('other', 'Other'),
            ('unknown', 'Unknown')
        ],
        default='unknown',
        help_text="Patient's gender"
    )
    
    # Contact information
    telecom = models.JSONField(default=list, blank=True, help_text="Contact details (phone, email, etc.)")
    address = models.JSONField(default=list, blank=True, help_text="Addresses")
    
    # Additional information
    marital_status = models.CharField(max_length=50, blank=True, help_text="Marital status")
    communication = models.JSONField(default=list, blank=True, help_text="Languages and preferred language")
    
    # Medical information
    deceased = models.BooleanField(default=False, help_text="If patient is deceased")
    deceased_date = models.DateTimeField(null=True, blank=True, help_text="Date of death if applicable")
    
    # FHIR specific fields
    active = models.BooleanField(default=True, help_text="Whether this patient's record is in active use")
    multiple_birth = models.BooleanField(default=False, help_text="Whether patient is part of a multiple birth")
    multiple_birth_integer = models.IntegerField(null=True, blank=True, help_text="Order of birth if multiple birth")
    
    # Additional data
    contact = models.JSONField(default=list, blank=True, help_text="Contact parties (e.g. guardian, family)")
    general_practitioner = models.JSONField(default=list, blank=True, help_text="Patient's nominated care provider")
    managing_organization = models.JSONField(default=dict, blank=True, help_text="Organization that is the custodian of the patient record")
    
    class Meta:
        verbose_name = "FHIR Patient"
        verbose_name_plural = "FHIR Patients"
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['birth_date']),
            models.Index(fields=['gender']),
        ]
    
    def __str__(self):
        return f"Patient: {self.name}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Patient resource.
        """
        resource = {
            "resourceType": "Patient",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "active": self.active,
            "name": [{"text": self.name}],
            "gender": self.gender,
            "telecom": self.telecom,
            "address": self.address,
            "contact": self.contact,
            "communication": self.communication,
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        if self.birth_date:
            resource["birthDate"] = self.birth_date.isoformat()
            
        if self.deceased:
            resource["deceasedBoolean"] = True
            if self.deceased_date:
                resource["deceasedDateTime"] = self.deceased_date.isoformat()
        
        if self.multiple_birth:
            if self.multiple_birth_integer:
                resource["multipleBirthInteger"] = self.multiple_birth_integer
            else:
                resource["multipleBirthBoolean"] = True
                
        if self.marital_status:
            resource["maritalStatus"] = {"text": self.marital_status}
            
        if self.general_practitioner:
            resource["generalPractitioner"] = self.general_practitioner
            
        if self.managing_organization:
            resource["managingOrganization"] = self.managing_organization
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Patient resource.
        """
        if fhir_dict.get("resourceType") != "Patient":
            raise ValueError("Resource type must be Patient")
        
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
        
        # Create or update patient
        patient, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "name": name,
                "gender": fhir_dict.get("gender", "unknown"),
                "birth_date": fhir_dict.get("birthDate"),
                "telecom": fhir_dict.get("telecom", []),
                "address": fhir_dict.get("address", []),
                "marital_status": fhir_dict.get("maritalStatus", {}).get("text", ""),
                "communication": fhir_dict.get("communication", []),
                "active": fhir_dict.get("active", True),
                "contact": fhir_dict.get("contact", []),
                "general_practitioner": fhir_dict.get("generalPractitioner", []),
                "managing_organization": fhir_dict.get("managingOrganization", {}),
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        # Handle deceased information
        if "deceasedBoolean" in fhir_dict and fhir_dict["deceasedBoolean"]:
            patient.deceased = True
        elif "deceasedDateTime" in fhir_dict:
            patient.deceased = True
            patient.deceased_date = fhir_dict["deceasedDateTime"]
            
        # Handle multiple birth information
        if "multipleBirthBoolean" in fhir_dict and fhir_dict["multipleBirthBoolean"]:
            patient.multiple_birth = True
        elif "multipleBirthInteger" in fhir_dict:
            patient.multiple_birth = True
            patient.multiple_birth_integer = fhir_dict["multipleBirthInteger"]
            
        patient.save()
        return patient
