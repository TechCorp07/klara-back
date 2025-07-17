"""
Models for FHIR Condition resource.
Represents clinical conditions, problems, diagnoses, or other health matters.
"""
from django.db import models
from fhir.models.base import FHIRBaseModel
from fhir.models.patient import FHIRPatient


class FHIRCondition(FHIRBaseModel):
    """
    FHIR Condition resource model.
    Represents detailed information about a patient's condition, problem, diagnosis, or other health matter.
    """
    # Subject of the condition
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.CASCADE,
        related_name='conditions',
        help_text="Patient who has the condition"
    )
    
    # Basic condition information
    code = models.CharField(max_length=100, help_text="Identification of the condition (SNOMED CT code)")
    code_system = models.CharField(max_length=100, default="http://snomed.info/sct", help_text="Code system")
    code_display = models.CharField(max_length=255, help_text="Human-readable description of the condition")
    
    # Clinical status
    clinical_status = models.CharField(
        max_length=20,
        choices=[
            ('active', 'Active'),
            ('recurrence', 'Recurrence'),
            ('relapse', 'Relapse'),
            ('inactive', 'Inactive'),
            ('remission', 'Remission'),
            ('resolved', 'Resolved')
        ],
        default='active',
        help_text="Clinical status of the condition"
    )
    
    # Verification status
    verification_status = models.CharField(
        max_length=20,
        choices=[
            ('unconfirmed', 'Unconfirmed'),
            ('provisional', 'Provisional'),
            ('differential', 'Differential'),
            ('confirmed', 'Confirmed'),
            ('refuted', 'Refuted'),
            ('entered-in-error', 'Entered in Error')
        ],
        default='confirmed',
        help_text="Verification status of the condition"
    )
    
    # Category
    category = models.CharField(
        max_length=50,
        choices=[
            ('problem-list-item', 'Problem List Item'),
            ('encounter-diagnosis', 'Encounter Diagnosis'),
            ('health-concern', 'Health Concern')
        ],
        default='problem-list-item',
        help_text="Category of the condition"
    )
    
    # Severity
    severity = models.CharField(
        max_length=20,
        choices=[
            ('mild', 'Mild'),
            ('moderate', 'Moderate'),
            ('severe', 'Severe')
        ],
        blank=True,
        help_text="Subjective severity of condition"
    )
    
    # Timing information
    onset_date = models.DateTimeField(null=True, blank=True, help_text="Date when condition first manifested")
    abatement_date = models.DateTimeField(null=True, blank=True, help_text="Date when condition resolved")
    recorded_date = models.DateTimeField(auto_now_add=True, help_text="Date when condition was first recorded")
    
    # Additional information
    body_site = models.JSONField(default=list, blank=True, help_text="Anatomical location")
    note = models.TextField(blank=True, help_text="Additional information about the condition")
    
    # NMOSD-specific fields
    is_nmosd = models.BooleanField(default=False, help_text="Whether this condition is NMOSD")
    nmosd_subtype = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ('aqp4-positive', 'AQP4-IgG Positive'),
            ('mog-positive', 'MOG-IgG Positive'),
            ('double-negative', 'Double Negative (AQP4 and MOG negative)'),
            ('unknown', 'Unknown')
        ],
        help_text="NMOSD subtype"
    )
    
    class Meta:
        verbose_name = "FHIR Condition"
        verbose_name_plural = "FHIR Conditions"
        indexes = [
            models.Index(fields=['patient']),
            models.Index(fields=['code']),
            models.Index(fields=['clinical_status']),
            models.Index(fields=['verification_status']),
            models.Index(fields=['is_nmosd']),
        ]
    
    def __str__(self):
        return f"Condition: {self.code_display} for {self.patient.name}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Condition resource.
        """
        resource = {
            "resourceType": "Condition",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "clinicalStatus": {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                        "code": self.clinical_status,
                        "display": self.get_clinical_status_display()
                    }
                ]
            },
            "verificationStatus": {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-ver-status",
                        "code": self.verification_status,
                        "display": self.get_verification_status_display()
                    }
                ]
            },
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/condition-category",
                            "code": self.category,
                            "display": self.get_category_display()
                        }
                    ]
                }
            ],
            "code": {
                "coding": [
                    {
                        "system": self.code_system,
                        "code": self.code,
                        "display": self.code_display
                    }
                ],
                "text": self.code_display
            },
            "subject": {
                "reference": f"Patient/{self.patient.id}",
                "display": self.patient.name
            },
            "recordedDate": self.recorded_date.isoformat(),
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        # Add severity if available
        if self.severity:
            resource["severity"] = {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-severity",
                        "code": self.severity,
                        "display": self.get_severity_display()
                    }
                ]
            }
            
        # Add onset and abatement if available
        if self.onset_date:
            resource["onsetDateTime"] = self.onset_date.isoformat()
            
        if self.abatement_date:
            resource["abatementDateTime"] = self.abatement_date.isoformat()
            
        # Add body site if available
        if self.body_site:
            resource["bodySite"] = self.body_site
            
        # Add note if available
        if self.note:
            resource["note"] = [{"text": self.note}]
            
        # Add NMOSD-specific extensions if applicable
        if self.is_nmosd:
            resource["extension"].append({
                "url": "https://klararety.com/fhir/StructureDefinition/is-nmosd",
                "valueBoolean": True
            })
            
            if self.nmosd_subtype:
                resource["extension"].append({
                    "url": "https://klararety.com/fhir/StructureDefinition/nmosd-subtype",
                    "valueString": self.nmosd_subtype
                })
                
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Condition resource.
        """
        if fhir_dict.get("resourceType") != "Condition":
            raise ValueError("Resource type must be Condition")
        
        # Extract identifier
        identifier = None
        if "identifier" in fhir_dict and len(fhir_dict["identifier"]) > 0:
            identifier = fhir_dict["identifier"][0].get("value")
            
        # Extract patient reference
        patient_id = None
        if "subject" in fhir_dict and "reference" in fhir_dict["subject"]:
            reference = fhir_dict["subject"]["reference"]
            if reference.startswith("Patient/"):
                patient_id = reference.split("/")[1]
                
        if not patient_id:
            raise ValueError("Condition must have a patient reference")
            
        try:
            patient = FHIRPatient.objects.get(id=patient_id)
        except FHIRPatient.DoesNotExist:
            raise ValueError(f"Patient with ID {patient_id} does not exist")
            
        # Extract code information
        code = ""
        code_system = "http://snomed.info/sct"
        code_display = ""
        
        if "code" in fhir_dict and "coding" in fhir_dict["code"] and len(fhir_dict["code"]["coding"]) > 0:
            coding = fhir_dict["code"]["coding"][0]
            code = coding.get("code", "")
            code_system = coding.get("system", "http://snomed.info/sct")
            code_display = coding.get("display", "")
            
        if not code_display and "text" in fhir_dict.get("code", {}):
            code_display = fhir_dict["code"]["text"]
            
        # Extract clinical status
        clinical_status = "active"
        if "clinicalStatus" in fhir_dict and "coding" in fhir_dict["clinicalStatus"] and len(fhir_dict["clinicalStatus"]["coding"]) > 0:
            clinical_status = fhir_dict["clinicalStatus"]["coding"][0].get("code", "active")
            
        # Extract verification status
        verification_status = "confirmed"
        if "verificationStatus" in fhir_dict and "coding" in fhir_dict["verificationStatus"] and len(fhir_dict["verificationStatus"]["coding"]) > 0:
            verification_status = fhir_dict["verificationStatus"]["coding"][0].get("code", "confirmed")
            
        # Extract category
        category = "problem-list-item"
        if "category" in fhir_dict and len(fhir_dict["category"]) > 0:
            if "coding" in fhir_dict["category"][0] and len(fhir_dict["category"][0]["coding"]) > 0:
                category = fhir_dict["category"][0]["coding"][0].get("code", "problem-list-item")
                
        # Extract severity
        severity = ""
        if "severity" in fhir_dict and "coding" in fhir_dict["severity"] and len(fhir_dict["severity"]["coding"]) > 0:
            severity = fhir_dict["severity"]["coding"][0].get("code", "")
            
        # Extract onset and abatement dates
        onset_date = None
        if "onsetDateTime" in fhir_dict:
            onset_date = fhir_dict["onsetDateTime"]
            
        abatement_date = None
        if "abatementDateTime" in fhir_dict:
            abatement_date = fhir_dict["abatementDateTime"]
            
        # Extract body site
        body_site = []
        if "bodySite" in fhir_dict:
            body_site = fhir_dict["bodySite"]
            
        # Extract note
        note = ""
        if "note" in fhir_dict and len(fhir_dict["note"]) > 0:
            note = fhir_dict["note"][0].get("text", "")
            
        # Extract NMOSD-specific information
        is_nmosd = False
        nmosd_subtype = ""
        
        if "extension" in fhir_dict:
            for extension in fhir_dict["extension"]:
                if extension.get("url") == "https://klararety.com/fhir/StructureDefinition/is-nmosd":
                    is_nmosd = extension.get("valueBoolean", False)
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/nmosd-subtype":
                    nmosd_subtype = extension.get("valueString", "")
        
        # Create or update condition
        condition, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "patient": patient,
                "code": code,
                "code_system": code_system,
                "code_display": code_display,
                "clinical_status": clinical_status,
                "verification_status": verification_status,
                "category": category,
                "severity": severity,
                "onset_date": onset_date,
                "abatement_date": abatement_date,
                "body_site": body_site,
                "note": note,
                "is_nmosd": is_nmosd,
                "nmosd_subtype": nmosd_subtype,
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        return condition
