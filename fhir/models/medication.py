"""
Models for FHIR MedicationStatement resource.
Represents a record of medication being taken by a patient.
"""
from django.db import models
from fhir.models.base import FHIRBaseModel
from fhir.models.patient import FHIRPatient


class FHIRMedicationStatement(FHIRBaseModel):
    """
    FHIR MedicationStatement resource model.
    Represents a record of medication being taken by a patient.
    """
    # Subject of the medication statement
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.CASCADE,
        related_name='medication_statements',
        help_text="Patient who is taking the medication"
    )
    
    # Medication information
    medication = models.CharField(max_length=255, help_text="Name of the medication")
    medication_code = models.CharField(max_length=100, blank=True, help_text="Code for the medication (RxNorm code)")
    medication_system = models.CharField(max_length=100, default="http://www.nlm.nih.gov/research/umls/rxnorm", blank=True, help_text="Code system")
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('active', 'Active'),
            ('completed', 'Completed'),
            ('entered-in-error', 'Entered in Error'),
            ('intended', 'Intended'),
            ('stopped', 'Stopped'),
            ('on-hold', 'On Hold'),
            ('unknown', 'Unknown'),
            ('not-taken', 'Not Taken')
        ],
        default='active',
        help_text="Status of the medication statement"
    )
    
    # Timing information
    effective_date = models.DateTimeField(help_text="When the statement was effective")
    date_asserted = models.DateTimeField(auto_now_add=True, help_text="When the statement was asserted")
    
    # Dosage information
    dosage = models.JSONField(default=list, blank=True, help_text="How the medication is taken")
    
    # Reason for taking
    reason_code = models.CharField(max_length=100, blank=True, help_text="Reason for taking medication")
    reason_reference = models.CharField(max_length=255, blank=True, help_text="Condition or observation that supports why the medication is being taken")
    
    # Additional information
    note = models.TextField(blank=True, help_text="Additional information about the medication statement")
    
    # Adherence tracking
    adherence_status = models.CharField(
        max_length=20,
        choices=[
            ('adherent', 'Adherent'),
            ('partially-adherent', 'Partially Adherent'),
            ('non-adherent', 'Non-Adherent'),
            ('unknown', 'Unknown')
        ],
        default='unknown',
        help_text="Medication adherence status"
    )
    
    adherence_score = models.IntegerField(null=True, blank=True, help_text="Adherence score (0-100)")
    
    class Meta:
        verbose_name = "FHIR Medication Statement"
        verbose_name_plural = "FHIR Medication Statements"
        indexes = [
            models.Index(fields=['patient']),
            models.Index(fields=['medication']),
            models.Index(fields=['status']),
            models.Index(fields=['effective_date']),
            models.Index(fields=['adherence_status']),
        ]
    
    def __str__(self):
        return f"Medication: {self.medication} for {self.patient.name}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR MedicationStatement resource.
        """
        resource = {
            "resourceType": "MedicationStatement",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "status": self.status,
            "subject": {
                "reference": f"Patient/{self.patient.id}",
                "display": self.patient.name
            },
            "effectiveDateTime": self.effective_date.isoformat(),
            "dateAsserted": self.date_asserted.isoformat(),
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        # Add medication information
        if self.medication_code:
            resource["medicationCodeableConcept"] = {
                "coding": [
                    {
                        "system": self.medication_system,
                        "code": self.medication_code,
                        "display": self.medication
                    }
                ],
                "text": self.medication
            }
        else:
            resource["medicationCodeableConcept"] = {
                "text": self.medication
            }
            
        # Add dosage if available
        if self.dosage:
            resource["dosage"] = self.dosage
            
        # Add reason if available
        if self.reason_code:
            resource["reasonCode"] = [
                {
                    "coding": [
                        {
                            "code": self.reason_code,
                            "display": self.reason_code
                        }
                    ]
                }
            ]
            
        if self.reason_reference:
            resource["reasonReference"] = [
                {
                    "reference": self.reason_reference
                }
            ]
            
        # Add note if available
        if self.note:
            resource["note"] = [{"text": self.note}]
            
        # Add adherence information as extensions
        if self.adherence_status != 'unknown':
            resource["extension"].append({
                "url": "https://klararety.com/fhir/StructureDefinition/adherence-status",
                "valueString": self.adherence_status
            })
            
        if self.adherence_score is not None:
            resource["extension"].append({
                "url": "https://klararety.com/fhir/StructureDefinition/adherence-score",
                "valueInteger": self.adherence_score
            })
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR MedicationStatement resource.
        """
        if fhir_dict.get("resourceType") != "MedicationStatement":
            raise ValueError("Resource type must be MedicationStatement")
        
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
            raise ValueError("MedicationStatement must have a patient reference")
            
        try:
            patient = FHIRPatient.objects.get(id=patient_id)
        except FHIRPatient.DoesNotExist:
            raise ValueError(f"Patient with ID {patient_id} does not exist")
            
        # Extract medication information
        medication = ""
        medication_code = ""
        medication_system = "http://www.nlm.nih.gov/research/umls/rxnorm"
        
        if "medicationCodeableConcept" in fhir_dict:
            if "text" in fhir_dict["medicationCodeableConcept"]:
                medication = fhir_dict["medicationCodeableConcept"]["text"]
                
            if "coding" in fhir_dict["medicationCodeableConcept"] and len(fhir_dict["medicationCodeableConcept"]["coding"]) > 0:
                coding = fhir_dict["medicationCodeableConcept"]["coding"][0]
                medication_code = coding.get("code", "")
                medication_system = coding.get("system", "http://www.nlm.nih.gov/research/umls/rxnorm")
                if not medication and "display" in coding:
                    medication = coding["display"]
        
        # Extract reason information
        reason_code = ""
        if "reasonCode" in fhir_dict and len(fhir_dict["reasonCode"]) > 0:
            if "coding" in fhir_dict["reasonCode"][0] and len(fhir_dict["reasonCode"][0]["coding"]) > 0:
                reason_code = fhir_dict["reasonCode"][0]["coding"][0].get("code", "")
                
        reason_reference = ""
        if "reasonReference" in fhir_dict and len(fhir_dict["reasonReference"]) > 0:
            if "reference" in fhir_dict["reasonReference"][0]:
                reason_reference = fhir_dict["reasonReference"][0]["reference"]
                
        # Extract note
        note = ""
        if "note" in fhir_dict and len(fhir_dict["note"]) > 0:
            note = fhir_dict["note"][0].get("text", "")
            
        # Extract adherence information
        adherence_status = "unknown"
        adherence_score = None
        
        if "extension" in fhir_dict:
            for extension in fhir_dict["extension"]:
                if extension.get("url") == "https://klararety.com/fhir/StructureDefinition/adherence-status":
                    adherence_status = extension.get("valueString", "unknown")
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/adherence-score":
                    adherence_score = extension.get("valueInteger")
        
        # Create or update medication statement
        medication_statement, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "patient": patient,
                "medication": medication,
                "medication_code": medication_code,
                "medication_system": medication_system,
                "status": fhir_dict.get("status", "active"),
                "effective_date": fhir_dict.get("effectiveDateTime"),
                "dosage": fhir_dict.get("dosage", []),
                "reason_code": reason_code,
                "reason_reference": reason_reference,
                "note": note,
                "adherence_status": adherence_status,
                "adherence_score": adherence_score,
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        return medication_statement
