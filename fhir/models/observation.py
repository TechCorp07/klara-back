"""
Models for FHIR Observation resource.
Maps to wearable measurements and other clinical observations.
"""
from django.db import models
from django.conf import settings
from fhir.models.base import FHIRBaseModel
from fhir.models.patient import FHIRPatient


class FHIRObservation(FHIRBaseModel):
    """
    FHIR Observation resource model.
    Represents measurements and assertions about a patient's health status.
    """
    # Subject of the observation
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.CASCADE,
        related_name='observations',
        help_text="Patient this observation is about"
    )
    
    # Basic observation information
    code = models.CharField(max_length=100, help_text="Type of observation (LOINC or SNOMED CT code)")
    code_system = models.CharField(max_length=100, default="http://loinc.org", help_text="Code system")
    code_display = models.CharField(max_length=255, help_text="Human-readable description of the code")
    
    # Observation value
    value = models.FloatField(null=True, blank=True, help_text="Numeric value of the observation")
    value_string = models.CharField(max_length=255, blank=True, help_text="String value of the observation")
    value_boolean = models.BooleanField(null=True, blank=True, help_text="Boolean value of the observation")
    unit = models.CharField(max_length=50, blank=True, help_text="Unit of the observation value")
    
    # Observation context
    effective_date = models.DateTimeField(help_text="When the observation was made")
    issued = models.DateTimeField(auto_now_add=True, help_text="When the observation was issued")
    
    # Status and category
    status = models.CharField(
        max_length=20,
        choices=[
            ('registered', 'Registered'),
            ('preliminary', 'Preliminary'),
            ('final', 'Final'),
            ('amended', 'Amended'),
            ('corrected', 'Corrected'),
            ('cancelled', 'Cancelled'),
            ('entered-in-error', 'Entered in Error'),
            ('unknown', 'Unknown')
        ],
        default='final',
        help_text="Status of the observation"
    )
    
    category = models.CharField(
        max_length=50,
        choices=[
            ('vital-signs', 'Vital Signs'),
            ('laboratory', 'Laboratory'),
            ('imaging', 'Imaging'),
            ('social-history', 'Social History'),
            ('exam', 'Exam'),
            ('therapy', 'Therapy'),
            ('activity', 'Activity'),
            ('survey', 'Survey'),
            ('neurological', 'Neurological')
        ],
        default='vital-signs',
        help_text="Category of observation"
    )
    
    # Reference ranges
    reference_range_low = models.FloatField(null=True, blank=True, help_text="Lower limit of reference range")
    reference_range_high = models.FloatField(null=True, blank=True, help_text="Upper limit of reference range")
    reference_range_text = models.CharField(max_length=255, blank=True, help_text="Text description of reference range")
    
    # Device information
    device_id = models.CharField(max_length=255, blank=True, help_text="ID of the device that generated the observation")
    device_name = models.CharField(max_length=255, blank=True, help_text="Name of the device that generated the observation")
    
    # Additional data
    component = models.JSONField(default=list, blank=True, help_text="Component observations (e.g., systolic and diastolic BP)")
    
    # For wearable integration
    wearable_source = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ('apple_health', 'Apple Health'),
            ('google_fit', 'Google Fit'),
            ('fitbit', 'Fitbit'),
            ('samsung_health', 'Samsung Health'),
            ('withings', 'Withings'),
            ('garmin', 'Garmin'),
            ('oura', 'Oura Ring'),
            ('whoop', 'Whoop'),
            ('other', 'Other')
        ],
        help_text="Source wearable device platform"
    )
    
    # For NMOSD-specific indicators
    is_nmosd_indicator = models.BooleanField(default=False, help_text="Whether this is a NMOSD-specific indicator")
    nmosd_indicator_type = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ('tremor', 'Tremor'),
            ('gait', 'Gait Analysis'),
            ('balance', 'Balance'),
            ('fatigue', 'Fatigue'),
            ('vision', 'Vision'),
            ('pain', 'Pain'),
            ('spasticity', 'Spasticity'),
            ('other', 'Other')
        ],
        help_text="Type of NMOSD indicator"
    )
    
    class Meta:
        verbose_name = "FHIR Observation"
        verbose_name_plural = "FHIR Observations"
        indexes = [
            models.Index(fields=['patient']),
            models.Index(fields=['code']),
            models.Index(fields=['effective_date']),
            models.Index(fields=['status']),
            models.Index(fields=['category']),
            models.Index(fields=['is_nmosd_indicator']),
        ]
    
    def __str__(self):
        return f"Observation: {self.code_display} for {self.patient.name}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Observation resource.
        """
        resource = {
            "resourceType": "Observation",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "status": self.status,
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/observation-category",
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
            "effectiveDateTime": self.effective_date.isoformat(),
            "issued": self.issued.isoformat(),
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        # Add value based on type
        if self.value is not None:
            resource["valueQuantity"] = {
                "value": self.value,
                "unit": self.unit,
                "system": "http://unitsofmeasure.org",
                "code": self.unit
            }
        elif self.value_string:
            resource["valueString"] = self.value_string
        elif self.value_boolean is not None:
            resource["valueBoolean"] = self.value_boolean
            
        # Add reference range if available
        if self.reference_range_low is not None or self.reference_range_high is not None:
            reference_range = {}
            if self.reference_range_low is not None:
                reference_range["low"] = {
                    "value": self.reference_range_low,
                    "unit": self.unit,
                    "system": "http://unitsofmeasure.org",
                    "code": self.unit
                }
            if self.reference_range_high is not None:
                reference_range["high"] = {
                    "value": self.reference_range_high,
                    "unit": self.unit,
                    "system": "http://unitsofmeasure.org",
                    "code": self.unit
                }
            if self.reference_range_text:
                reference_range["text"] = self.reference_range_text
                
            resource["referenceRange"] = [reference_range]
            
        # Add device information if available
        if self.device_id or self.device_name:
            resource["device"] = {
                "display": self.device_name,
                "identifier": {"value": self.device_id}
            }
            
        # Add component observations if available
        if self.component:
            resource["component"] = self.component
            
        # Add NMOSD-specific extensions if applicable
        if self.is_nmosd_indicator:
            resource["extension"].append({
                "url": "https://klararety.com/fhir/StructureDefinition/nmosd-indicator",
                "valueBoolean": True
            })
            
            if self.nmosd_indicator_type:
                resource["extension"].append({
                    "url": "https://klararety.com/fhir/StructureDefinition/nmosd-indicator-type",
                    "valueString": self.nmosd_indicator_type
                })
                
        # Add wearable source if available
        if self.wearable_source:
            resource["extension"].append({
                "url": "https://klararety.com/fhir/StructureDefinition/wearable-source",
                "valueString": self.wearable_source
            })
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Observation resource.
        """
        if fhir_dict.get("resourceType") != "Observation":
            raise ValueError("Resource type must be Observation")
        
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
            raise ValueError("Observation must have a patient reference")
            
        try:
            patient = FHIRPatient.objects.get(id=patient_id)
        except FHIRPatient.DoesNotExist:
            raise ValueError(f"Patient with ID {patient_id} does not exist")
            
        # Extract code information
        code = ""
        code_system = "http://loinc.org"
        code_display = ""
        
        if "code" in fhir_dict and "coding" in fhir_dict["code"] and len(fhir_dict["code"]["coding"]) > 0:
            coding = fhir_dict["code"]["coding"][0]
            code = coding.get("code", "")
            code_system = coding.get("system", "http://loinc.org")
            code_display = coding.get("display", "")
            
        if not code_display and "text" in fhir_dict.get("code", {}):
            code_display = fhir_dict["code"]["text"]
            
        # Extract category
        category = "vital-signs"
        if "category" in fhir_dict and len(fhir_dict["category"]) > 0:
            if "coding" in fhir_dict["category"][0] and len(fhir_dict["category"][0]["coding"]) > 0:
                category = fhir_dict["category"][0]["coding"][0].get("code", "vital-signs")
                
        # Extract value information
        value = None
        value_string = ""
        value_boolean = None
        unit = ""
        
        if "valueQuantity" in fhir_dict:
            value = fhir_dict["valueQuantity"].get("value")
            unit = fhir_dict["valueQuantity"].get("unit", "")
        elif "valueString" in fhir_dict:
            value_string = fhir_dict["valueString"]
        elif "valueBoolean" in fhir_dict:
            value_boolean = fhir_dict["valueBoolean"]
            
        # Extract reference range
        reference_range_low = None
        reference_range_high = None
        reference_range_text = ""
        
        if "referenceRange" in fhir_dict and len(fhir_dict["referenceRange"]) > 0:
            reference_range = fhir_dict["referenceRange"][0]
            if "low" in reference_range:
                reference_range_low = reference_range["low"].get("value")
            if "high" in reference_range:
                reference_range_high = reference_range["high"].get("value")
            if "text" in reference_range:
                reference_range_text = reference_range["text"]
                
        # Extract device information
        device_id = ""
        device_name = ""
        
        if "device" in fhir_dict:
            if "display" in fhir_dict["device"]:
                device_name = fhir_dict["device"]["display"]
            if "identifier" in fhir_dict["device"] and "value" in fhir_dict["device"]["identifier"]:
                device_id = fhir_dict["device"]["identifier"]["value"]
                
        # Extract NMOSD-specific information
        is_nmosd_indicator = False
        nmosd_indicator_type = ""
        
        if "extension" in fhir_dict:
            for extension in fhir_dict["extension"]:
                if extension.get("url") == "https://klararety.com/fhir/StructureDefinition/nmosd-indicator":
                    is_nmosd_indicator = extension.get("valueBoolean", False)
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/nmosd-indicator-type":
                    nmosd_indicator_type = extension.get("valueString", "")
                    
        # Extract wearable source
        wearable_source = ""
        
        if "extension" in fhir_dict:
            for extension in fhir_dict["extension"]:
                if extension.get("url") == "https://klararety.com/fhir/StructureDefinition/wearable-source":
                    wearable_source = extension.get("valueString", "")
        
        # Create or update observation
        observation, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "patient": patient,
                "code": code,
                "code_system": code_system,
                "code_display": code_display,
                "value": value,
                "value_string": value_string,
                "value_boolean": value_boolean,
                "unit": unit,
                "effective_date": fhir_dict.get("effectiveDateTime"),
                "status": fhir_dict.get("status", "final"),
                "category": category,
                "reference_range_low": reference_range_low,
                "reference_range_high": reference_range_high,
                "reference_range_text": reference_range_text,
                "device_id": device_id,
                "device_name": device_name,
                "component": fhir_dict.get("component", []),
                "is_nmosd_indicator": is_nmosd_indicator,
                "nmosd_indicator_type": nmosd_indicator_type,
                "wearable_source": wearable_source,
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        return observation
