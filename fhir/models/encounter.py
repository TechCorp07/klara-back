"""
Models for FHIR Encounter resource.
Represents an interaction between a patient and healthcare provider(s).
"""
from django.db import models
from fhir.models.base import FHIRBaseModel
from fhir.models.patient import FHIRPatient


class FHIREncounter(FHIRBaseModel):
    """
    FHIR Encounter resource model.
    Represents an interaction between a patient and healthcare provider(s).
    """
    # Subject of the encounter
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.CASCADE,
        related_name='encounters',
        help_text="Patient involved in the encounter"
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('planned', 'Planned'),
            ('arrived', 'Arrived'),
            ('triaged', 'Triaged'),
            ('in-progress', 'In Progress'),
            ('onleave', 'On Leave'),
            ('finished', 'Finished'),
            ('cancelled', 'Cancelled'),
            ('entered-in-error', 'Entered in Error'),
            ('unknown', 'Unknown')
        ],
        default='planned',
        help_text="Status of the encounter"
    )
    
    # Class (type of encounter)
    class_code = models.CharField(
        max_length=20,
        choices=[
            ('ambulatory', 'Ambulatory'),
            ('emergency', 'Emergency'),
            ('home', 'Home'),
            ('inpatient', 'Inpatient'),
            ('virtual', 'Virtual'),
            ('other', 'Other')
        ],
        default='virtual',
        help_text="Classification of the encounter"
    )
    
    # Timing information
    start = models.DateTimeField(help_text="Start time of the encounter")
    end = models.DateTimeField(null=True, blank=True, help_text="End time of the encounter")
    
    # Type of encounter
    type_code = models.CharField(max_length=100, blank=True, help_text="Type of encounter (SNOMED CT code)")
    type_display = models.CharField(max_length=255, blank=True, help_text="Human-readable description of the encounter type")
    
    # Service type
    service_type = models.CharField(max_length=100, blank=True, help_text="Specific type of service")
    
    # Priority
    priority = models.CharField(
        max_length=20,
        choices=[
            ('routine', 'Routine'),
            ('urgent', 'Urgent'),
            ('asap', 'ASAP'),
            ('stat', 'Stat')
        ],
        default='routine',
        help_text="Priority of the encounter"
    )
    
    # Participants
    participants = models.JSONField(default=list, blank=True, help_text="List of participants in the encounter")
    
    # Location
    location = models.CharField(max_length=255, blank=True, help_text="Location of the encounter")
    
    # Additional information
    reason_code = models.CharField(max_length=100, blank=True, help_text="Reason for the encounter")
    reason_display = models.CharField(max_length=255, blank=True, help_text="Human-readable description of the reason")
    
    # Telemedicine-specific fields
    is_telemedicine = models.BooleanField(default=True, help_text="Whether this is a telemedicine encounter")
    telemedicine_platform = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ('zoom', 'Zoom'),
            ('webex', 'Webex'),
            ('teams', 'Microsoft Teams'),
            ('google-meet', 'Google Meet'),
            ('custom', 'Custom Platform'),
            ('other', 'Other')
        ],
        help_text="Telemedicine platform used"
    )
    
    # Video session information
    video_url = models.URLField(blank=True, help_text="URL for the video session")
    meeting_id = models.CharField(max_length=255, blank=True, help_text="Meeting ID for the video session")
    password = models.CharField(max_length=255, blank=True, help_text="Password for the video session")
    
    # Notes
    notes = models.TextField(blank=True, help_text="Notes about the encounter")
    
    class Meta:
        verbose_name = "FHIR Encounter"
        verbose_name_plural = "FHIR Encounters"
        indexes = [
            models.Index(fields=['patient']),
            models.Index(fields=['status']),
            models.Index(fields=['class_code']),
            models.Index(fields=['start']),
            models.Index(fields=['is_telemedicine']),
        ]
    
    def __str__(self):
        return f"Encounter: {self.get_class_code_display()} for {self.patient.name} on {self.start}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Encounter resource.
        """
        resource = {
            "resourceType": "Encounter",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "status": self.status,
            "class": {
                "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                "code": self.class_code,
                "display": self.get_class_code_display()
            },
            "subject": {
                "reference": f"Patient/{self.patient.id}",
                "display": self.patient.name
            },
            "period": {
                "start": self.start.isoformat()
            },
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        # Add end time if available
        if self.end:
            resource["period"]["end"] = self.end.isoformat()
            
        # Add type if available
        if self.type_code:
            resource["type"] = [
                {
                    "coding": [
                        {
                            "system": "http://snomed.info/sct",
                            "code": self.type_code,
                            "display": self.type_display
                        }
                    ]
                }
            ]
            
        # Add service type if available
        if self.service_type:
            resource["serviceType"] = {
                "coding": [
                    {
                        "code": self.service_type,
                        "display": self.service_type
                    }
                ]
            }
            
        # Add priority if available
        if self.priority:
            resource["priority"] = {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/v3-ActPriority",
                        "code": self.priority,
                        "display": self.get_priority_display()
                    }
                ]
            }
            
        # Add participants if available
        if self.participants:
            resource["participant"] = self.participants
            
        # Add location if available
        if self.location:
            resource["location"] = [
                {
                    "location": {
                        "display": self.location
                    }
                }
            ]
            
        # Add reason if available
        if self.reason_code:
            resource["reasonCode"] = [
                {
                    "coding": [
                        {
                            "code": self.reason_code,
                            "display": self.reason_display
                        }
                    ]
                }
            ]
            
        # Add telemedicine-specific extensions
        if self.is_telemedicine:
            resource["extension"].append({
                "url": "https://klararety.com/fhir/StructureDefinition/is-telemedicine",
                "valueBoolean": True
            })
            
            if self.telemedicine_platform:
                resource["extension"].append({
                    "url": "https://klararety.com/fhir/StructureDefinition/telemedicine-platform",
                    "valueString": self.telemedicine_platform
                })
                
            if self.video_url:
                resource["extension"].append({
                    "url": "https://klararety.com/fhir/StructureDefinition/video-url",
                    "valueUrl": self.video_url
                })
                
            if self.meeting_id:
                resource["extension"].append({
                    "url": "https://klararety.com/fhir/StructureDefinition/meeting-id",
                    "valueString": self.meeting_id
                })
                
        # Add notes if available
        if self.notes:
            resource["note"] = [{"text": self.notes}]
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Encounter resource.
        """
        if fhir_dict.get("resourceType") != "Encounter":
            raise ValueError("Resource type must be Encounter")
        
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
            raise ValueError("Encounter must have a patient reference")
            
        try:
            patient = FHIRPatient.objects.get(id=patient_id)
        except FHIRPatient.DoesNotExist:
            raise ValueError(f"Patient with ID {patient_id} does not exist")
            
        # Extract class information
        class_code = "virtual"
        if "class" in fhir_dict and "code" in fhir_dict["class"]:
            class_code = fhir_dict["class"]["code"]
            
        # Extract timing information
        start = None
        end = None
        
        if "period" in fhir_dict:
            if "start" in fhir_dict["period"]:
                start = fhir_dict["period"]["start"]
            if "end" in fhir_dict["period"]:
                end = fhir_dict["period"]["end"]
                
        if not start:
            raise ValueError("Encounter must have a start time")
            
        # Extract type information
        type_code = ""
        type_display = ""
        
        if "type" in fhir_dict and len(fhir_dict["type"]) > 0:
            if "coding" in fhir_dict["type"][0] and len(fhir_dict["type"][0]["coding"]) > 0:
                coding = fhir_dict["type"][0]["coding"][0]
                type_code = coding.get("code", "")
                type_display = coding.get("display", "")
                
        # Extract service type
        service_type = ""
        if "serviceType" in fhir_dict and "coding" in fhir_dict["serviceType"] and len(fhir_dict["serviceType"]["coding"]) > 0:
            service_type = fhir_dict["serviceType"]["coding"][0].get("code", "")
            
        # Extract priority
        priority = "routine"
        if "priority" in fhir_dict and "coding" in fhir_dict["priority"] and len(fhir_dict["priority"]["coding"]) > 0:
            priority = fhir_dict["priority"]["coding"][0].get("code", "routine")
            
        # Extract participants
        participants = []
        if "participant" in fhir_dict:
            participants = fhir_dict["participant"]
            
        # Extract location
        location = ""
        if "location" in fhir_dict and len(fhir_dict["location"]) > 0:
            if "location" in fhir_dict["location"][0] and "display" in fhir_dict["location"][0]["location"]:
                location = fhir_dict["location"][0]["location"]["display"]
                
        # Extract reason
        reason_code = ""
        reason_display = ""
        
        if "reasonCode" in fhir_dict and len(fhir_dict["reasonCode"]) > 0:
            if "coding" in fhir_dict["reasonCode"][0] and len(fhir_dict["reasonCode"][0]["coding"]) > 0:
                coding = fhir_dict["reasonCode"][0]["coding"][0]
                reason_code = coding.get("code", "")
                reason_display = coding.get("display", "")
                
        # Extract telemedicine-specific information
        is_telemedicine = False
        telemedicine_platform = ""
        video_url = ""
        meeting_id = ""
        password = ""
        
        if "extension" in fhir_dict:
            for extension in fhir_dict["extension"]:
                if extension.get("url") == "https://klararety.com/fhir/StructureDefinition/is-telemedicine":
                    is_telemedicine = extension.get("valueBoolean", False)
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/telemedicine-platform":
                    telemedicine_platform = extension.get("valueString", "")
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/video-url":
                    video_url = extension.get("valueUrl", "")
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/meeting-id":
                    meeting_id = extension.get("valueString", "")
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/password":
                    password = extension.get("valueString", "")
                    
        # Extract notes
        notes = ""
        if "note" in fhir_dict and len(fhir_dict["note"]) > 0:
            notes = fhir_dict["note"][0].get("text", "")
        
        # Create or update encounter
        encounter, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "patient": patient,
                "status": fhir_dict.get("status", "planned"),
                "class_code": class_code,
                "start": start,
                "end": end,
                "type_code": type_code,
                "type_display": type_display,
                "service_type": service_type,
                "priority": priority,
                "participants": participants,
                "location": location,
                "reason_code": reason_code,
                "reason_display": reason_display,
                "is_telemedicine": is_telemedicine,
                "telemedicine_platform": telemedicine_platform,
                "video_url": video_url,
                "meeting_id": meeting_id,
                "password": password,
                "notes": notes,
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        return encounter
