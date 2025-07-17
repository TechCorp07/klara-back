"""
Models for FHIR Communication resource.
Represents a record of communication between healthcare providers and patients.
"""
from django.db import models
from fhir.models.base import FHIRBaseModel
from fhir.models.patient import FHIRPatient


class FHIRCommunication(FHIRBaseModel):
    """
    FHIR Communication resource model.
    Represents a record of communication between healthcare providers and patients.
    """
    # Participants
    sender = models.CharField(max_length=255, help_text="Reference to the sender")
    sender_type = models.CharField(
        max_length=20,
        choices=[
            ('patient', 'Patient'),
            ('practitioner', 'Practitioner'),
            ('organization', 'Organization'),
            ('related-person', 'Related Person'),
            ('device', 'Device')
        ],
        default='practitioner',
        help_text="Type of sender"
    )
    
    recipient = models.CharField(max_length=255, help_text="Reference to the recipient")
    recipient_type = models.CharField(
        max_length=20,
        choices=[
            ('patient', 'Patient'),
            ('practitioner', 'Practitioner'),
            ('organization', 'Organization'),
            ('related-person', 'Related Person'),
            ('device', 'Device')
        ],
        default='patient',
        help_text="Type of recipient"
    )
    
    # Patient reference (for easy querying)
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.CASCADE,
        related_name='communications',
        null=True,
        blank=True,
        help_text="Patient involved in the communication"
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('preparation', 'Preparation'),
            ('in-progress', 'In Progress'),
            ('not-done', 'Not Done'),
            ('on-hold', 'On Hold'),
            ('stopped', 'Stopped'),
            ('completed', 'Completed'),
            ('entered-in-error', 'Entered in Error'),
            ('unknown', 'Unknown')
        ],
        default='completed',
        help_text="Status of the communication"
    )
    
    # Timing information
    sent = models.DateTimeField(help_text="When sent")
    received = models.DateTimeField(null=True, blank=True, help_text="When received")
    
    # Content
    category = models.CharField(
        max_length=50,
        choices=[
            ('alert', 'Alert'),
            ('notification', 'Notification'),
            ('reminder', 'Reminder'),
            ('instruction', 'Instruction'),
            ('summary', 'Summary'),
            ('note', 'Note'),
            ('question', 'Question'),
            ('response', 'Response')
        ],
        default='notification',
        help_text="Category of communication"
    )
    
    subject = models.CharField(max_length=255, blank=True, help_text="Subject line")
    content = models.TextField(help_text="Content of the communication")
    content_type = models.CharField(
        max_length=20,
        choices=[
            ('text', 'Text'),
            ('html', 'HTML'),
            ('markdown', 'Markdown')
        ],
        default='text',
        help_text="Type of content"
    )
    
    # Additional information
    priority = models.CharField(
        max_length=20,
        choices=[
            ('routine', 'Routine'),
            ('urgent', 'Urgent'),
            ('asap', 'ASAP'),
            ('stat', 'Stat')
        ],
        default='routine',
        help_text="Priority of communication"
    )
    
    medium = models.CharField(
        max_length=20,
        choices=[
            ('email', 'Email'),
            ('sms', 'SMS'),
            ('app', 'App Notification'),
            ('phone', 'Phone'),
            ('video', 'Video'),
            ('in-person', 'In Person'),
            ('other', 'Other')
        ],
        default='app',
        help_text="Medium of communication"
    )
    
    # Attachments
    has_attachments = models.BooleanField(default=False, help_text="Whether the communication has attachments")
    attachments = models.JSONField(default=list, blank=True, help_text="Attachments to the communication")
    
    class Meta:
        verbose_name = "FHIR Communication"
        verbose_name_plural = "FHIR Communications"
        indexes = [
            models.Index(fields=['patient']),
            models.Index(fields=['sender']),
            models.Index(fields=['recipient']),
            models.Index(fields=['status']),
            models.Index(fields=['sent']),
            models.Index(fields=['category']),
            models.Index(fields=['medium']),
        ]
    
    def __str__(self):
        return f"Communication: {self.subject or self.category} from {self.sender} to {self.recipient}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Communication resource.
        """
        resource = {
            "resourceType": "Communication",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "status": self.status,
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/communication-category",
                            "code": self.category,
                            "display": self.get_category_display()
                        }
                    ]
                }
            ],
            "priority": self.priority,
            "sent": self.sent.isoformat(),
            "payload": [
                {
                    "contentString": self.content
                }
            ],
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        # Add sender
        resource["sender"] = {
            "reference": f"{self.sender_type.capitalize()}/{self.sender}",
            "display": self.sender
        }
        
        # Add recipient
        resource["recipient"] = [
            {
                "reference": f"{self.recipient_type.capitalize()}/{self.recipient}",
                "display": self.recipient
            }
        ]
        
        # Add subject if available
        if self.subject:
            resource["note"] = [{"text": self.subject}]
            
        # Add received time if available
        if self.received:
            resource["received"] = self.received.isoformat()
            
        # Add medium as extension
        resource["extension"].append({
            "url": "https://klararety.com/fhir/StructureDefinition/communication-medium",
            "valueString": self.medium
        })
        
        # Add content type as extension
        resource["extension"].append({
            "url": "https://klararety.com/fhir/StructureDefinition/content-type",
            "valueString": self.content_type
        })
        
        # Add attachments if available
        if self.has_attachments and self.attachments:
            for attachment in self.attachments:
                resource["payload"].append({
                    "contentAttachment": attachment
                })
                
        # Add patient reference if available
        if self.patient:
            resource["subject"] = {
                "reference": f"Patient/{self.patient.id}",
                "display": self.patient.name
            }
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Communication resource.
        """
        if fhir_dict.get("resourceType") != "Communication":
            raise ValueError("Resource type must be Communication")
        
        # Extract identifier
        identifier = None
        if "identifier" in fhir_dict and len(fhir_dict["identifier"]) > 0:
            identifier = fhir_dict["identifier"][0].get("value")
            
        # Extract sender information
        sender = ""
        sender_type = "practitioner"
        
        if "sender" in fhir_dict and "reference" in fhir_dict["sender"]:
            reference = fhir_dict["sender"]["reference"]
            parts = reference.split("/")
            if len(parts) == 2:
                sender_type = parts[0].lower()
                sender = parts[1]
                
        # Extract recipient information
        recipient = ""
        recipient_type = "patient"
        
        if "recipient" in fhir_dict and len(fhir_dict["recipient"]) > 0:
            if "reference" in fhir_dict["recipient"][0]:
                reference = fhir_dict["recipient"][0]["reference"]
                parts = reference.split("/")
                if len(parts) == 2:
                    recipient_type = parts[0].lower()
                    recipient = parts[1]
                    
        # Extract patient reference
        patient = None
        if "subject" in fhir_dict and "reference" in fhir_dict["subject"]:
            reference = fhir_dict["subject"]["reference"]
            if reference.startswith("Patient/"):
                patient_id = reference.split("/")[1]
                try:
                    patient = FHIRPatient.objects.get(id=patient_id)
                except FHIRPatient.DoesNotExist:
                    pass
                    
        # Extract category
        category = "notification"
        if "category" in fhir_dict and len(fhir_dict["category"]) > 0:
            if "coding" in fhir_dict["category"][0] and len(fhir_dict["category"][0]["coding"]) > 0:
                category = fhir_dict["category"][0]["coding"][0].get("code", "notification")
                
        # Extract content
        content = ""
        if "payload" in fhir_dict and len(fhir_dict["payload"]) > 0:
            if "contentString" in fhir_dict["payload"][0]:
                content = fhir_dict["payload"][0]["contentString"]
                
        # Extract subject
        subject = ""
        if "note" in fhir_dict and len(fhir_dict["note"]) > 0:
            subject = fhir_dict["note"][0].get("text", "")
            
        # Extract medium and content type from extensions
        medium = "app"
        content_type = "text"
        
        if "extension" in fhir_dict:
            for extension in fhir_dict["extension"]:
                if extension.get("url") == "https://klararety.com/fhir/StructureDefinition/communication-medium":
                    medium = extension.get("valueString", "app")
                elif extension.get("url") == "https://klararety.com/fhir/StructureDefinition/content-type":
                    content_type = extension.get("valueString", "text")
                    
        # Extract attachments
        attachments = []
        has_attachments = False
        
        if "payload" in fhir_dict:
            for payload in fhir_dict["payload"]:
                if "contentAttachment" in payload:
                    attachments.append(payload["contentAttachment"])
                    has_attachments = True
        
        # Create or update communication
        communication, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "sender": sender,
                "sender_type": sender_type,
                "recipient": recipient,
                "recipient_type": recipient_type,
                "patient": patient,
                "status": fhir_dict.get("status", "completed"),
                "sent": fhir_dict.get("sent"),
                "received": fhir_dict.get("received"),
                "category": category,
                "subject": subject,
                "content": content,
                "content_type": content_type,
                "priority": fhir_dict.get("priority", "routine"),
                "medium": medium,
                "has_attachments": has_attachments,
                "attachments": attachments,
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        return communication
