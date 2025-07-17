"""
Models for FHIR Organization resource.
Represents a formally or informally recognized grouping of people or organizations.
"""
from django.db import models
from fhir.models.base import FHIRBaseModel


class FHIROrganization(FHIRBaseModel):
    """
    FHIR Organization resource model.
    Represents a group of people or organizations with a common purpose.
    """
    # Basic information
    name = models.CharField(max_length=255, help_text="Organization name")
    alias = models.JSONField(default=list, blank=True, help_text="Alternative names for the organization")
    
    # Type and classification
    type = models.CharField(
        max_length=50,
        choices=[
            ('prov', 'Healthcare Provider'),
            ('dept', 'Hospital Department'),
            ('team', 'Organizational Team'),
            ('govt', 'Government'),
            ('ins', 'Insurance Company'),
            ('pay', 'Payer'),
            ('edu', 'Educational Institution'),
            ('reli', 'Religious Institution'),
            ('crs', 'Clinical Research Sponsor'),
            ('cg', 'Community Group'),
            ('bus', 'Non-Healthcare Business'),
            ('other', 'Other')
        ],
        default='prov',
        help_text="Organization type"
    )
    
    # Contact information
    telecom = models.JSONField(default=list, blank=True, help_text="Contact details (phone, email, etc.)")
    address = models.JSONField(default=list, blank=True, help_text="Addresses")
    
    # FHIR specific fields
    active = models.BooleanField(default=True, help_text="Whether this organization's record is in active use")
    part_of = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sub_organizations',
        help_text="The organization of which this organization forms a part"
    )
    
    # Additional information
    contact = models.JSONField(default=list, blank=True, help_text="Contact for the organization")
    endpoint = models.JSONField(default=list, blank=True, help_text="Technical endpoints providing access to services")
    
    class Meta:
        verbose_name = "FHIR Organization"
        verbose_name_plural = "FHIR Organizations"
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['type']),
            models.Index(fields=['active']),
        ]
    
    def __str__(self):
        return f"Organization: {self.name}"
    
    def to_fhir(self):
        """
        Convert the Django model to a FHIR Organization resource.
        """
        resource = {
            "resourceType": "Organization",
            "id": str(self.id),
            "identifier": [{"value": self.identifier}],
            "active": self.active,
            "name": self.name,
            "alias": self.alias,
            "telecom": self.telecom,
            "address": self.address,
            "contact": self.contact,
            "endpoint": self.endpoint,
            "meta": self.meta,
            "text": self.text,
            "extension": self.extension,
        }
        
        if self.type:
            resource["type"] = [{"coding": [{"code": self.type}]}]
            
        if self.part_of:
            resource["partOf"] = {
                "reference": f"Organization/{self.part_of.id}",
                "display": self.part_of.name
            }
            
        return resource
    
    @classmethod
    def from_fhir(cls, fhir_dict):
        """
        Create a Django model from a FHIR Organization resource.
        """
        if fhir_dict.get("resourceType") != "Organization":
            raise ValueError("Resource type must be Organization")
        
        # Extract identifier
        identifier = None
        if "identifier" in fhir_dict and len(fhir_dict["identifier"]) > 0:
            identifier = fhir_dict["identifier"][0].get("value")
            
        # Extract type
        type_code = 'other'
        if "type" in fhir_dict and len(fhir_dict["type"]) > 0:
            if "coding" in fhir_dict["type"][0] and len(fhir_dict["type"][0]["coding"]) > 0:
                type_code = fhir_dict["type"][0]["coding"][0].get("code", 'other')
        
        # Create or update organization
        organization, created = cls.objects.update_or_create(
            identifier=identifier or str(fhir_dict.get("id", "")),
            defaults={
                "name": fhir_dict.get("name", ""),
                "alias": fhir_dict.get("alias", []),
                "type": type_code,
                "telecom": fhir_dict.get("telecom", []),
                "address": fhir_dict.get("address", []),
                "contact": fhir_dict.get("contact", []),
                "endpoint": fhir_dict.get("endpoint", []),
                "active": fhir_dict.get("active", True),
                "meta": fhir_dict.get("meta", {}),
                "text": fhir_dict.get("text", {}),
                "extension": fhir_dict.get("extension", []),
            }
        )
        
        # Handle part_of relationship
        if "partOf" in fhir_dict and "reference" in fhir_dict["partOf"]:
            reference = fhir_dict["partOf"]["reference"]
            if reference.startswith("Organization/"):
                part_of_id = reference.split("/")[1]
                try:
                    part_of = cls.objects.get(id=part_of_id)
                    organization.part_of = part_of
                    organization.save()
                except cls.DoesNotExist:
                    pass
        
        return organization
