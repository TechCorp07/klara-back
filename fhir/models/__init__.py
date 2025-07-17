"""
Models initialization for FHIR module.
Import all models to make them available.
"""

from fhir.models.base import FHIRBaseModel
from fhir.models.patient import FHIRPatient
from fhir.models.practitioner import FHIRPractitioner
from fhir.models.organization import FHIROrganization
from fhir.models.observation import FHIRObservation
from fhir.models.condition import FHIRCondition
from fhir.models.medication import FHIRMedicationStatement
from fhir.models.communication import FHIRCommunication
from fhir.models.encounter import FHIREncounter

# NEW: import the SMART Auth models in your top-level init (optional)
from fhir.models.smart_auth import SMARTAuthRequest, SMARTToken

__all__ = [
    'FHIRBaseModel',
    'FHIRPatient',
    'FHIRPractitioner',
    'FHIROrganization',
    'FHIRObservation',
    'FHIRCondition',
    'FHIRMedicationStatement',
    'FHIRCommunication',
    'FHIREncounter',
    'SMARTAuthRequest',
    'SMARTToken',
]
