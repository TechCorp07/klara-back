"""
URL configuration for FHIR module.
Defines API endpoints for FHIR resources.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from fhir.views import (
    FHIRPatientViewSet,
    FHIRPractitionerViewSet,
    FHIROrganizationViewSet,
    FHIRObservationViewSet,
    FHIRConditionViewSet,
    FHIRMedicationStatementViewSet,
    FHIRCommunicationViewSet,
    FHIREncounterViewSet,
)

router = DefaultRouter()
router.register(r'Patient', FHIRPatientViewSet)
router.register(r'Practitioner', FHIRPractitionerViewSet)
router.register(r'Organization', FHIROrganizationViewSet)
router.register(r'Observation', FHIRObservationViewSet)
router.register(r'Condition', FHIRConditionViewSet)
router.register(r'MedicationStatement', FHIRMedicationStatementViewSet)
router.register(r'Communication', FHIRCommunicationViewSet)
router.register(r'Encounter', FHIREncounterViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
