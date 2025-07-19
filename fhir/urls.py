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
from users.enhanced_views import EnhancedFHIRViewSet


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
    # Enhanced FHIR endpoints
    path('export/patient-bundle/', EnhancedFHIRViewSet.as_view({'post': 'export_patient_bundle'}), name='export-patient-bundle'),
    path('import/external-data/', EnhancedFHIRViewSet.as_view({'post': 'import_external_data'}), name='import-external-data'),
]
