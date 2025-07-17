# urls.py in healthcare app - Create this file

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    MedicalRecordViewSet, MedicationViewSet, MedicationIntakeViewSet, AllergyViewSet, 
    ConditionViewSet, ConditionFlareViewSet, SymptomViewSet, ImmunizationViewSet, 
    LabTestViewSet, LabResultViewSet, VitalSignViewSet, TreatmentViewSet, 
    FamilyHistoryViewSet, HealthDataConsentViewSet, HealthDataAuditLogViewSet, 
    EHRIntegrationViewSet, WearableIntegrationViewSet, RareConditionRegistryViewSet,
    ReferralNetworkViewSet
)

router = DefaultRouter()
router.register(r'medical-records', MedicalRecordViewSet)
router.register(r'medications', MedicationViewSet)
router.register(r'medication-intakes', MedicationIntakeViewSet)
router.register(r'allergies', AllergyViewSet)
router.register(r'conditions', ConditionViewSet)
router.register(r'condition-flares', ConditionFlareViewSet)
router.register(r'symptoms', SymptomViewSet)
router.register(r'immunizations', ImmunizationViewSet)
router.register(r'lab-tests', LabTestViewSet)
router.register(r'lab-results', LabResultViewSet)
router.register(r'vital-signs', VitalSignViewSet)
router.register(r'treatments', TreatmentViewSet)
router.register(r'family-history', FamilyHistoryViewSet)
router.register(r'health-data-consents', HealthDataConsentViewSet)
router.register(r'audit-logs', HealthDataAuditLogViewSet)
router.register(r'ehr-integrations', EHRIntegrationViewSet)
router.register(r'wearable-integrations', WearableIntegrationViewSet)
router.register(r'rare-conditions', RareConditionRegistryViewSet)
router.register(r'referral-network', ReferralNetworkViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
