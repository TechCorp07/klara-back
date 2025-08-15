# urls.py in healthcare app

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
from users.enhanced_views import EnhancedTelemedicineViewSet


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
router.register(r'health-data-consents', HealthDataConsentViewSet, basename='healthdataconsent')
router.register(r'audit-logs', HealthDataAuditLogViewSet)
router.register(r'ehr-integrations', EHRIntegrationViewSet)
router.register(r'wearable-integrations', WearableIntegrationViewSet)
router.register(r'rare-conditions', RareConditionRegistryViewSet)
router.register(r'referral-network', ReferralNetworkViewSet)

urlpatterns = [
    path('medical-records/summary/', MedicalRecordViewSet.as_view({'get': 'get_patient_summary'}), name='medical-records-summary'),
    # Dashboard endpoints
    path('dashboard/patient/', MedicalRecordViewSet.as_view({'get': 'patient_dashboard'}), name='patient-dashboard'),
    path('dashboard/provider/', MedicalRecordViewSet.as_view({'get': 'provider_dashboard'}), name='provider-dashboard'),
    path('dashboard/pharmco/', MedicalRecordViewSet.as_view({'get': 'pharmco_dashboard'}), name='pharmco-dashboard'),
    
    # Enhanced Telemedicine endpoints
    path('telemedicine/smart-scheduling/', EnhancedTelemedicineViewSet.as_view({'post': 'schedule_intelligent_appointment'}), name='smart-telemedicine-scheduling'),
    path('telemedicine/provider-dashboard/', EnhancedTelemedicineViewSet.as_view({'get': 'get_provider_dashboard'}), name='provider-telemedicine-dashboard'),
    
    path('', include(router.urls)),
]
