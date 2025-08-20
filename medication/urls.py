from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    MedicationViewSet, PrescriptionViewSet, MedicationIntakeViewSet,
    MedicationReminderViewSet, AdherenceRecordViewSet, SideEffectViewSet,
    DrugInteractionViewSet
)
from users.enhanced_views import EnhancedMedicationViewSet


router = DefaultRouter()
router.register(r'medications', MedicationViewSet, basename='medication')
router.register(r'prescriptions', PrescriptionViewSet, basename='prescription')
router.register(r'intakes', MedicationIntakeViewSet, basename='medicationintake')
router.register(r'reminders', MedicationReminderViewSet, basename='medicationreminder')
router.register(r'adherence', AdherenceRecordViewSet, basename='adherencerecord')
router.register(r'side-effects', SideEffectViewSet, basename='sideeffect')
router.register(r'interactions', DrugInteractionViewSet, basename='druginteraction')

urlpatterns = [
    path('', include(router.urls)),
    
    # Provider prescription management
    path('prescriptions/create/', PrescriptionViewSet.as_view({'post': 'create_prescription'}), name='create-prescription'),
    path('prescriptions/my-patients/', PrescriptionViewSet.as_view({'get': 'my_patients'}), name='provider-patients'),
    
    # Patient prescription endpoints  
    path('prescriptions/analytics/', PrescriptionViewSet.as_view({'get': 'analytics'}), name='prescription-analytics'),
    path('prescriptions/reminders/', PrescriptionViewSet.as_view({'get': 'reminders', 'patch': 'reminders'}), name='prescription-reminders'),
    path('prescriptions/insights/', PrescriptionViewSet.as_view({'get': 'insights'}), name='prescription-insights'),
    path('prescriptions/interactions/', PrescriptionViewSet.as_view({'get': 'interactions'}), name='prescription-interactions'),
    path('prescriptions/schedule/', PrescriptionViewSet.as_view({'get': 'schedule'}), name='prescription-schedule'),
    
    # Enhanced Medication endpoints
    path('adherence/intelligent-schedule/', EnhancedMedicationViewSet.as_view({'post': 'create_intelligent_reminder_schedule'}), name='intelligent-medication-schedule'),
    path('adherence/analyze-trends/', EnhancedMedicationViewSet.as_view({'get': 'analyze_adherence_trends'}), name='analyze-adherence-trends'),
]
