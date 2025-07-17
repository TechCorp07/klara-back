from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    MedicationViewSet, PrescriptionViewSet, MedicationIntakeViewSet,
    MedicationReminderViewSet, AdherenceRecordViewSet, SideEffectViewSet,
    DrugInteractionViewSet
)

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
]
