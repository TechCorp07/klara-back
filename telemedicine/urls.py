from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AppointmentViewSet, ConsultationViewSet, PrescriptionViewSet,
    ProviderAvailabilityViewSet, WaitingRoomViewSet, WaitingRoomPatientViewSet,
    ConsultationNoteViewSet
)

router = DefaultRouter()
router.register(r'appointments', AppointmentViewSet)
router.register(r'consultations', ConsultationViewSet)
router.register(r'prescriptions', PrescriptionViewSet)
router.register(r'availability', ProviderAvailabilityViewSet)
router.register(r'waiting-rooms', WaitingRoomViewSet)
router.register(r'waiting-room-patients', WaitingRoomPatientViewSet)
router.register(r'consultation-notes', ConsultationNoteViewSet)

urlpatterns = [
    path('', include(router.urls)),
    
    # Additional custom endpoints could be added here if needed
]
