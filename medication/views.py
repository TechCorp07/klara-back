from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from datetime import timedelta
from .services.adherence import calculate_adherence
from .services.interactions import check_interactions
from healthcare.permissions import IsPatientOrProviderForRecord, HasHealthDataConsent
from users.permissions import IsApprovedUser, IsCaregiverWithAccess

from .models import (
    Medication, Prescription, MedicationIntake, MedicationReminder,
    AdherenceRecord, SideEffect, DrugInteraction
)
from .serializers import (
    MedicationSerializer, PrescriptionSerializer, MedicationIntakeSerializer,
    MedicationReminderSerializer, AdherenceRecordSerializer, SideEffectSerializer,
    DrugInteractionSerializer
)
from .filters import (
    MedicationFilter, PrescriptionFilter, MedicationIntakeFilter, 
    MedicationReminderFilter, AdherenceRecordFilter, SideEffectFilter, 
    DrugInteractionFilter
)


class MedicationViewSet(viewsets.ModelViewSet):
    """API viewset for medications."""
    queryset = Medication.objects.all()
    serializer_class = MedicationSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = MedicationFilter
    search_fields = ['name', 'generic_name', 'dosage']
    ordering_fields = ['name', 'start_date', 'end_date', 'created_at', 'updated_at']
    ordering = ['-updated_at']
    permission_classes = [IsAuthenticated, IsApprovedUser, IsPatientOrProviderForRecord]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their medications
        if user.role == 'patient':
            return Medication.objects.filter(patient=user)
        
        # For providers, show medications for their patients
        elif user.role == 'provider':
            return Medication.objects.filter(
                Q(prescriber=user) | 
                Q(medical_record__primary_physician=user)
            )
        
        # For admins and staff, show all medications
        elif user.is_staff or user.role == 'admin':
            return Medication.objects.all()
            
        # For caregivers, show medications for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            patient_id = self.request.query_params.get('patient_id')
            
            if patient_id:
                # Check if caregiver is authorized for this patient
                return Medication.objects.filter(
                    patient__patient_profile__authorized_caregivers=user,
                    patient_id=patient_id
                )
                
            # Show all medications for all patients under caregiver's care
            return Medication.objects.filter(
                patient__patient_profile__authorized_caregivers=user
            )
            
        # Default empty queryset for unauthorized roles
        return Medication.objects.none()
    
    @action(detail=True, methods=['post'])
    def schedule_reminder(self, request, pk=None):
        """Create a reminder for this medication."""
        medication = self.get_object()
        
        # Ensure that only the patient or provider can create reminders
        if request.user != medication.patient and request.user != medication.prescriber:
            return Response(
                {"detail": "Only patient or prescriber can schedule reminders."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Extract reminder data from request
        reminder_data = {
            'medication': medication.id,
            'patient': medication.patient.id,
            'reminder_type': request.data.get('reminder_type', 'dose'),
            'message': request.data.get('message', f"Time to take your {medication.name}"),
            'frequency': request.data.get('frequency', 'daily'),
            'scheduled_time': request.data.get('scheduled_time'),
            'send_email': request.data.get('send_email', True),
            'send_push': request.data.get('send_push', True),
            'send_sms': request.data.get('send_sms', False),
        }
        
        # Validate required fields
        if not reminder_data.get('scheduled_time'):
            return Response(
                {"detail": "scheduled_time is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create reminder
        serializer = MedicationReminderSerializer(data=reminder_data, context={'request': request})
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def mark_taken(self, request, pk=None):
        """Mark a medication as taken."""
        medication = self.get_object()
        
        # Record the intake
        intake_data = {
            'medication': medication.id,
            'scheduled_time': request.data.get('scheduled_time', timezone.now()),
            'actual_time': request.data.get('actual_time', timezone.now()),
            'status': 'taken',
            'dosage_taken': request.data.get('dosage_taken', medication.dosage),
            'notes': request.data.get('notes', ''),
            'recorded_via': request.data.get('recorded_via', 'app')
        }
        
        serializer = MedicationIntakeSerializer(data=intake_data, context={'request': request})
        if serializer.is_valid():
            serializer.save(recorded_by=request.user)
            
            # Update adherence record
            calculate_adherence(medication)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def mark_skipped(self, request, pk=None):
        """Mark a medication as skipped."""
        medication = self.get_object()
        
        # Record the intake
        intake_data = {
            'medication': medication.id,
            'scheduled_time': request.data.get('scheduled_time', timezone.now()),
            'actual_time': request.data.get('actual_time', timezone.now()),
            'status': 'skipped',
            'skip_reason': request.data.get('skip_reason', ''),
            'notes': request.data.get('notes', ''),
            'recorded_via': request.data.get('recorded_via', 'app')
        }
        
        serializer = MedicationIntakeSerializer(data=intake_data, context={'request': request})
        if serializer.is_valid():
            serializer.save(recorded_by=request.user)
            
            # Update adherence record
            calculate_adherence(medication)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def adherence(self, request, pk=None):
        """Get adherence records for a medication."""
        medication = self.get_object()
        
        # Get adherence records for this medication
        adherence_records = AdherenceRecord.objects.filter(medication=medication)
        
        # Apply period type filter if provided
        period_type = request.query_params.get('period_type')
        if period_type:
            adherence_records = adherence_records.filter(period_type=period_type)
        
        # Apply date range filter if provided
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            adherence_records = adherence_records.filter(period_end__gte=start_date)
        
        if end_date:
            adherence_records = adherence_records.filter(period_start__lte=end_date)
        
        # Sort by period start date (most recent first)
        adherence_records = adherence_records.order_by('-period_start')
        
        serializer = AdherenceRecordSerializer(adherence_records, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def check_interactions(self, request, pk=None):
        """Check interactions for this medication with patient's other medications."""
        medication = self.get_object()
        
        # Retrieve patient's active medications excluding this one
        other_medications = Medication.objects.filter(
            patient=medication.patient,
            active=True
        ).exclude(id=medication.id)
        
        # Check interactions
        interactions = []
        for other_med in other_medications:
            interaction = check_interactions(medication, other_med)
            if interaction:
                interactions.append(interaction)
        
        # Return interaction data
        serializer = DrugInteractionSerializer(interactions, many=True)
        return Response(serializer.data)


class PrescriptionViewSet(viewsets.ModelViewSet):
    """API viewset for prescriptions."""
    queryset = Prescription.objects.all()
    serializer_class = PrescriptionSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = PrescriptionFilter
    search_fields = ['medication_name', 'prescription_number']
    ordering_fields = ['prescribed_date', 'expiration_date', 'created_at']
    ordering = ['-prescribed_date']
    permission_classes = [IsAuthenticated, IsApprovedUser, IsPatientOrProviderForRecord]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their prescriptions
        if user.role == 'patient':
            return Prescription.objects.filter(patient=user)
        
        # For providers, show prescriptions they've written
        elif user.role == 'provider':
            return Prescription.objects.filter(prescriber=user)
        
        # For admins and staff, show all prescriptions
        elif user.is_staff or user.role == 'admin':
            return Prescription.objects.all()
            
        # For caregivers, show prescriptions for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            patient_id = self.request.query_params.get('patient_id')
            
            if patient_id:
                # Check if caregiver is authorized for this patient
                return Prescription.objects.filter(
                    patient__patient_profile__authorized_caregivers=user,
                    patient_id=patient_id
                )
                
            # Show all prescriptions for all patients under caregiver's care
            return Prescription.objects.filter(
                patient__patient_profile__authorized_caregivers=user
            )
            
        # Default empty queryset for unauthorized roles
        return Prescription.objects.none()


class MedicationIntakeViewSet(viewsets.ModelViewSet):
    """API viewset for medication intakes."""
    queryset = MedicationIntake.objects.all()
    serializer_class = MedicationIntakeSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = MedicationIntakeFilter  # Replace filterset_fields
    search_fields = ['notes', 'skip_reason']
    ordering_fields = ['scheduled_time', 'actual_time', 'created_at']
    ordering = ['-scheduled_time']
    permission_classes = [IsAuthenticated, IsApprovedUser, IsCaregiverWithAccess]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their intakes
        if user.role == 'patient':
            return MedicationIntake.objects.filter(medication__patient=user)
        
        # For providers, show intakes for their patients
        elif user.role == 'provider':
            return MedicationIntake.objects.filter(
                Q(medication__prescriber=user) |
                Q(medication__medical_record__primary_physician=user)
            )
        
        # For admins and staff, show all intakes
        elif user.is_staff or user.role == 'admin':
            return MedicationIntake.objects.all()
            
        # For caregivers, show intakes for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            patient_id = self.request.query_params.get('patient_id')
            
            if patient_id:
                # Check if caregiver is authorized for this patient
                return MedicationIntake.objects.filter(
                    medication__patient__patient_profile__authorized_caregivers=user,
                    medication__patient_id=patient_id
                )
                
            # Show all intakes for all patients under caregiver's care
            return MedicationIntake.objects.filter(
                medication__patient__patient_profile__authorized_caregivers=user
            )
            
        # Default empty queryset for unauthorized roles
        return MedicationIntake.objects.none()
    
    @action(detail=False, methods=['get'])
    def overdue(self, request):
        """Get overdue medication intakes."""
        # Get base queryset
        queryset = self.get_queryset()
        
        # Filter by status and scheduled time
        now = timezone.now()
        overdue_intakes = queryset.filter(
            status='missed',
            scheduled_time__lt=now
        ).order_by('scheduled_time')
        
        # Apply medication filter if provided
        medication_id = request.query_params.get('medication_id')
        if medication_id:
            overdue_intakes = overdue_intakes.filter(medication_id=medication_id)
        
        # Apply date range filter if provided
        start_date = request.query_params.get('start_date')
        if start_date:
            overdue_intakes = overdue_intakes.filter(scheduled_time__gte=start_date)
        
        # Default to intakes scheduled in last 24 hours if no date filter
        if not start_date:
            yesterday = now - timedelta(days=1)
            overdue_intakes = overdue_intakes.filter(scheduled_time__gte=yesterday)
        
        serializer = self.get_serializer(overdue_intakes, many=True)
        return Response(serializer.data)


class MedicationReminderViewSet(viewsets.ModelViewSet):
    """API viewset for medication reminders."""
    queryset = MedicationReminder.objects.all()
    serializer_class = MedicationReminderSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = MedicationReminderFilter  # Replace filterset_fields
    search_fields = ['message']
    ordering_fields = ['scheduled_time', 'created_at']
    ordering = ['scheduled_time']
    permission_classes = [IsAuthenticated, IsApprovedUser, IsCaregiverWithAccess]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their reminders
        if user.role == 'patient':
            return MedicationReminder.objects.filter(patient=user)
        
        # For providers, show reminders they've created
        elif user.role == 'provider':
            return MedicationReminder.objects.filter(
                Q(created_by=user) |
                Q(medication__prescriber=user) |
                Q(medication__medical_record__primary_physician=user)
            )
        
        # For admins and staff, show all reminders
        elif user.is_staff or user.role == 'admin':
            return MedicationReminder.objects.all()
            
        # For caregivers, show reminders for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            patient_id = self.request.query_params.get('patient_id')
            
            if patient_id:
                # Check if caregiver is authorized for this patient
                return MedicationReminder.objects.filter(
                    patient__patient_profile__authorized_caregivers=user,
                    patient_id=patient_id
                )
                
            # Show all reminders for all patients under caregiver's care
            return MedicationReminder.objects.filter(
                patient__patient_profile__authorized_caregivers=user
            )
            
        # Default empty queryset for unauthorized roles
        return MedicationReminder.objects.none()
    
    @action(detail=False, methods=['get'])
    def due_now(self, request):
        """Get reminders that are due now."""
        # Get base queryset
        queryset = self.get_queryset()
        
        # Filter active reminders
        active_reminders = queryset.filter(is_active=True)
        
        # Check which ones are due
        due_reminders = []
        for reminder in active_reminders:
            if reminder.is_due():
                due_reminders.append(reminder)
        
        serializer = self.get_serializer(due_reminders, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def send_now(self, request, pk=None):
        """Send a reminder immediately."""
        reminder = self.get_object()
        
        # Check permissions
        if (request.user != reminder.patient and 
            request.user != reminder.medication.prescriber and 
            request.user.role not in ['admin', 'caregiver']):
            return Response(
                {"detail": "Not authorized to send this reminder."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Import services here to avoid circular imports
        from .services.reminders import send_reminder
        
        try:
            success = send_reminder(reminder)
            
            if success:
                # Update last_sent timestamp
                reminder.last_sent = timezone.now()
                reminder.save(update_fields=['last_sent'])
                
                return Response({
                    "detail": "Reminder sent successfully.",
                    "reminder": self.get_serializer(reminder).data
                })
            else:
                return Response(
                    {"detail": "Failed to send reminder."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
                
        except Exception as e:
            return Response(
                {"detail": f"Error sending reminder: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdherenceRecordViewSet(viewsets.ReadOnlyModelViewSet):
    """API viewset for adherence records (read-only)."""
    queryset = AdherenceRecord.objects.all()
    serializer_class = AdherenceRecordSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = AdherenceRecordFilter  # Replace filterset_fields
    ordering_fields = ['period_start', 'period_end', 'adherence_rate']
    ordering = ['-period_start']
    permission_classes = [IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their adherence records
        if user.role == 'patient':
            return AdherenceRecord.objects.filter(patient=user)
        
        # For providers, show adherence records for their patients
        elif user.role == 'provider':
            return AdherenceRecord.objects.filter(
                Q(medication__prescriber=user) |
                Q(medication__medical_record__primary_physician=user)
            )
        
        # For admins and staff, show all adherence records
        elif user.is_staff or user.role == 'admin':
            return AdherenceRecord.objects.all()
            
        # For pharmaceutical companies with consent
        elif user.role == 'pharmco':
            # Only show records for patients with medication adherence consent
            return AdherenceRecord.objects.filter(
                patient__medication_adherence_monitoring_consent=True
            )
            
        # For caregivers, show adherence records for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Only if they have medication access
            if user.caregiver_profile.access_level in ['MEDICATIONS', 'FULL']:
                patient_id = self.request.query_params.get('patient_id')
                
                if patient_id:
                    # Check if caregiver is authorized for this patient
                    return AdherenceRecord.objects.filter(
                        patient__patient_profile__authorized_caregivers=user,
                        patient_id=patient_id
                    )
                    
                # Show all adherence records for all patients under caregiver's care
                return AdherenceRecord.objects.filter(
                    patient__patient_profile__authorized_caregivers=user
                )
            
        # Default empty queryset for unauthorized roles
        return AdherenceRecord.objects.none()


class SideEffectViewSet(viewsets.ModelViewSet):
    """API viewset for medication side effects."""
    queryset = SideEffect.objects.all()
    serializer_class = SideEffectSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = SideEffectFilter  # Replace filterset_fields
    search_fields = ['description', 'notes']
    ordering_fields = ['onset_date', 'resolution_date', 'created_at']
    ordering = ['-onset_date']
    permission_classes = [IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their side effects
        if user.role == 'patient':
            return SideEffect.objects.filter(patient=user)
        
        # For providers, show side effects for their patients
        elif user.role == 'provider':
            return SideEffect.objects.filter(
                Q(medication__prescriber=user) |
                Q(medication__medical_record__primary_physician=user)
            )
        
        # For admins and staff, show all side effects
        elif user.is_staff or user.role == 'admin':
            return SideEffect.objects.all()
            
        # For caregivers, show side effects for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Only if they have appropriate access
            if user.caregiver_profile.access_level in ['MEDICATIONS', 'FULL']:
                patient_id = self.request.query_params.get('patient_id')
                
                if patient_id:
                    # Check if caregiver is authorized for this patient
                    return SideEffect.objects.filter(
                        patient__patient_profile__authorized_caregivers=user,
                        patient_id=patient_id
                    )
                    
                # Show all side effects for all patients under caregiver's care
                return SideEffect.objects.filter(
                    patient__patient_profile__authorized_caregivers=user
                )
            
        # Default empty queryset for unauthorized roles
        return SideEffect.objects.none()
    
    @action(detail=True, methods=['post'])
    def report_to_doctor(self, request, pk=None):
        """Mark side effect as reported to doctor."""
        side_effect = self.get_object()
        
        # Check permissions
        if (request.user != side_effect.patient and 
            request.user.role not in ['admin', 'provider', 'caregiver']):
            return Response(
                {"detail": "Not authorized to report this side effect."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Update side effect
        side_effect.reported_to_doctor = True
        side_effect.doctor_notified_date = timezone.now().date()
        side_effect.save(update_fields=['reported_to_doctor', 'doctor_notified_date'])
        
        # Return updated record
        serializer = self.get_serializer(side_effect)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def mark_resolved(self, request, pk=None):
        """Mark side effect as resolved."""
        side_effect = self.get_object()
        
        # Check permissions
        if (request.user != side_effect.patient and 
            request.user != side_effect.medication.prescriber and
            request.user.role not in ['admin', 'caregiver']):
            return Response(
                {"detail": "Not authorized to resolve this side effect."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Update side effect
        side_effect.ongoing = False
        side_effect.resolution_date = request.data.get('resolution_date', timezone.now().date())
        side_effect.save(update_fields=['ongoing', 'resolution_date'])
        
        # Return updated record
        serializer = self.get_serializer(side_effect)
        return Response(serializer.data)


class DrugInteractionViewSet(viewsets.ModelViewSet):
    """API viewset for drug interactions."""
    queryset = DrugInteraction.objects.all()
    serializer_class = DrugInteractionSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = DrugInteractionFilter  # Replace filterset_fields
    search_fields = ['description', 'resolution_action']
    ordering_fields = ['detected_date', 'resolved_date', 'created_at']
    ordering = ['-detected_date']
    permission_classes = [IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    
    def get_queryset(self):
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # For patients, show only their interactions
        if user.role == 'patient':
            return DrugInteraction.objects.filter(patient=user)
        
        # For providers, show interactions for their patients
        elif user.role == 'provider':
            return DrugInteraction.objects.filter(
                Q(medication_a__prescriber=user) |
                Q(medication_b__prescriber=user) |
                Q(medication_a__medical_record__primary_physician=user) |
                Q(medication_b__medical_record__primary_physician=user)
            )
        
        # For admins and staff, show all interactions
        elif user.is_staff or user.role == 'admin':
            return DrugInteraction.objects.all()
            
        # For caregivers, show interactions for patients they care for
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Only if they have medication access
            if user.caregiver_profile.access_level in ['MEDICATIONS', 'FULL']:
                patient_id = self.request.query_params.get('patient_id')
                
                if patient_id:
                    # Check if caregiver is authorized for this patient
                    return DrugInteraction.objects.filter(
                        patient__patient_profile__authorized_caregivers=user,
                        patient_id=patient_id
                    )
                    
                # Show all interactions for all patients under caregiver's care
                return DrugInteraction.objects.filter(
                    patient__patient_profile__authorized_caregivers=user
                )
            
        # Default empty queryset for unauthorized roles
        return DrugInteraction.objects.none()
    
    @action(detail=True, methods=['post'])
    def mark_resolved(self, request, pk=None):
        """Mark drug interaction as resolved."""
        interaction = self.get_object()
        
        # Check permissions
        if (request.user != interaction.patient and 
            request.user != interaction.medication_a.prescriber and
            request.user != interaction.medication_b.prescriber and
            request.user.role not in ['admin']):
            return Response(
                {"detail": "Not authorized to resolve this interaction."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Extract data from request
        resolution_action = request.data.get('resolution_action', '')
        
        # Update interaction
        interaction.resolved_date = request.data.get('resolved_date', timezone.now().date())
        interaction.resolution_action = resolution_action
        interaction.save(update_fields=['resolved_date', 'resolution_action'])
        
        # Return updated record
        serializer = self.get_serializer(interaction)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def notify_patient(self, request, pk=None):
        """Mark drug interaction as patient notified."""
        interaction = self.get_object()
        
        # Check permissions
        if (request.user != interaction.medication_a.prescriber and
            request.user != interaction.medication_b.prescriber and
            request.user.role not in ['admin']):
            return Response(
                {"detail": "Not authorized to mark as notified."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Update interaction
        interaction.patient_notified = True
        interaction.save(update_fields=['patient_notified'])
        
        # Return updated record
        serializer = self.get_serializer(interaction)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def notify_provider(self, request, pk=None):
        """Mark drug interaction as provider notified."""
        interaction = self.get_object()
        
        # Check permissions
        if (request.user != interaction.patient and
            request.user.role not in ['admin', 'caregiver']):
            return Response(
                {"detail": "Not authorized to mark as notified."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Update interaction
        interaction.provider_notified = True
        interaction.save(update_fields=['provider_notified'])
        
        # Return updated record
        serializer = self.get_serializer(interaction)
        return Response(serializer.data)

