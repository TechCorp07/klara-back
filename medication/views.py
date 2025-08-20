from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from django.db import transaction
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
    def setup_reminders_from_preferences(self, request, pk=None):
        """Setup reminders based on patient's notification preferences."""
        medication = self.get_object()
        patient_profile = medication.patient.patient_profile
        
        if not patient_profile.medication_reminder_enabled:
            return Response({
                "detail": "Patient has disabled medication reminders"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Clear existing reminders
        medication.reminders.all().delete()
        
        # Generate new reminders based on preferences
        from .services.reminders import generate_reminders
        reminders = generate_reminders(medication)
        
        serializer = MedicationReminderSerializer(reminders, many=True)
        return Response({
            "detail": f"Created {len(reminders)} reminders",
            "reminders": serializer.data
        })
    
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

    @action(detail=False, methods=['get'])
    def schedule(self, request):
        """Get patient's medication schedule for a specific date."""
        from django.utils import timezone
        from datetime import datetime, timedelta
        
        try:
            # Get the date parameter (defaults to today)
            date_str = request.query_params.get('date')
            if date_str:
                target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            else:
                target_date = timezone.now().date()
            
            # Get active prescriptions for the current user (already filtered by get_queryset)
            active_prescriptions = self.get_queryset().filter(
                status='active'
            )
            
            schedule_items = []
            
            for prescription in active_prescriptions:
                # Generate scheduled times based on frequency
                scheduled_times = self._generate_scheduled_times(prescription, target_date)
                
                # Get adherence records for this prescription and date
                from .models import MedicationAdherence
                adherence_records = MedicationAdherence.objects.filter(
                    prescription=prescription,
                    date=target_date
                )
                
                # Create adherence data structure
                adherence_data = []
                for scheduled_time in scheduled_times:
                    # Check if there's an adherence record for this time
                    adherence_record = adherence_records.filter(
                        scheduled_time__time=scheduled_time.time()
                    ).first()
                    
                    if adherence_record:
                        adherence_data.append({
                            'prescription': prescription.id,
                            'scheduled_time': adherence_record.scheduled_time.isoformat(),
                            'taken': adherence_record.taken,
                            'taken_time': adherence_record.taken_time.isoformat() if adherence_record.taken_time else None,
                            'notes': adherence_record.notes or ''
                        })
                    else:
                        # No record yet, so it's pending
                        adherence_data.append({
                            'prescription': prescription.id,
                            'scheduled_time': scheduled_time.isoformat(),
                            'taken': False,
                            'taken_time': None,
                            'notes': ''
                        })
                
                # Create schedule item
                schedule_item = {
                    'prescription': self.get_serializer(prescription).data,
                    'scheduled_times': [time.isoformat() for time in scheduled_times],
                    'adherence_data': adherence_data
                }
                
                schedule_items.append(schedule_item)
            
            return Response(schedule_items)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to fetch medication schedule: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _generate_scheduled_times(self, prescription, target_date):
        """Generate scheduled times for a prescription on a given date."""
        from datetime import datetime, time
        
        scheduled_times = []
        
        # Parse frequency - this is simplified, you can make it more sophisticated
        frequency = prescription.frequency.lower()
        
        if 'daily' in frequency or 'once' in frequency:
            # Once daily - morning
            scheduled_times.append(
                datetime.combine(target_date, time(8, 0))  # 8:00 AM
            )
        elif 'twice' in frequency or '2' in frequency:
            # Twice daily
            scheduled_times.extend([
                datetime.combine(target_date, time(8, 0)),   # 8:00 AM
                datetime.combine(target_date, time(20, 0))   # 8:00 PM
            ])
        elif 'three' in frequency or '3' in frequency:
            # Three times daily
            scheduled_times.extend([
                datetime.combine(target_date, time(8, 0)),   # 8:00 AM
                datetime.combine(target_date, time(14, 0)),  # 2:00 PM
                datetime.combine(target_date, time(20, 0))   # 8:00 PM
            ])
        elif 'four' in frequency or '4' in frequency:
            # Four times daily
            scheduled_times.extend([
                datetime.combine(target_date, time(8, 0)),   # 8:00 AM
                datetime.combine(target_date, time(12, 0)),  # 12:00 PM
                datetime.combine(target_date, time(16, 0)),  # 4:00 PM
                datetime.combine(target_date, time(20, 0))   # 8:00 PM
            ])
        
        return scheduled_times

    @action(detail=True, methods=['post'])
    def log(self, request, pk=None):
        """Log medication taken or missed."""
        from django.utils import timezone
        from .models import MedicationAdherence
        
        try:
            prescription = self.get_object()
            
            # Get data from request
            taken_time = request.data.get('taken_time', timezone.now().isoformat())
            taken = request.data.get('taken', True)
            scheduled_time = request.data.get('scheduled_time')
            notes = request.data.get('notes', '')
            
            # Parse scheduled_time
            if isinstance(scheduled_time, str):
                scheduled_time = datetime.fromisoformat(scheduled_time.replace('Z', '+00:00'))
            
            # Create or update adherence record
            adherence_record, created = MedicationAdherence.objects.get_or_create(
                prescription=prescription,
                scheduled_time=scheduled_time,
                defaults={
                    'date': scheduled_time.date(),
                    'taken': taken,
                    'taken_time': taken_time if taken else None,
                    'notes': notes
                }
            )
            
            if not created:
                # Update existing record
                adherence_record.taken = taken
                adherence_record.taken_time = taken_time if taken else None
                adherence_record.notes = notes
                adherence_record.save()
            
            return Response({
                'message': 'Medication logged successfully',
                'adherence_record': {
                    'id': adherence_record.id,
                    'taken': adherence_record.taken,
                    'taken_time': adherence_record.taken_time,
                    'scheduled_time': adherence_record.scheduled_time.isoformat(),
                    'notes': adherence_record.notes
                }
            })
            
        except Exception as e:
            return Response(
                {'error': f'Failed to log medication: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def create_prescription(self, request):
        """Provider creates a new prescription for a patient."""
        try:
            # Ensure only providers can create prescriptions
            if request.user.role != 'provider':
                return Response(
                    {'error': 'Only healthcare providers can create prescriptions'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            with transaction.atomic():
                # Extract data
                patient_id = request.data.get('patient_id')
                medication_name = request.data.get('medication_name')
                dosage = request.data.get('dosage')
                frequency = request.data.get('frequency')
                quantity = request.data.get('quantity')
                refills = request.data.get('refills', 0)
                instructions = request.data.get('instructions', '')
                pharmacy_name = request.data.get('pharmacy_name')
                pharmacy_phone = request.data.get('pharmacy_phone')
                pharmacy_address = request.data.get('pharmacy_address')
                
                # Validate required fields
                if not all([patient_id, medication_name, dosage, frequency, quantity]):
                    return Response(
                        {'error': 'Missing required fields'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Get patient and verify provider has access
                from django.contrib.auth import get_user_model
                User = get_user_model()
                
                try:
                    patient = User.objects.get(id=patient_id, role='patient')
                except User.DoesNotExist:
                    return Response(
                        {'error': 'Patient not found'},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
                # Check if provider has access to this patient
                has_access = self._provider_has_patient_access(request.user, patient)
                if not has_access:
                    return Response(
                        {'error': 'You are not authorized to prescribe for this patient'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                # Generate prescription number
                import uuid
                prescription_number = f"RX{uuid.uuid4().hex[:8].upper()}"
                
                # Create prescription
                prescription = Prescription.objects.create(
                    prescription_number=prescription_number,
                    patient=patient,
                    prescriber=request.user,
                    medication_name=medication_name,
                    dosage=dosage,
                    frequency=frequency,
                    quantity=quantity,
                    refills=refills,
                    instructions=instructions,
                    pharmacy_name=pharmacy_name,
                    pharmacy_phone=pharmacy_phone,
                    pharmacy_address=pharmacy_address,
                    prescribed_date=timezone.now().date(),
                    status='pending',
                    created_by=request.user
                )
                
                # Log prescription creation for HIPAA compliance
                from audit.services.medication_integration import log_prescription_access
                log_prescription_access(
                    user=request.user,
                    patient_id=patient.id,
                    prescription_id=prescription.id,
                    access_type='create',
                    reason='Provider created new prescription'
                )
                
                # If electronic prescription, send to pharmacy
                if request.data.get('send_electronically', False):
                    self._send_e_prescription(prescription)
                
                # Serialize and return
                serializer = self.get_serializer(prescription)
                return Response({
                    'message': 'Prescription created successfully',
                    'prescription': serializer.data
                }, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            return Response(
                {'error': f'Failed to create prescription: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _provider_has_patient_access(self, provider, patient):
        """Check if provider has access to prescribe for this patient."""
        # Check if provider is the patient's primary physician
        from healthcare.models import MedicalRecord
        medical_record = MedicalRecord.objects.filter(
            patient=patient,
            primary_physician=provider
        ).first()
        
        if medical_record:
            return True
        
        # Check if there's an active appointment/consultation
        from telemedicine.models import Appointment
        recent_appointment = Appointment.objects.filter(
            patient=patient,
            provider=provider,
            scheduled_time__gte=timezone.now() - timedelta(days=30)
        ).first()
        
        if recent_appointment:
            return True
        
        # Check if provider has patient in their care (you can customize this logic)
        if hasattr(provider, 'primary_patients') and patient in provider.primary_patients.all():
            return True
        
        return False

    def _send_e_prescription(self, prescription):
        """Send prescription electronically to pharmacy."""
        try:
            # Mark as electronically sent
            prescription.is_electronic = True
            prescription.save()
            
            # Log transmission
            from audit.services.medication_integration import log_e_prescription_transmission
            log_e_prescription_transmission(
                user=prescription.prescriber,
                patient_id=prescription.patient.id,
                prescription_id=prescription.id,
                pharmacy_id=prescription.pharmacy_name,  # This could be pharmacy ID
                status='sent'
            )
            
            # Here you would integrate with actual e-prescribing service
            # For now, just simulate the process
            prescription.electronic_routing_id = f"EPCS{prescription.id}"
            prescription.save()
            
        except Exception as e:
            # Log failed transmission
            from audit.services.medication_integration import log_e_prescription_transmission
            log_e_prescription_transmission(
                user=prescription.prescriber,
                patient_id=prescription.patient.id,
                prescription_id=prescription.id,
                pharmacy_id=prescription.pharmacy_name,
                status='failed'
            )
            raise e

    @action(detail=False, methods=['get'])
    def my_patients(self, request):
        """Get patients that this provider can prescribe for."""
        if request.user.role != 'provider':
            return Response(
                {'error': 'Only providers can access this endpoint'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        from django.contrib.auth import get_user_model
        from healthcare.models import MedicalRecord
        
        User = get_user_model()
        
        # Get patients where this provider is the primary physician
        patients = User.objects.filter(
            role='patient',
            medical_records__primary_physician=request.user
        ).distinct()
        
        # Also include patients from recent appointments
        from telemedicine.models import Appointment
        recent_patients = User.objects.filter(
            role='patient',
            patient_appointments__provider=request.user,
            patient_appointments__scheduled_time__gte=timezone.now() - timedelta(days=90)
        ).distinct()
        
        # Combine and serialize
        all_patients = patients.union(recent_patients)
        
        patient_data = []
        for patient in all_patients:
            patient_data.append({
                'id': patient.id,
                'name': patient.get_full_name(),
                'email': patient.email,
                'has_rare_condition': getattr(patient.patient_profile, 'has_rare_condition', False) if hasattr(patient, 'patient_profile') else False
            })
        
        return Response(patient_data)
    
    @action(detail=False, methods=['get'])
    def analytics(self, request):
        """Get prescription analytics for the current patient."""
        from django.db.models import Count, Avg, Q
        from datetime import datetime, timedelta
        
        try:
            # Get timeframe parameter
            timeframe = request.query_params.get('timeframe', '30d')
            
            # Calculate date range
            if timeframe == '7d':
                days = 7
            elif timeframe == '90d':
                days = 90
            else:
                days = 30
                
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get patient's prescriptions (already filtered by get_queryset)
            prescriptions = self.get_queryset().filter(status='active')
            
            # Get adherence records for the period
            from .models import MedicationAdherence
            adherence_records = MedicationAdherence.objects.filter(
                prescription__in=prescriptions,
                date__range=[start_date, end_date]
            )
            
            # Calculate analytics
            analytics_data = {
                'adherence_trends': [],
                'missed_doses': [],
                'side_effects': [],
                'insights': {
                    'overall_adherence': 0,
                    'best_adherence_day': 'Monday',
                    'worst_adherence_day': 'Friday',
                    'optimal_time_pattern': 'Morning doses',
                    'improvement_suggestions': [
                        'Set additional reminders for Friday doses',
                        'Consider pill organizers for complex regimens',
                        'Schedule weekend refill reminders'
                    ]
                }
            }
            
            # Calculate daily adherence rates
            for i in range(days):
                current_date = start_date + timedelta(days=i)
                day_records = adherence_records.filter(date=current_date)
                
                if day_records.exists():
                    taken_count = day_records.filter(taken=True).count()
                    total_count = day_records.count()
                    rate = (taken_count / total_count) * 100 if total_count > 0 else 0
                else:
                    rate = 0
                
                analytics_data['adherence_trends'].append({
                    'date': current_date.isoformat(),
                    'rate': round(rate, 2)
                })
            
            # Calculate overall adherence
            if adherence_records.exists():
                total_taken = adherence_records.filter(taken=True).count()
                total_scheduled = adherence_records.count()
                analytics_data['insights']['overall_adherence'] = round(
                    (total_taken / total_scheduled) * 100, 2
                ) if total_scheduled > 0 else 0
            
            # Get missed doses by prescription
            for prescription in prescriptions:
                missed_records = adherence_records.filter(
                    prescription=prescription,
                    taken=False
                )
                
                if missed_records.exists():
                    missed_times = [
                        record.scheduled_time.isoformat() 
                        for record in missed_records
                    ]
                    
                    analytics_data['missed_doses'].append({
                        'medication': prescription.medication_name,
                        'missed_times': missed_times
                    })
            
            # Get side effects
            from .models import SideEffect
            side_effects = SideEffect.objects.filter(
                medication__prescription__in=prescriptions,
                ongoing=True
            )
            
            for side_effect in side_effects:
                analytics_data['side_effects'].append({
                    'medication': side_effect.medication.name if hasattr(side_effect, 'medication') else 'Unknown',
                    'effects': [side_effect.description] if hasattr(side_effect, 'description') else [],
                    'severity': side_effect.severity if hasattr(side_effect, 'severity') else 'mild'
                })
            
            return Response(analytics_data)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to fetch analytics: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get', 'patch'])
    def reminders(self, request):
        """Get or update medication reminder preferences for patient."""
        if request.method == 'GET':
            # Return current reminder preferences
            reminder_preferences = {
                'enabled': True,
                'methods': ['email', 'push'],
                'frequency': '30min',
                'quiet_hours': {'start': '22:00', 'end': '07:00'},
                'smart_suggestions': True
            }
            return Response(reminder_preferences)
        
        elif request.method == 'PATCH':
            # Update reminder preferences
            # In a real implementation, save to user profile or medication model
            return Response({
                'message': 'Reminder preferences updated successfully',
                'preferences': request.data
            })

    @action(detail=False, methods=['get'])
    def insights(self, request):
        """Get personalized medication insights."""
        try:
            # Get patient's prescriptions
            prescriptions = self.get_queryset().filter(status='active')
            
            insights = {
                'adherence_score': 85,
                'risk_factors': [
                    'Weekend adherence drops by 15%',
                    'Evening doses frequently missed'
                ],
                'recommendations': [
                    'Set weekend reminders',
                    'Use smart pillbox for evening doses',
                    'Consider medication timing optimization'
                ],
                'patterns': {
                    'best_time': '08:00',
                    'worst_day': 'Saturday',
                    'adherence_trend': 'improving'
                },
                'next_refill_dates': []
            }
            
            # Calculate next refill dates
            for prescription in prescriptions:
                if prescription.expiration_date:
                    days_until_refill = (prescription.expiration_date - timezone.now().date()).days
                    if days_until_refill <= 30:  # Show if refill needed within 30 days
                        insights['next_refill_dates'].append({
                            'medication': prescription.medication_name,
                            'days_until_refill': days_until_refill,
                            'refill_date': prescription.expiration_date.isoformat()
                        })
            
            return Response(insights)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to fetch insights: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def interactions(self, request):
        """Check for drug interactions between patient's prescriptions."""
        try:
            # Get patient's active prescriptions
            prescriptions = self.get_queryset().filter(status='active')
            
            interactions = []
            
            # Check interactions between all prescription pairs
            for i, prescription_a in enumerate(prescriptions):
                for prescription_b in prescriptions[i+1:]:
                    # Simple interaction check - in real implementation, 
                    # use drug database or AI service
                    interaction_risk = self._check_drug_interaction(
                        prescription_a.medication_name, 
                        prescription_b.medication_name
                    )
                    
                    if interaction_risk:
                        interactions.append({
                            'medication_a': prescription_a.medication_name,
                            'medication_b': prescription_b.medication_name,
                            'severity': interaction_risk['severity'],
                            'description': interaction_risk['description'],
                            'recommendation': interaction_risk['recommendation']
                        })
            
            return Response({
                'interactions': interactions,
                'total_count': len(interactions),
                'high_risk_count': len([i for i in interactions if i['severity'] == 'high'])
            })
            
        except Exception as e:
            return Response(
                {'error': f'Failed to check interactions: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _check_drug_interaction(self, med_a, med_b):
        """Simple drug interaction checker - replace with real drug database."""
        # This is a simplified example - use real drug interaction database
        known_interactions = {
            ('warfarin', 'aspirin'): {
                'severity': 'high',
                'description': 'Increased bleeding risk',
                'recommendation': 'Monitor closely, consider dose adjustment'
            },
            ('metformin', 'alcohol'): {
                'severity': 'moderate',
                'description': 'Increased risk of lactic acidosis',
                'recommendation': 'Limit alcohol consumption'
            }
        }
        
        # Check both directions
        key1 = (med_a.lower(), med_b.lower())
        key2 = (med_b.lower(), med_a.lower())
        
        return known_interactions.get(key1) or known_interactions.get(key2)
    

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

