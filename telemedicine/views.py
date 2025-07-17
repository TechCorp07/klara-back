import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.db.models import Q, F
from django.contrib.auth import get_user_model
from .services.rare_disease_consultation import RareDiseaseConsultationService
#from .services.notification_service import telemedicine_notifications

from rest_framework import viewsets, status, filters, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend

from .models import (
    Appointment, Consultation, Prescription, 
    ProviderAvailability, WaitingRoom, WaitingRoomPatient,
    ConsultationNote
)
from .serializers import (
    AppointmentSerializer, AppointmentDetailSerializer, ConsultationSerializer,
    PrescriptionSerializer, ProviderAvailabilitySerializer, WaitingRoomSerializer,
    WaitingRoomPatientSerializer, ConsultationNoteSerializer, JoinInfoSerializer,
    CancelAppointmentSerializer, RescheduleAppointmentSerializer, ConsultationStartSerializer,
    ConsultationEndSerializer, AvailabilitySlotSerializer, CheckInPatientSerializer, 
    PatientReadySerializer
)
from .permissions import (
    IsApprovedUser, IsPatientProviderOrAdmin, IsProviderOrAdmin, 
    IsAppointmentParticipant, CanViewPrescription, CanStartConsultation,
    CanJoinConsultation, CanManageProviderAvailability, CanManageWaitingRoom,
    CanPrescribe, IsPatientWithTelemedicineAccess, CanViewHealthData
)
from .services import (
    zoom_service, notifications_service, scheduling_service
)

from healthcare.models import VitalSign
from wearables.models import WearableMeasurement

User = get_user_model()
logger = logging.getLogger(__name__)


class AppointmentViewSet(viewsets.ModelViewSet):
    """ViewSet for telemedicine appointments."""
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ['status', 'patient', 'provider', 'appointment_type', 'priority', 'scheduled_time']
    search_fields = ['patient__first_name', 'patient__last_name', 'provider__first_name', 'provider__last_name', 'reason']
    ordering_fields = ['scheduled_time', 'created_at', 'updated_at', 'status']
    ordering = ['-scheduled_time']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, IsPatientProviderOrAdmin]
    
    def get_serializer_class(self):
        """Use detailed serializer for retrieve action."""
        if self.action == 'retrieve':
            return AppointmentDetailSerializer
        return AppointmentSerializer
    
    def get_queryset(self):
        """Filter appointments based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
                
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter based on user role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'provider':
            return queryset.filter(provider=user)
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(patient__in=authorized_patients)
        
        # Admin can see all
        return queryset
    
    def get_permissions(self):
        """Adjust permissions based on action."""
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated(), IsApprovedUser(), IsPatientWithTelemedicineAccess()]
        
        return super().get_permissions()
    
    def perform_create(self, serializer):
        """Create appointment with proper metadata."""
        serializer.save(created_by=self.request.user, updated_by=self.request.user)
        
        # Send confirmation notification
        try:
            appointment = serializer.instance
            notifications_service.send_appointment_confirmation(appointment)
        except Exception as e:
            logger.error(f"Failed to send confirmation notification: {str(e)}")
    
    def perform_update(self, serializer):
        """Update appointment with proper metadata."""
        serializer.save(updated_by=self.request.user)
    
    @action(detail=False, methods=['get'])
    def upcoming(self, request):
        """Get upcoming appointments."""
        user = request.user
        now = timezone.now()
        
        # Build filter based on user role
        if user.role == 'patient':
            filter_kwargs = {'patient': user}
        elif user.role == 'provider':
            filter_kwargs = {'provider': user}
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            authorized_patients = user.caregiver_patients.all()
            filter_kwargs = {'patient__in': authorized_patients}
        else:
            filter_kwargs = {}
        
        # Get upcoming appointments
        appointments = Appointment.objects.filter(
            Q(scheduled_time__gte=now) | Q(status='in_progress'),
            status__in=['scheduled', 'confirmed', 'in_progress', 'checked_in'],
            **filter_kwargs
        ).order_by('scheduled_time')
        
        serializer = self.get_serializer(appointments, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def past(self, request):
        """Get past appointments."""
        user = request.user
        now = timezone.now()
        
        # Build filter based on user role
        if user.role == 'patient':
            filter_kwargs = {'patient': user}
        elif user.role == 'provider':
            filter_kwargs = {'provider': user}
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            authorized_patients = user.caregiver_patients.all()
            filter_kwargs = {'patient__in': authorized_patients}
        else:
            filter_kwargs = {}
        
        # Get past appointments
        appointments = Appointment.objects.filter(
            scheduled_time__lt=now,
            status__in=['completed', 'cancelled', 'no_show'],
            **filter_kwargs
        ).order_by('-scheduled_time')
        
        # Paginate results
        page = self.paginate_queryset(appointments)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = self.get_serializer(appointments, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel an appointment."""
        appointment = self.get_object()
        serializer = CancelAppointmentSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Check if appointment can be cancelled
                if appointment.status in ['completed', 'cancelled', 'no_show']:
                    return Response(
                        {'detail': 'Cannot cancel an appointment that is already completed, cancelled, or marked as no-show.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Get cancellation reason
                reason = serializer.validated_data.get('reason', '')
                
                # Cancel appointment using service
                appointment = scheduling_service.cancel_appointment(
                    appointment=appointment,
                    reason=reason,
                    cancelled_by=request.user
                )
                
                # Send cancellation notifications
                notify_participants = serializer.validated_data.get('notify_participants', True)
                if notify_participants:
                    try:
                        notifications_service.send_appointment_cancellation(
                            appointment=appointment,
                            reason=reason,
                            notify_provider=True
                        )
                    except Exception as e:
                        logger.error(f"Failed to send cancellation notification: {str(e)}")
                
                # Return the updated appointment
                serializer = self.get_serializer(appointment)
                return Response(serializer.data)
                
            except Exception as e:
                logger.error(f"Error cancelling appointment: {str(e)}")
                return Response(
                    {'detail': f'Error cancelling appointment: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def reschedule(self, request, pk=None):
        """Reschedule an appointment."""
        appointment = self.get_object()
        serializer = RescheduleAppointmentSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Try to reschedule appointment using scheduling service
                appointment = scheduling_service.reschedule_appointment(
                    appointment=appointment,
                    new_start_time=serializer.validated_data['new_scheduled_time'],
                    new_end_time=serializer.validated_data['new_end_time'],
                    reason=serializer.validated_data.get('reason'),
                    updated_by=request.user
                )
                
                # Send confirmation notification
                notify_participants = serializer.validated_data.get('notify_participants', True)
                if notify_participants:
                    try:
                        notifications_service.send_appointment_confirmation(appointment)
                    except Exception as e:
                        logger.error(f"Failed to send reschedule notification: {str(e)}")
                
                # Return the updated appointment
                serializer = self.get_serializer(appointment)
                return Response(serializer.data)
                
            except scheduling_service.SchedulingException as e:
                return Response(
                    {'detail': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
            except Exception as e:
                logger.error(f"Error rescheduling appointment: {str(e)}")
                return Response(
                    {'detail': f'Error rescheduling appointment: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def available_slots(self, request):
        """Get available appointment slots for a provider."""
        # Get required parameters
        provider_id = request.query_params.get('provider_id')
        date_str = request.query_params.get('date')
        appointment_type = request.query_params.get('appointment_type')
        duration_minutes = request.query_params.get('duration_minutes', 30)
        
        if not provider_id or not date_str:
            return Response(
                {'detail': 'provider_id and date parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get provider
            provider = User.objects.get(id=provider_id, role='provider')
            
            # Parse date
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            # Get available slots
            slots = scheduling_service.get_available_slots(
                provider=provider,
                date=date,
                appointment_type=appointment_type,
                duration_minutes=int(duration_minutes)
            )
            
            # Serialize slots
            serializer = AvailabilitySlotSerializer(slots, many=True)
            return Response(serializer.data)
            
        except User.DoesNotExist:
            return Response(
                {'detail': 'Provider not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ValueError:
            return Response(
                {'detail': 'Invalid date format. Use YYYY-MM-DD.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error getting available slots: {str(e)}")
            return Response(
                {'detail': f'Error getting available slots: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def patient_vitals(self, request, pk=None):
        """Get recent vitals for a patient in preparation for appointment."""
        appointment = self.get_object()
        
        # Make sure user has permission to access this data
        self.check_object_permissions(request, appointment)
        
        # Determine the patient
        patient = appointment.patient
        
        try:
            # Get recent vitals from healthcare module
            recent_vitals = VitalSign.objects.filter(
                created_by=patient
            ).order_by('-measured_at')[:10]
            
            # Get recent vitals from wearables module
            recent_wearable_data = WearableMeasurement.objects.filter(
                user=patient,
                synced_to_healthcare=False  # Only get measurements not already in healthcare module
            ).order_by('-measured_at')[:20]
            
            # Process vital signs into a structured format
            vitals_data = {}
            
            for vital in recent_vitals:
                if vital.measurement_type not in vitals_data:
                    vitals_data[vital.measurement_type] = []
                
                vitals_data[vital.measurement_type].append({
                    'value': vital.value,
                    'unit': vital.unit,
                    'measured_at': vital.measured_at.isoformat(),
                    'source': vital.source
                })
            
            # Process wearable data
            for measurement in recent_wearable_data:
                # Map wearable measurement types to vital sign types
                measurement_map = {
                    'heart_rate': 'heart_rate',
                    'blood_pressure': 'blood_pressure',
                    'oxygen_saturation': 'oxygen_saturation',
                    'weight': 'weight',
                    'temperature': 'temperature',
                    'blood_glucose': 'blood_glucose',
                    'respiratory_rate': 'respiratory_rate'
                }
                
                vital_type = measurement_map.get(measurement.measurement_type)
                if vital_type:
                    if vital_type not in vitals_data:
                        vitals_data[vital_type] = []
                    
                    # Handle special case for blood pressure
                    if vital_type == 'blood_pressure' and measurement.systolic and measurement.diastolic:
                        vitals_data[vital_type].append({
                            'value': f"{measurement.systolic}/{measurement.diastolic}",
                            'unit': measurement.unit,
                            'measured_at': measurement.measured_at.isoformat(),
                            'source': f"{measurement.integration_type} ({measurement.device_model})"
                        })
                    else:
                        vitals_data[vital_type].append({
                            'value': str(measurement.value),
                            'unit': measurement.unit,
                            'measured_at': measurement.measured_at.isoformat(),
                            'source': f"{measurement.integration_type} ({measurement.device_model})"
                        })
            
            return Response(vitals_data)
            
        except Exception as e:
            logger.error(f"Error getting patient vitals: {str(e)}")
            return Response(
                {'detail': f'Error getting patient vitals: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def dashboard_summary(self, request):
        """Get appointment dashboard summary for different user types."""
        user = request.user
        
        if user.role == 'patient':
            return self._get_patient_dashboard(request)
        elif user.role == 'provider':
            return self._get_provider_dashboard(request)
        elif user.role == 'caregiver':
            return self._get_caregiver_dashboard(request)
        else:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    def _get_patient_dashboard(self, request):
        """Get patient-specific appointment dashboard."""
        patient = request.user
        now = timezone.now()
        
        # Get upcoming appointments
        upcoming = Appointment.objects.filter(
            patient=patient,
            scheduled_time__gte=now,
            status__in=[Appointment.Status.SCHEDULED, Appointment.Status.CONFIRMED]
        ).order_by('scheduled_time')[:5]
        
        # Get recent appointments
        recent = Appointment.objects.filter(
            patient=patient,
            scheduled_time__lt=now
        ).order_by('-scheduled_time')[:5]
        
        # Get rare disease consultation stats
        rare_condition_appointments = Appointment.objects.filter(
            patient=patient,
            medical_record__has_rare_condition=True
        )
        
        # Prepare dashboard data
        dashboard_data = {
            'upcoming_appointments': AppointmentSerializer(upcoming, many=True, context={'request': request}).data,
            'recent_appointments': AppointmentSerializer(recent, many=True, context={'request': request}).data,
            'statistics': {
                'total_appointments': Appointment.objects.filter(patient=patient).count(),
                'completed_appointments': Appointment.objects.filter(
                    patient=patient, 
                    status=Appointment.Status.COMPLETED
                ).count(),
                'rare_condition_appointments': rare_condition_appointments.count(),
                'telemedicine_appointments': Appointment.objects.filter(
                    patient=patient,
                    appointment_type__in=[
                        Appointment.AppointmentType.VIDEO_CONSULTATION,
                        Appointment.AppointmentType.PHONE_CONSULTATION
                    ]
                ).count()
            },
            'next_appointment': AppointmentSerializer(upcoming.first(), context={'request': request}).data if upcoming.exists() else None,
            'care_team_size': self._get_care_team_size(patient),
            'consultation_preparation': self._get_consultation_preparation_status(patient)
        }
        
        return Response(dashboard_data)

    def _get_provider_dashboard(self, request):
        """Get provider-specific appointment dashboard."""
        provider = request.user
        now = timezone.now()
        today = now.date()
        
        # Get today's appointments
        today_appointments = Appointment.objects.filter(
            provider=provider,
            scheduled_time__date=today
        ).order_by('scheduled_time')
        
        # Get upcoming appointments (next 7 days)
        upcoming = Appointment.objects.filter(
            provider=provider,
            scheduled_time__gte=now,
            scheduled_time__date__lte=today + timedelta(days=7),
            status__in=[Appointment.Status.SCHEDULED, Appointment.Status.CONFIRMED]
        ).order_by('scheduled_time')
        
        # Get rare disease patients requiring special attention
        rare_disease_patients = Appointment.objects.filter(
            provider=provider,
            medical_record__has_rare_condition=True,
            scheduled_time__gte=now
        ).values('patient').distinct()
        
        dashboard_data = {
            'today_appointments': AppointmentSerializer(today_appointments, many=True, context={'request': request}).data,
            'upcoming_appointments': AppointmentSerializer(upcoming[:10], many=True, context={'request': request}).data,
            'statistics': {
                'today_total': today_appointments.count(),
                'today_completed': today_appointments.filter(status=Appointment.Status.COMPLETED).count(),
                'upcoming_week': upcoming.count(),
                'rare_disease_patients': rare_disease_patients.count(),
                'telemedicine_today': today_appointments.filter(
                    appointment_type__in=[
                        Appointment.AppointmentType.VIDEO_CONSULTATION,
                        Appointment.AppointmentType.PHONE_CONSULTATION
                    ]
                ).count()
            },
            'current_consultation': self._get_current_consultation(provider),
            'waiting_room_status': self._get_waiting_room_status(provider),
            'alerts': self._get_provider_alerts(provider)
        }
        
        return Response(dashboard_data)

    def _get_caregiver_dashboard(self, request):
        """Get caregiver-specific appointment dashboard."""
        caregiver = request.user
        
        # Get patients under caregiver's care
        if hasattr(caregiver, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            from users.models import PatientAuthorizedCaregiver
            
            authorized_patients = User.objects.filter(
                patient_authorizations__caregiver=caregiver,
                patient_authorizations__access_level__in=['FULL', 'SCHEDULE']
            )
            
            # Get appointments for these patients
            upcoming_appointments = Appointment.objects.filter(
                patient__in=authorized_patients,
                scheduled_time__gte=timezone.now(),
                status__in=[Appointment.Status.SCHEDULED, Appointment.Status.CONFIRMED]
            ).order_by('scheduled_time')[:10]
            
            # Get recent appointments
            recent_appointments = Appointment.objects.filter(
                patient__in=authorized_patients,
                scheduled_time__lt=timezone.now()
            ).order_by('-scheduled_time')[:5]
            
            dashboard_data = {
                'patients_under_care': authorized_patients.count(),
                'upcoming_appointments': AppointmentSerializer(upcoming_appointments, many=True, context={'request': request}).data,
                'recent_appointments': AppointmentSerializer(recent_appointments, many=True, context={'request': request}).data,
                'care_alerts': self._get_caregiver_alerts(authorized_patients),
                'medication_reminders': self._get_caregiver_medication_reminders(authorized_patients)
            }
            
            return Response(dashboard_data)
        
        return Response({'error': 'Caregiver profile not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'])
    def prepare_rare_disease_consultation(self, request, pk=None):
        """Prepare data for rare disease consultation."""
        appointment = self.get_object()
        
        if request.user != appointment.provider:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        
        preparation_data = RareDiseaseConsultationService.prepare_rare_disease_consultation(appointment)
        
        if 'error' in preparation_data:
            return Response(preparation_data, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(preparation_data)

    @action(detail=True, methods=['post'])
    def send_care_team_notification(self, request, pk=None):
        """Send notification to patient's care team."""
        appointment = self.get_object()
        
        if request.user not in [appointment.patient, appointment.provider]:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        
        notification_type = request.data.get('notification_type', 'general')
        message = request.data.get('message', '')
        
        # Get consultation if exists
        consultation = appointment.consultations.first()
        
        if consultation:
            success = RareDiseaseConsultationService.notify_care_team(consultation, notification_type)
            
            if success:
                return Response({'message': 'Care team notified successfully'})
            else:
                return Response({'error': 'Failed to notify care team'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({'error': 'No consultation found'}, status=status.HTTP_404_NOT_FOUND)


class ConsultationViewSet(viewsets.ModelViewSet):
    """ViewSet for telemedicine consultations."""
    queryset = Consultation.objects.all()
    serializer_class = ConsultationSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['appointment', 'status', 'platform']
    ordering_fields = ['start_time', 'created_at']
    ordering = ['-created_at']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, IsPatientProviderOrAdmin]
    
    def get_queryset(self):
        """Filter consultations based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter based on user role
        if user.role == 'patient':
            return queryset.filter(appointment__patient=user)
        elif user.role == 'provider':
            return queryset.filter(appointment__provider=user)
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(appointment__patient__in=authorized_patients)
        
        # Admin can see all
        return queryset
    
    def get_permissions(self):
        """Adjust permissions based on action."""
        permissions_classes = [permissions.IsAuthenticated, IsApprovedUser]
        
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permissions_classes.append(IsProviderOrAdmin)
        elif self.action == 'start':
            permissions_classes.append(CanStartConsultation)
        elif self.action == 'join_info':
            permissions_classes.append(CanJoinConsultation)
        else:
            permissions_classes.append(IsPatientProviderOrAdmin)
            
        return [permission() for permission in permissions_classes]
    
    @transaction.atomic
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a consultation."""
        consultation = self.get_object()
        serializer = ConsultationStartSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Check if consultation can be started
                if consultation.status != Consultation.Status.SCHEDULED:
                    return Response(
                        {'detail': 'Consultation can only be started if it is scheduled.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Update consultation status
                consultation.status = Consultation.Status.IN_PROGRESS
                consultation.start_time = timezone.now()
                consultation.platform = serializer.validated_data.get('platform', Consultation.Platform.ZOOM)
                consultation.recording_enabled = serializer.validated_data.get('recording_enabled', False)
                consultation.recording_consent = serializer.validated_data.get('recording_consent', False)
                
                # Add initial notes if provided
                initial_notes = serializer.validated_data.get('initial_notes', '')
                if initial_notes:
                    consultation.notes = initial_notes
                
                # Create meeting if platform is set and not already created
                if consultation.platform and not consultation.meeting_id:
                    try:
                        # Get appointment details
                        appointment = consultation.appointment
                        provider_email = appointment.provider.email if appointment.provider else None
                        patient_email = appointment.patient.email if appointment.patient else None
                        
                        # Only create meeting if provider email is available
                        if provider_email:
                            # Use platform service to create meeting
                            from .services import platform_service
                            
                            meeting_data = platform_service.create_meeting(
                                consultation=consultation,
                                platform=consultation.platform,
                                organizer_email=provider_email,
                                patient_email=patient_email
                            )
                            
                            # Update consultation with meeting details
                            consultation.meeting_id = meeting_data.get('meeting_id', '')
                            consultation.join_url = meeting_data.get('join_url', '')
                            consultation.password = meeting_data.get('password', '')
                            
                            # Store platform-specific data
                            if 'platform_data' in meeting_data:
                                consultation.platform_data = meeting_data['platform_data']
                        
                    except Exception as e:
                        logger.error(f"Meeting creation failed: {str(e)}")
                        return Response(
                            {'detail': f'Failed to create video conference: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                
                # Save consultation changes
                consultation.save()
                
                # Update appointment status
                appointment = consultation.appointment
                appointment.status = Appointment.Status.IN_PROGRESS
                appointment.save(update_fields=['status'])
                
                # Send notification to patient
                try:
                    notifications_service.send_consultation_start_notification(consultation)
                except Exception as e:
                    logger.warning(f"Failed to send consultation start notification: {str(e)}")
                
                # Return updated consultation
                serializer = self.get_serializer(consultation)
                return Response(serializer.data)
                
            except Exception as e:
                logger.error(f"Error starting consultation: {str(e)}")
                return Response(
                    {'detail': f'Error starting consultation: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['post'])
    def end(self, request, pk=None):
        """End a consultation."""
        consultation = self.get_object()
        serializer = ConsultationEndSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Check if consultation can be ended
                if consultation.status != Consultation.Status.IN_PROGRESS:
                    return Response(
                        {'detail': 'Consultation can only be ended if it is in progress.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Update consultation status
                consultation.status = Consultation.Status.COMPLETED
                consultation.end_time = timezone.now()
                
                # Calculate duration in minutes
                if consultation.start_time:
                    duration = (consultation.end_time - consultation.start_time).total_seconds() / 60
                    consultation.duration = int(duration)
                
                # Update other fields if provided
                for field in ['notes', 'diagnosis', 'treatment_plan', 'technical_issues', 'connection_quality']:
                    if field in serializer.validated_data:
                        setattr(consultation, field, serializer.validated_data[field])
                
                # Update follow-up information
                consultation.follow_up_required = serializer.validated_data.get('follow_up_required', False)
                if consultation.follow_up_required and 'follow_up_date' in serializer.validated_data:
                    consultation.follow_up_date = serializer.validated_data['follow_up_date']
                
                # Save consultation changes
                consultation.save()
                
                # Update appointment status
                appointment = consultation.appointment
                appointment.status = Appointment.Status.COMPLETED
                appointment.save(update_fields=['status'])
                
                # Return updated consultation
                serializer = self.get_serializer(consultation)
                return Response(serializer.data)
                
            except Exception as e:
                logger.error(f"Error ending consultation: {str(e)}")
                return Response(
                    {'detail': f'Error ending consultation: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def join_info(self, request, pk=None):
        """Get join information for a consultation."""
        consultation = self.get_object()
        
        # Check if consultation has video conference details
        if not consultation.meeting_id or not consultation.join_url:
            return Response(
                {'detail': 'No video conference information available for this consultation.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if consultation is ready to join
        if consultation.status not in [Consultation.Status.READY, Consultation.Status.IN_PROGRESS]:
            return Response(
                {'detail': f'Consultation is not ready to join (status: {consultation.get_status_display()}).'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Generate join info using platform service
            from .services import platform_service
            join_info = platform_service.get_join_info(consultation)
            
            # Create serializer with the data
            serializer = JoinInfoSerializer(join_info)
            
            # Update join time based on user role
            now = timezone.now()
            if request.user == consultation.appointment.patient and not consultation.patient_join_time:
                consultation.patient_join_time = now
                consultation.save(update_fields=['patient_join_time'])
            elif request.user == consultation.appointment.provider and not consultation.provider_join_time:
                consultation.provider_join_time = now
                consultation.save(update_fields=['provider_join_time'])
            
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error getting join information: {str(e)}")
            return Response(
                {'detail': f'Error getting join information: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    @action(detail=True, methods=['post'])
    def recording(self, request, pk=None):
        """Update recording settings for a consultation."""
        consultation = self.get_object()
            
            # Check permissions
        if request.user != consultation.appointment.provider and not request.user.is_staff:
            return Response(
                {'detail': 'Only the provider can update recording settings.'},
                status=status.HTTP_403_FORBIDDEN
                )
        
        # Get recording parameters
        recording_enabled = request.data.get('recording_enabled', False)
        recording_consent = request.data.get('recording_consent', False)
            
        # Validate consent if enabling recording
        if recording_enabled and not recording_consent:
            return Response(
                {'detail': 'Patient consent is required for recording.'},
                status=status.HTTP_400_BAD_REQUEST
                )
            
        # Update consultation
        consultation.recording_enabled = recording_enabled
        consultation.recording_consent = recording_consent
        consultation.save(update_fields=['recording_enabled', 'recording_consent'])
            
        # If using Zoom and consultation is in progress, update recording settings in Zoom
        if (consultation.platform == Consultation.Platform.ZOOM and 
            consultation.status == Consultation.Status.IN_PROGRESS and
            consultation.meeting_id):
            try:
                # This is a placeholder - in a real implementation, you would call the Zoom API to update recording settings
                logger.info(f"Would update Zoom recording settings for meeting {consultation.meeting_id}")
            except Exception as e:
                logger.error(f"Failed to update Zoom recording settings: {str(e)}")
            
            serializer = self.get_serializer(consultation)
            return Response(serializer.data)


class PrescriptionViewSet(viewsets.ModelViewSet):
    """ViewSet for electronic prescriptions."""
    queryset = Prescription.objects.all()
    serializer_class = PrescriptionSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ['patient', 'provider', 'status', 'consultation', 'prescribed_date']
    search_fields = ['medication_name', 'instructions', 'pharmacy_notes']
    ordering_fields = ['prescribed_time', 'created_at', 'updated_at']
    ordering = ['-prescribed_time']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, CanViewPrescription]
    
    def get_queryset(self):
        """Filter prescriptions based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter based on user role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'provider':
            return queryset.filter(provider=user)
        elif user.role == 'pharmco':
            return queryset.filter(status__in=['pending', 'active'])
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(patient__in=authorized_patients)
        
        # Admin can see all
        return queryset
    
    def get_permissions(self):
        """Adjust permissions based on action."""
        if self.action in ['create', 'update', 'partial_update']:
            return [permissions.IsAuthenticated(), IsApprovedUser(), CanPrescribe()]
        
        return super().get_permissions()
    
    def perform_create(self, serializer):
        """Create prescription with automatic fields."""
        # Set expiration date if not provided
        if 'expiration_date' not in serializer.validated_data:
            # Default to 90 days from prescription date
            prescribed_date = timezone.now().date()
            expiration_date = prescribed_date + timezone.timedelta(days=90)
            serializer.save(expiration_date=expiration_date)
        else:
            serializer.save()
        
        # Send notification to patient
        try:
            prescription = serializer.instance
            notifications_service.send_prescription_notification(prescription)
        except Exception as e:
            logger.error(f"Failed to send prescription notification: {str(e)}")
    
    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update prescription status."""
        prescription = self.get_object()
        
        # Get new status
        new_status = request.data.get('status')
        if not new_status or new_status not in dict(Prescription.Status.choices).keys():
            return Response(
                {'detail': f'Invalid status. Must be one of: {", ".join(dict(Prescription.Status.choices).keys())}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate status transition
        valid_transitions = {
            'draft': ['pending', 'cancelled'],
            'pending': ['active', 'denied', 'cancelled'],
            'active': ['filled', 'completed', 'cancelled'],
            'filled': ['completed', 'cancelled'],
            'completed': [],
            'cancelled': [],
            'expired': [],
            'denied': ['pending']
        }
        
        if new_status not in valid_transitions.get(prescription.status, []):
            return Response(
                {'detail': f'Invalid status transition from {prescription.status} to {new_status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update prescription
        prescription.status = new_status
        
        # Update fill date if status is filled
        if new_status == 'filled':
            prescription.fill_date = timezone.now().date()
        
        prescription.save()
        
        # Return updated prescription
        serializer = self.get_serializer(prescription)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def active(self, request):
        """Get active prescriptions."""
        # Get patient ID if provided
        patient_id = request.query_params.get('patient_id')
        
        # Start with all prescriptions from the queryset
        queryset = self.get_queryset()
        
        # Filter by patient if specified
        if patient_id:
            queryset = queryset.filter(patient_id=patient_id)
            
        # Filter by active status
        queryset = queryset.filter(status='active')
        
        # Check for expiration
        today = timezone.now().date()
        queryset = queryset.filter(
            Q(expiration_date__isnull=True) | Q(expiration_date__gte=today)
        )
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ProviderAvailabilityViewSet(viewsets.ModelViewSet):
    """ViewSet for provider availability."""
    queryset = ProviderAvailability.objects.all()
    serializer_class = ProviderAvailabilitySerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['provider', 'is_available', 'start_time']
    ordering_fields = ['start_time', 'created_at']
    ordering = ['start_time']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, CanManageProviderAvailability]
    
    def get_queryset(self):
        """Filter availability based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Providers can only see their own availability
        if user.role == 'provider':
            queryset = queryset.filter(provider=user)
            
        # Get date range from query parameters
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                start_datetime = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
                queryset = queryset.filter(end_time__gte=start_datetime)
            except ValueError:
                pass
                
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                end_datetime = timezone.make_aware(datetime.combine(end_date, datetime.max.time()))
                queryset = queryset.filter(start_time__lte=end_datetime)
            except ValueError:
                pass
        
        return queryset
    
    def perform_create(self, serializer):
        """Set provider field for new availability blocks."""
        if self.request.user.role == 'provider':
            serializer.save(provider=self.request.user)
        else:
            serializer.save()
    
    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        """Create multiple availability slots at once."""
        if not isinstance(request.data, list):
            return Response(
                {'detail': 'Expected a list of availability slots'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        created_slots = []
        errors = []
        
        for item in request.data:
            serializer = self.get_serializer(data=item)
            if serializer.is_valid():
                try:
                    if request.user.role == 'provider':
                        slot = serializer.save(provider=request.user)
                    else:
                        slot = serializer.save()
                    created_slots.append(self.get_serializer(slot).data)
                except Exception as e:
                    errors.append({
                        'data': item,
                        'error': str(e)
                    })
            else:
                errors.append({
                    'data': item,
                    'error': serializer.errors
                })
        
        return Response({
            'created': created_slots,
            'errors': errors
        })
    
    @action(detail=False, methods=['get'])
    def provider_schedule(self, request):
        """Get a provider's schedule with availability and appointments."""
        # Get required parameters
        provider_id = request.query_params.get('provider_id')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if not provider_id or not start_date:
            return Response(
                {'detail': 'provider_id and start_date parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get provider
            provider = User.objects.get(id=provider_id, role='provider')
            
            # Parse dates
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            
            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            
            # Get schedule
            schedule = scheduling_service.get_provider_schedule(
                provider=provider,
                start_date=start_date,
                end_date=end_date
            )
            
            return Response(schedule)
            
        except User.DoesNotExist:
            return Response(
                {'detail': 'Provider not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ValueError:
            return Response(
                {'detail': 'Invalid date format. Use YYYY-MM-DD.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error getting provider schedule: {str(e)}")
            return Response(
                {'detail': f'Error getting provider schedule: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class WaitingRoomViewSet(viewsets.ModelViewSet):
    """ViewSet for virtual waiting rooms."""
    queryset = WaitingRoom.objects.all()
    serializer_class = WaitingRoomSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['provider', 'is_active']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['provider', 'name']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, CanManageWaitingRoom]
    
    def get_queryset(self):
        """Filter waiting rooms based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Providers can only see their own waiting rooms
        if user.role == 'provider':
            queryset = queryset.filter(provider=user)
        
        return queryset
    
    def perform_create(self, serializer):
        """Set provider field for new waiting rooms."""
        if self.request.user.role == 'provider':
            serializer.save(provider=self.request.user)
        else:
            serializer.save()
    
    @action(detail=True, methods=['get'])
    def patients(self, request, pk=None):
        """Get patients currently in the waiting room."""
        waiting_room = self.get_object()
        
        # Get only waiting patients
        waiting_patients = waiting_room.patients.filter(status='waiting').order_by('checked_in_time')
        
        serializer = WaitingRoomPatientSerializer(waiting_patients, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def check_in(self, request, pk=None):
        """Check a patient into the waiting room."""
        waiting_room = self.get_object()
        serializer = CheckInPatientSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                appointment_id = serializer.validated_data['appointment_id']
                notes = serializer.validated_data.get('notes', '')
                
                # Get the appointment
                appointment = Appointment.objects.get(id=appointment_id)
                
                # Check if appointment is valid for this waiting room
                if appointment.provider != waiting_room.provider:
                    return Response(
                        {'detail': 'Appointment is not with this provider'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if appointment is today
                today = timezone.now().date()
                if appointment.scheduled_time.date() != today:
                    return Response(
                        {'detail': 'Appointment is not scheduled for today'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if already in waiting room
                existing_entry = WaitingRoomPatient.objects.filter(
                    waiting_room=waiting_room,
                    appointment=appointment,
                    status='waiting'
                ).first()
                
                if existing_entry:
                    return Response(
                        {'detail': 'Patient is already in waiting room'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Create waiting room entry
                waiting_room_patient = WaitingRoomPatient.objects.create(
                    waiting_room=waiting_room,
                    appointment=appointment,
                    status='waiting',
                    notes=notes
                )
                
                # Update appointment status
                appointment.status = Appointment.Status.CHECKED_IN
                appointment.save(update_fields=['status'])
                
                # Return the created entry
                response_serializer = WaitingRoomPatientSerializer(waiting_room_patient)
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)
                
            except Appointment.DoesNotExist:
                return Response(
                    {'detail': 'Appointment not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                logger.error(f"Error checking in patient: {str(e)}")
                return Response(
                    {'detail': f'Error checking in patient: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def patient_ready(self, request, pk=None):
        """Mark a patient as ready for consultation."""
        waiting_room = self.get_object()
        serializer = PatientReadySerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                waiting_room_patient_id = serializer.validated_data['waiting_room_patient_id']
                
                # Get the waiting room patient entry
                waiting_room_patient = get_object_or_404(
                    WaitingRoomPatient,
                    id=waiting_room_patient_id,
                    waiting_room=waiting_room,
                    status='waiting'
                )
                
                # Mark as ready
                waiting_room_patient.status = WaitingRoomPatient.Status.READY
                waiting_room_patient.ready_time = timezone.now()
                waiting_room_patient.save(update_fields=['status', 'ready_time'])
                
                # Get or create consultation
                appointment = waiting_room_patient.appointment
                consultation, created = Consultation.objects.get_or_create(
                    appointment=appointment,
                    defaults={
                        'status': Consultation.Status.READY
                    }
                )
                
                # Update consultation status if not created
                if not created and consultation.status not in ['in_progress', 'completed', 'cancelled']:
                    consultation.status = Consultation.Status.READY
                    consultation.save(update_fields=['status'])
                
                # Return the updated entry with consultation info
                response_serializer = WaitingRoomPatientSerializer(waiting_room_patient)
                return Response({
                    'waiting_room_patient': response_serializer.data,
                    'consultation_id': consultation.id,
                    'consultation_status': consultation.get_status_display()
                })
                
            except WaitingRoomPatient.DoesNotExist:
                return Response(
                    {'detail': 'Patient not found in waiting room'},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                logger.error(f"Error marking patient ready: {str(e)}")
                return Response(
                    {'detail': f'Error marking patient ready: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WaitingRoomPatientViewSet(viewsets.ModelViewSet):
    """ViewSet for patients in virtual waiting room."""
    queryset = WaitingRoomPatient.objects.all()
    serializer_class = WaitingRoomPatientSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['waiting_room', 'appointment', 'status']
    ordering_fields = ['checked_in_time', 'ready_time']
    ordering = ['checked_in_time']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, CanManageWaitingRoom]
    
    def get_queryset(self):
        """Filter waiting room patients based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Providers can only see patients in their waiting rooms
        if user.role == 'provider':
            queryset = queryset.filter(waiting_room__provider=user)
        
        # Get only active statuses by default
        if not self.request.query_params.get('status'):
            queryset = queryset.filter(status__in=['waiting', 'ready'])
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a waiting room entry."""
        waiting_room_patient = self.get_object()
        
        # Mark as cancelled
        waiting_room_patient.status = WaitingRoomPatient.Status.CANCELLED
        waiting_room_patient.save(update_fields=['status'])
        
        serializer = self.get_serializer(waiting_room_patient)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete a waiting room entry."""
        waiting_room_patient = self.get_object()
        
        # Mark as completed
        waiting_room_patient.status = WaitingRoomPatient.Status.COMPLETED
        waiting_room_patient.save(update_fields=['status'])
        
        serializer = self.get_serializer(waiting_room_patient)
        return Response(serializer.data)


class ConsultationNoteViewSet(viewsets.ModelViewSet):
    """ViewSet for consultation notes."""
    queryset = ConsultationNote.objects.all()
    serializer_class = ConsultationNoteSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['consultation', 'is_complete']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, CanViewHealthData]
    
    def get_queryset(self):
        """Filter consultation notes based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter based on user role
        if user.role == 'patient':
            return queryset.filter(consultation__appointment__patient=user)
        elif user.role == 'provider':
            return queryset.filter(consultation__appointment__provider=user)
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(consultation__appointment__patient__in=authorized_patients)
        
        # Admin can see all
        return queryset
    
    def perform_create(self, serializer):
        """Set created_by field for new notes."""
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def mark_complete(self, request, pk=None):
        """Mark note as complete."""
        note = self.get_object()
        
        # Check if user is the provider
        if request.user != note.consultation.appointment.provider and not request.user.is_staff:
            return Response(
                {'detail': 'Only the provider can mark notes as complete'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Mark as complete
        note.is_complete = True
        note.completed_at = timezone.now()
        note.save(update_fields=['is_complete', 'completed_at'])
        
        serializer = self.get_serializer(note)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def templates(self, request):
        """Get available note templates."""
        # This would typically be loaded from a database or configuration
        # For now, return some example templates
        templates = [
            {
                'id': 'soap',
                'name': 'SOAP Note',
                'sections': [
                    {'id': 'subjective', 'name': 'Subjective', 'description': "Patient's subjective experience"},
                    {'id': 'objective', 'name': 'Objective', 'description': "Objective observations"},
                    {'id': 'assessment', 'name': 'Assessment', 'description': "Provider's assessment"},
                    {'id': 'plan', 'name': 'Plan', 'description': "Treatment plan"}
                ]
            },
            {
                'id': 'comprehensive',
                'name': 'Comprehensive Note',
                'sections': [
                    {'id': 'chief_complaint', 'name': 'Chief Complaint', 'description': "Reason for visit"},
                    {'id': 'history_present_illness', 'name': 'History of Present Illness', 'description': "Details of current symptoms"},
                    {'id': 'past_medical_history', 'name': 'Past Medical History', 'description': "Relevant medical history"},
                    {'id': 'medications', 'name': 'Medications', 'description': "Current medications"},
                    {'id': 'allergies', 'name': 'Allergies', 'description': "Known allergies"},
                    {'id': 'review_of_systems', 'name': 'Review of Systems', 'description': "Systematic review"},
                    {'id': 'physical_examination', 'name': 'Physical Examination', 'description': "Findings on examination"},
                    {'id': 'assessment', 'name': 'Assessment', 'description': "Diagnosis and assessment"},
                    {'id': 'plan', 'name': 'Plan', 'description': "Treatment plan"}
                ]
            }
        ]
        
        return Response(templates)
