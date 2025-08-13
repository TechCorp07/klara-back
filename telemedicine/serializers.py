from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import (
    Appointment, Consultation, Prescription, 
    ProviderAvailability, WaitingRoom, WaitingRoomPatient,
    ConsultationNote
)
from healthcare.serializers import UserBasicSerializer, MedicalRecordSerializer, ConditionSerializer

User = get_user_model()


class ProviderAvailabilitySerializer(serializers.ModelSerializer):
    """Serializer for provider availability."""
    provider_details = UserBasicSerializer(source='provider', read_only=True)
    is_booked = serializers.BooleanField(read_only=True)
    duration_minutes = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = ProviderAvailability
        fields = '__all__'
        read_only_fields = ('created_at',)


class AppointmentSerializer(serializers.ModelSerializer):
    """Serializer for appointments."""
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    provider_details = UserBasicSerializer(source='provider', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    appointment_type_display = serializers.CharField(source='get_appointment_type_display', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    meeting_url = serializers.SerializerMethodField()
    meeting_id = serializers.SerializerMethodField()
    telemedicine_ready = serializers.SerializerMethodField()
    
    class Meta:
        model = Appointment
        fields = (
            'id', 'patient', 'provider', 'medical_record', 'related_condition',
            'scheduled_time', 'end_time', 'duration_minutes', 'timezone',
            'status', 'appointment_type', 'priority', 'reason', 'notes',
            'reminders_enabled', 'reminder_sent', 'reminder_sent_time',
            'insurance_verified', 'copay_amount', 'copay_collected',
            'availability_block', 'created_at', 'updated_at',
            'patient_details', 'provider_details', 'status_display',
            'appointment_type_display', 'priority_display',
            'meeting_url', 'meeting_id', 'telemedicine_ready'
        )
        read_only_fields = (
            'created_at', 'updated_at', 'reminder_sent', 'reminder_sent_time',
            'status_display', 'appointment_type_display', 'priority_display',
            'meeting_url', 'meeting_id', 'telemedicine_ready'
        )
        
    def get_meeting_url(self, obj):
        """Get meeting URL if telemedicine appointment has consultation."""
        if obj.is_telemedicine:
            consultation = obj.consultations.first()
            return consultation.join_url if consultation else None
        return None
    
    def get_meeting_id(self, obj):
        """Get meeting ID if telemedicine appointment has consultation."""
        if obj.is_telemedicine:
            consultation = obj.consultations.first()
            return consultation.meeting_id if consultation else None
        return None
    
    def get_telemedicine_ready(self, obj):
        """Check if telemedicine setup is complete."""
        if obj.is_telemedicine:
            consultation = obj.consultations.first()
            return bool(consultation and consultation.join_url)
        return False
    
    def validate(self, data):
        """
        Validate appointment data.
        - End time must be after start time
        - Cannot schedule in the past
        """
        if 'scheduled_time' in data and 'end_time' in data:
            if data['end_time'] <= data['scheduled_time']:
                raise serializers.ValidationError(
                    {"end_time": "End time must be after scheduled time"}
                )
                
            # Check if appointment is in the past
            now = timezone.now()
            if data['scheduled_time'] < now:
                raise serializers.ValidationError(
                    {"scheduled_time": "Cannot schedule appointments in the past"}
                )
                
        return data
    
    def create(self, validated_data):
        """
        Create appointment with proper metadata.
        """
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
            validated_data['updated_by'] = request.user
            
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """
        Update appointment with proper metadata.
        """
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['updated_by'] = request.user
            
        return super().update(instance, validated_data)


class AppointmentDetailSerializer(AppointmentSerializer):
    """Extended serializer for appointments with additional related data."""
    medical_record_details = MedicalRecordSerializer(source='medical_record', read_only=True)
    related_condition_details = ConditionSerializer(source='related_condition', read_only=True)
    availability_details = ProviderAvailabilitySerializer(source='availability_block', read_only=True)
    
    class Meta(AppointmentSerializer.Meta):
        fields = AppointmentSerializer.Meta.fields + (
            'medical_record_details', 'related_condition_details', 
            'availability_details', 'encrypted_metadata'
        )


class ConsultationSerializer(serializers.ModelSerializer):
    """Serializer for consultations."""
    appointment_details = AppointmentSerializer(source='appointment', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    platform_display = serializers.CharField(source='get_platform_display', read_only=True)
    patient = serializers.SerializerMethodField(read_only=True)
    provider = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Consultation
        fields = (
            'id', 'appointment', 'status', 'platform', 'start_time', 'end_time',
            'duration', 'patient_join_time', 'provider_join_time', 'notes', 
            'diagnosis', 'treatment_plan', 'follow_up_required', 'follow_up_date',
            'vital_signs', 'meeting_id', 'join_url', 'password', 
            'recording_enabled', 'recording_consent', 'technical_issues',
            'connection_quality', 'created_at', 'updated_at',
            'appointment_details', 'status_display', 'platform_display',
            'patient', 'provider'
        )
        read_only_fields = (
            'created_at', 'updated_at', 'duration', 'meeting_id',
            'join_url', 'password', 'status_display', 'platform_display',
            'patient', 'provider'
        )
        extra_kwargs = {
            'host_key': {'write_only': True},
            'platform_data': {'write_only': True},
        }
    
    def get_patient(self, obj):
        """Get patient details."""
        if obj.appointment and obj.appointment.patient:
            return UserBasicSerializer(obj.appointment.patient).data
        return None
    
    def get_provider(self, obj):
        """Get provider details."""
        if obj.appointment and obj.appointment.provider:
            return UserBasicSerializer(obj.appointment.provider).data
        return None


class PrescriptionSerializer(serializers.ModelSerializer):
    """Serializer for prescriptions."""
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    provider_details = UserBasicSerializer(source='provider', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    prescription_type_display = serializers.CharField(source='get_prescription_type_display', read_only=True)
    days_until_expiration = serializers.IntegerField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Prescription
        fields = (
            'id', 'patient', 'provider', 'consultation', 'prescription_type',
            'status', 'medication_name', 'dosage', 'frequency', 'duration',
            'quantity', 'refills', 'instructions', 'prescribed_date', 'prescribed_time',
            'fill_date', 'expiration_date', 'pharmacy_notes', 'pharmacy_id',
            'external_rx_id', 'patient_notified', 'patient_notification_time',
            'is_electronically_sent', 'sent_timestamp', 'send_method',
            'electronic_rx_reference', 'ndc_code', 'generic_allowed',
            'prior_authorization_required', 'drug_interaction_checked',
            'drug_allergy_checked', 'created_at', 'updated_at',
            'patient_details', 'provider_details', 'status_display',
            'prescription_type_display', 'days_until_expiration', 'is_active'
        )
        read_only_fields = (
            'created_at', 'updated_at', 'prescribed_date', 'prescribed_time',
            'status_display', 'prescription_type_display', 'days_until_expiration',
            'is_active'
        )
        ref_name = "TelemedicinePrescriptionSerializer"
    
    def validate(self, data):
        """
        Validate prescription data.
        - Refills must be a non-negative integer
        - Dosage and frequency are required
        """
        if 'refills' in data and data['refills'] < 0:
            raise serializers.ValidationError(
                {"refills": "Refills cannot be a negative number"}
            )
        
        return data


class WaitingRoomSerializer(serializers.ModelSerializer):
    """Serializer for virtual waiting rooms."""
    provider_details = UserBasicSerializer(source='provider', read_only=True)
    patient_count = serializers.SerializerMethodField()
    
    class Meta:
        model = WaitingRoom
        fields = (
            'id', 'name', 'provider', 'is_active', 'estimated_wait_time',
            'custom_message', 'created_at', 'updated_at', 'provider_details',
            'patient_count'
        )
        read_only_fields = ('created_at', 'updated_at', 'patient_count')
    
    def get_patient_count(self, obj):
        """Get count of patients currently in waiting room."""
        return obj.patients.filter(status='waiting').count()


class WaitingRoomPatientSerializer(serializers.ModelSerializer):
    """Serializer for patients in waiting room."""
    patient_details = serializers.SerializerMethodField()
    appointment_details = AppointmentSerializer(source='appointment', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    wait_duration = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = WaitingRoomPatient
        fields = (
            'id', 'waiting_room', 'appointment', 'status', 'checked_in_time',
            'ready_time', 'notes', 'patient_details', 'appointment_details',
            'status_display', 'wait_duration'
        )
        read_only_fields = (
            'checked_in_time', 'ready_time', 'patient_details',
            'status_display', 'wait_duration'
        )
    
    def get_patient_details(self, obj):
        """Get patient details."""
        if obj.appointment and obj.appointment.patient:
            return UserBasicSerializer(obj.appointment.patient).data
        return None


class ConsultationNoteSerializer(serializers.ModelSerializer):
    """Serializer for consultation notes."""
    consultation_details = ConsultationSerializer(source='consultation', read_only=True)
    created_by_details = UserBasicSerializer(source='created_by', read_only=True)
    
    class Meta:
        model = ConsultationNote
        fields = (
            'id', 'consultation', 'subjective', 'objective', 'assessment', 'plan',
            'chief_complaint', 'history_present_illness', 'past_medical_history',
            'medications', 'allergies', 'review_of_systems', 'physical_examination',
            'diagnostic_results', 'vital_signs', 'is_complete', 'completed_at',
            'template_used', 'created_at', 'updated_at', 'created_by',
            'consultation_details', 'created_by_details'
        )
        read_only_fields = (
            'created_at', 'updated_at', 'completed_at',
            'consultation_details', 'created_by_details'
        )


# Specialized action serializers
class JoinInfoSerializer(serializers.Serializer):
    """Serializer for consultation join information."""
    meeting_id = serializers.CharField()
    join_url = serializers.URLField()
    password = serializers.CharField()
    platform = serializers.CharField()
    platform_display = serializers.CharField()


class CancelAppointmentSerializer(serializers.Serializer):
    """Serializer for cancelling appointments."""
    reason = serializers.CharField(required=False, allow_blank=True)
    notify_participants = serializers.BooleanField(default=True)


class RescheduleAppointmentSerializer(serializers.Serializer):
    """Serializer for rescheduling appointments."""
    new_scheduled_time = serializers.DateTimeField(required=True)
    new_end_time = serializers.DateTimeField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True)
    notify_participants = serializers.BooleanField(default=True)
    
    def validate(self, data):
        """
        Validate rescheduling data.
        - New end time must be after new start time
        - Cannot reschedule in the past
        """
        if data['new_end_time'] <= data['new_scheduled_time']:
            raise serializers.ValidationError(
                {"new_end_time": "End time must be after scheduled time"}
            )
            
        # Check if new appointment time is in the past
        now = timezone.now()
        if data['new_scheduled_time'] < now:
            raise serializers.ValidationError(
                {"new_scheduled_time": "Cannot reschedule appointments in the past"}
            )
            
        return data


class ConsultationStartSerializer(serializers.Serializer):
    """Serializer for starting a consultation."""
    platform = serializers.ChoiceField(
        choices=Consultation.Platform.choices,
        default=Consultation.Platform.ZOOM
    )
    recording_enabled = serializers.BooleanField(default=False)
    recording_consent = serializers.BooleanField(default=False)
    initial_notes = serializers.CharField(required=False, allow_blank=True)
    custom_meeting_id = serializers.CharField(required=False, allow_blank=True)


class ConsultationEndSerializer(serializers.Serializer):
    """Serializer for ending a consultation."""
    notes = serializers.CharField(required=False, allow_blank=True)
    diagnosis = serializers.CharField(required=False, allow_blank=True)
    treatment_plan = serializers.CharField(required=False, allow_blank=True)
    follow_up_required = serializers.BooleanField(default=False)
    follow_up_date = serializers.DateField(required=False, allow_null=True)
    technical_issues = serializers.CharField(required=False, allow_blank=True)
    connection_quality = serializers.IntegerField(required=False, min_value=1, max_value=5, allow_null=True)


class AvailabilitySlotSerializer(serializers.Serializer):
    """Serializer for availability slots."""
    start_time = serializers.DateTimeField()
    end_time = serializers.DateTimeField()
    is_available = serializers.BooleanField()
    duration_minutes = serializers.IntegerField(read_only=True)


class CheckInPatientSerializer(serializers.Serializer):
    """Serializer for checking in a patient to waiting room."""
    appointment_id = serializers.IntegerField(required=True)
    notes = serializers.CharField(required=False, allow_blank=True)


class PatientReadySerializer(serializers.Serializer):
    """Serializer for marking a patient as ready for consultation."""
    patient_id = serializers.IntegerField(required=True)
    waiting_room_patient_id = serializers.IntegerField(required=True)
