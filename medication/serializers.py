from rest_framework import serializers
from django.contrib.auth import get_user_model
from healthcare.serializers import UserBasicSerializer, ConditionSerializer
from .models import (
    Medication, Prescription, MedicationIntake, MedicationReminder,
    AdherenceRecord, SideEffect, DrugInteraction
)

User = get_user_model()


class PrescriptionSerializer(serializers.ModelSerializer):
    """Serializer for prescriptions."""
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    prescriber_details = UserBasicSerializer(source='prescriber', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    days_until_expiration = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = Prescription
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'created_by', 'updated_by')
        ref_name = "MedicationPrescriptionSerializer"
    
    def get_days_until_expiration(self, obj):
        return obj.days_until_expiration()
    
    def get_is_expired(self, obj):
        return obj.is_expired()
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
            validated_data['updated_by'] = request.user
        
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['updated_by'] = request.user
        
        return super().update(instance, validated_data)


class MedicationIntakeSerializer(serializers.ModelSerializer):
    """Serializer for medication intakes."""
    medication_details = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    recorded_by_details = UserBasicSerializer(source='recorded_by', read_only=True)
    is_late = serializers.SerializerMethodField()
    minutes_late = serializers.SerializerMethodField()
    
    class Meta:
        model = MedicationIntake
        fields = '__all__'
        read_only_fields = ('created_at',)
        ref_name = "MedicationIntakeSerializer"
    
    def get_medication_details(self, obj):
        return {
            'id': obj.medication.id,
            'name': obj.medication.name,
            'dosage': obj.medication.dosage,
            'medication_type': obj.medication.medication_type,
            'medication_type_display': obj.medication.get_medication_type_display()
        }
    
    def get_is_due(self, obj):
        return obj.is_due()


class SideEffectSerializer(serializers.ModelSerializer):
    """Serializer for medication side effects."""
    medication_details = serializers.SerializerMethodField()
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    duration_days = serializers.SerializerMethodField()
    created_by_details = UserBasicSerializer(source='created_by', read_only=True)
    
    class Meta:
        model = SideEffect
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'created_by')
    
    def get_medication_details(self, obj):
        return {
            'id': obj.medication.id,
            'name': obj.medication.name,
            'dosage': obj.medication.dosage
        }
    
    def get_duration_days(self, obj):
        return obj.duration_days()
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        
        return super().create(validated_data)


class DrugInteractionSerializer(serializers.ModelSerializer):
    """Serializer for drug interactions."""
    medication_a_details = serializers.SerializerMethodField()
    medication_b_details = serializers.SerializerMethodField()
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    created_by_details = UserBasicSerializer(source='created_by', read_only=True)
    is_resolved = serializers.SerializerMethodField()
    
    class Meta:
        model = DrugInteraction
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'created_by')
    
    def get_medication_a_details(self, obj):
        return {
            'id': obj.medication_a.id,
            'name': obj.medication_a.name,
            'dosage': obj.medication_a.dosage
        }
    
    def get_medication_b_details(self, obj):
        return {
            'id': obj.medication_b.id,
            'name': obj.medication_b.name,
            'dosage': obj.medication_b.dosage
        }
    
    def get_is_resolved(self, obj):
        return obj.is_resolved()
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        
        return super().create(validated_data)


class AdherenceRecordSerializer(serializers.ModelSerializer):
    """Serializer for medication adherence records."""
    medication_details = serializers.SerializerMethodField()
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    period_type_display = serializers.CharField(source='get_period_type_display', read_only=True)
    
    class Meta:
        model = AdherenceRecord
        fields = '__all__'
        read_only_fields = ('created_at', 'doses_scheduled', 'doses_taken', 'doses_skipped', 
                           'doses_missed', 'adherence_rate', 'average_delay')
    
    def get_medication_details(self, obj):
        return {
            'id': obj.medication.id,
            'name': obj.medication.name,
            'dosage': obj.medication.dosage,
            'medication_type': obj.medication.medication_type,
            'medication_type_display': obj.medication.get_medication_type_display()
        }


class MedicationSerializer(serializers.ModelSerializer):
    """Serializer for medications."""
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    prescriber_details = UserBasicSerializer(source='prescriber', read_only=True)
    medication_type_display = serializers.CharField(source='get_medication_type_display', read_only=True)
    frequency_unit_display = serializers.CharField(source='get_frequency_unit_display', read_only=True)
    route_display = serializers.CharField(source='get_route_display', read_only=True)
    condition_details = ConditionSerializer(source='condition', read_only=True)
    created_by_details = UserBasicSerializer(source='created_by', read_only=True)
    updated_by_details = UserBasicSerializer(source='updated_by', read_only=True)
    is_expired = serializers.SerializerMethodField()
    days_remaining = serializers.SerializerMethodField()
    needs_refill = serializers.SerializerMethodField()
    adherence_rate = serializers.SerializerMethodField()
    
    class Meta:
        model = Medication
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'created_by', 'updated_by', 
                           'created_by_details', 'updated_by_details', 'fhir_resource_id')
        ref_name = "MedicationMedicationSerializer"
    
    def get_is_expired(self, obj):
        return obj.is_expired()
    
    def get_days_remaining(self, obj):
        return obj.days_remaining()
    
    def get_needs_refill(self, obj):
        return obj.needs_refill()
    
    def get_adherence_rate(self, obj):
        # Get the most recent adherence record if available
        try:
            latest_record = AdherenceRecord.objects.filter(
                medication=obj
            ).order_by('-period_end').first()
            
            if latest_record:
                return latest_record.adherence_rate
        except AdherenceRecord.DoesNotExist:
            pass
        
        return None
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
            validated_data['updated_by'] = request.user
        
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['updated_by'] = request.user
        
        # Update the instance
        instance = super().update(instance, validated_data)

        return {
            'id': instance.id,
            'name': instance.name,
            'dosage': instance.dosage,
            'medication_type': instance.medication_type,
            'medication_type_display': instance.get_medication_type_display()
        }
    
    def get_is_late(self, obj):
        return obj.is_late()
    
    def get_minutes_late(self, obj):
        return obj.minutes_late()


class MedicationReminderSerializer(serializers.ModelSerializer):
    """Serializer for medication reminders."""
    medication_details = serializers.SerializerMethodField()
    patient_details = UserBasicSerializer(source='patient', read_only=True)
    reminder_type_display = serializers.CharField(source='get_reminder_type_display', read_only=True)
    frequency_display = serializers.CharField(source='get_frequency_display', read_only=True)
    is_due = serializers.SerializerMethodField()
    
    class Meta:
        model = MedicationReminder
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'created_by')
    
    def get_medication_details(self, obj):
        return
