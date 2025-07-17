# medication/filters.py
from django_filters import rest_framework as filters
from django.db.models import Q
from .models import (
    Medication, Prescription, MedicationIntake, MedicationReminder,
    AdherenceRecord, SideEffect, DrugInteraction
)

class MedicationFilter(filters.FilterSet):
    patient = filters.NumberFilter(field_name='patient_id')
    class Meta:
        model = Medication
        fields = [
            'patient', 'active', 'for_rare_condition',
            'is_specialty_medication', 'medication_type'
        ]
    
    def filter_by_patient(self, queryset, name, value):
        if value:
            return queryset.filter(patient_id=value)
        return queryset

class PrescriptionFilter(filters.FilterSet):
    class Meta:
        model = Prescription
        fields = ['status', 'is_electronic']

class MedicationIntakeFilter(filters.FilterSet):
    medication = filters.NumberFilter(field_name='medication_id')
    class Meta:
        model = MedicationIntake
        fields = ['status', 'medication']
    
    def filter_by_medication(self, queryset, name, value):
        if value:
            return queryset.filter(medication_id=value)
        return queryset

class MedicationReminderFilter(filters.FilterSet):
    class Meta:
        model = MedicationReminder
        fields = ['reminder_type', 'frequency', 'is_active', 'medication']

class AdherenceRecordFilter(filters.FilterSet):
    class Meta:
        model = AdherenceRecord
        fields = ['period_type', 'medication', 'patient']

class SideEffectFilter(filters.FilterSet):
    class Meta:
        model = SideEffect
        fields = ['severity', 'medication', 'ongoing', 'reported_to_doctor']

class DrugInteractionFilter(filters.FilterSet):
    class Meta:
        model = DrugInteraction
        fields = ['severity', 'patient', 'patient_notified', 'provider_notified', 'resolved_date']
