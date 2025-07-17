from django.contrib import admin
from .models import (
    MedicalRecord, Medication, MedicationIntake, Allergy, Condition, ConditionFlare,
    Symptom, Immunization, LabTest, LabResult, VitalSign, Treatment, FamilyHistory,
    HealthDataConsent, HealthDataAuditLog, EHRIntegration, WearableIntegration,
    RareConditionRegistry, ReferralNetwork
)

class MedicationInline(admin.TabularInline):
    model = Medication
    extra = 0
    fields = ('name', 'dosage', 'frequency', 'active', 'for_rare_condition')

class ConditionInline(admin.TabularInline):
    model = Condition
    extra = 0
    fields = ('name', 'status', 'is_primary', 'is_rare_condition')

class LabTestInline(admin.TabularInline):
    model = LabTest
    extra = 0
    fields = ('name', 'status', 'ordered_date', 'for_rare_condition_monitoring')

@admin.register(MedicalRecord)
class MedicalRecordAdmin(admin.ModelAdmin):
    """Admin configuration for MedicalRecord model."""
    list_display = ('medical_record_number', 'patient', 'primary_physician', 'has_rare_condition', 'created_at')
    list_filter = ('has_rare_condition', 'data_sharing_authorized', 'research_participation_consent')
    search_fields = ('medical_record_number', 'patient__username', 'patient__email')
    raw_id_fields = ('patient', 'primary_physician', 'created_by', 'updated_by')
    inlines = [ConditionInline, MedicationInline, LabTestInline]
    
    fieldsets = (
        ('Patient Information', {
            'fields': ('patient', 'medical_record_number', 'date_of_birth', 'gender', 'blood_type',
                      'height', 'weight', 'ethnicity', 'preferred_language')
        }),
        ('Emergency Contact', {
            'fields': ('emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship')
        }),
        ('Provider Information', {
            'fields': ('primary_physician',)
        }),
        ('Consent & Sharing', {
            'fields': ('data_sharing_authorized', 'research_participation_consent', 'research_consent_date')
        }),
        ('Rare Condition Tracking', {
            'fields': ('has_rare_condition',)
        }),
        ('FHIR Integration', {
            'fields': ('fhir_resource_id', 'fhir_last_updated'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by', 'version', 'is_active'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Medication)
class MedicationAdmin(admin.ModelAdmin):
    """Admin configuration for Medication model."""
    list_display = ('name', 'medical_record', 'dosage', 'active', 'for_rare_condition', 'start_date')
    list_filter = ('active', 'for_rare_condition', 'is_specialty_medication', 'orphan_drug')
    search_fields = ('name', 'medical_record__patient__username', 'medical_record__patient__email')
    raw_id_fields = ('medical_record', 'prescriber', 'created_by')
    
    fieldsets = (
        ('Medication Information', {
            'fields': ('medical_record', 'name', 'dosage', 'frequency', 'instructions', 'medication_type')
        }),
        ('Status & Scheduling', {
            'fields': ('active', 'start_date', 'end_date', 'adherence_schedule')
        }),
        ('Rare Condition Related', {
            'fields': ('for_rare_condition', 'is_specialty_medication', 'orphan_drug')
        }),
        ('Provider Information', {
            'fields': ('prescriber', 'reason', 'pharmacy_notes')
        }),
        ('Side Effects Monitoring', {
            'fields': ('side_effects_reported', 'side_effects_notes')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')

class ConditionFlareInline(admin.TabularInline):
    model = ConditionFlare
    extra = 0
    fields = ('onset_date', 'resolved_date', 'severity', 'hospitalized')

class SymptomInline(admin.TabularInline):
    model = Symptom
    extra = 0
    fields = ('name', 'severity', 'is_active', 'first_observed')

@admin.register(Condition)
class ConditionAdmin(admin.ModelAdmin):
    """Admin configuration for Condition model."""
    list_display = ('name', 'medical_record', 'status', 'is_primary', 'is_rare_condition', 'diagnosed_date')
    list_filter = ('status', 'category', 'is_primary', 'is_rare_condition')
    search_fields = ('name', 'medical_record__patient__username', 'medical_record__patient__email', 'icd10_code')
    raw_id_fields = ('medical_record', 'rare_condition', 'created_by')
    inlines = [SymptomInline, ConditionFlareInline]
    
    fieldsets = (
        ('Condition Information', {
            'fields': ('medical_record', 'name', 'status', 'category', 'diagnosed_date', 'resolved_date', 'notes')
        }),
        ('Classification', {
            'fields': ('is_primary', 'icd10_code', 'diagnosing_provider')
        }),
        ('Rare Condition Tracking', {
            'fields': ('is_rare_condition', 'rare_condition', 'biomarker_status', 'genetic_information')
        }),
        ('Progression Tracking', {
            'fields': ('progression_metrics', 'last_assessment_date')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')

@admin.register(RareConditionRegistry)
class RareConditionRegistryAdmin(admin.ModelAdmin):
    """Admin configuration for RareConditionRegistry model."""
    list_display = ('name', 'identifier', 'prevalence', 'specialty_category')
    list_filter = ('specialty_category',)
    search_fields = ('name', 'identifier', 'description')
    
    fieldsets = (
        ('Condition Information', {
            'fields': ('name', 'identifier', 'description', 'prevalence', 'inheritance_pattern', 'onset_age', 'specialty_category')
        }),
        ('Research & Treatment', {
            'fields': ('known_treatments', 'biomarkers', 'research_resources', 'patient_organizations')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')

class LabResultInline(admin.TabularInline):
    model = LabResult
    extra = 0
    fields = ('test_name', 'value', 'unit', 'is_abnormal')

@admin.register(LabTest)
class LabTestAdmin(admin.ModelAdmin):
    """Admin configuration for LabTest model."""
    list_display = ('name', 'medical_record', 'status', 'ordered_date', 'for_rare_condition_monitoring')
    list_filter = ('status', 'for_rare_condition_monitoring', 'test_type')
    search_fields = ('name', 'medical_record__patient__username', 'lab_location')
    raw_id_fields = ('medical_record', 'ordered_by', 'related_condition', 'created_by')
    inlines = [LabResultInline]
    
    fieldsets = (
        ('Test Information', {
            'fields': ('medical_record', 'name', 'status', 'test_type', 'ordered_date', 'completed_date', 'notes')
        }),
        ('Provider Information', {
            'fields': ('ordered_by', 'lab_location', 'fasting_required', 'priority')
        }),
        ('Rare Condition Tracking', {
            'fields': ('for_rare_condition_monitoring', 'related_condition')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')

@admin.register(VitalSign)
class VitalSignAdmin(admin.ModelAdmin):
    """Admin configuration for VitalSign model."""
    list_display = ('measurement_type', 'value', 'unit', 'medical_record', 'measured_at', 'is_abnormal')
    list_filter = ('measurement_type', 'source', 'is_abnormal')
    search_fields = ('medical_record__patient__username', 'notes', 'context')
    raw_id_fields = ('medical_record', 'related_to_condition', 'created_by')
    
    fieldsets = (
        ('Vital Information', {
            'fields': ('medical_record', 'measurement_type', 'value', 'unit', 'measured_at', 'is_abnormal')
        }),
        ('Specific Measurements', {
            'fields': ('blood_pressure', 'heart_rate', 'temperature', 'respiratory_rate', 'oxygen_saturation')
        }),
        ('Source Information', {
            'fields': ('source', 'source_device_id', 'context', 'notes')
        }),
        ('Rare Condition Tracking', {
            'fields': ('related_to_condition',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at',)

@admin.register(HealthDataAuditLog)
class HealthDataAuditLogAdmin(admin.ModelAdmin):
    """Admin configuration for HealthDataAuditLog model."""
    list_display = ('timestamp', 'user', 'action', 'resource_type', 'resource_id', 'patient_id')
    list_filter = ('action', 'resource_type', 'timestamp')
    search_fields = ('user__username', 'patient_id', 'resource_id', 'ip_address')
    raw_id_fields = ('user',)
    
    fieldsets = (
        ('Action Information', {
            'fields': ('user', 'action', 'timestamp', 'ip_address', 'user_agent')
        }),
        ('Resource Information', {
            'fields': ('resource_type', 'resource_id', 'patient_id')
        }),
        ('Details', {
            'fields': ('access_reason', 'details')
        }),
    )
    
    readonly_fields = ('timestamp', 'user', 'action', 'resource_type', 'resource_id', 
                      'patient_id', 'ip_address', 'user_agent', 'access_reason', 'details')
    
    def has_add_permission(self, request):
        """Disable adding audit logs manually."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Disable changing audit logs."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Disable deleting audit logs."""
        return False

# Register remaining models
admin.site.register(MedicationIntake)
admin.site.register(Allergy)
admin.site.register(ConditionFlare)
admin.site.register(Symptom)
admin.site.register(Immunization)
admin.site.register(LabResult)
admin.site.register(Treatment)
admin.site.register(FamilyHistory)
admin.site.register(HealthDataConsent)
admin.site.register(EHRIntegration)
admin.site.register(WearableIntegration)
admin.site.register(ReferralNetwork)
