from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    Appointment, Consultation, Prescription, 
    ProviderAvailability, WaitingRoom, WaitingRoomPatient,
    ConsultationNote
)


class AppointmentAdmin(admin.ModelAdmin):
    """Admin interface for telemedicine appointments."""
    list_display = ('id', 'patient_name_link', 'provider_name_link', 'appointment_type_display', 
                    'scheduled_time', 'status', 'priority')
    list_filter = ('status', 'appointment_type', 'priority', 'created_at')
    search_fields = ('patient__first_name', 'patient__last_name', 'provider__first_name', 
                      'provider__last_name', 'reason')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by')
    fieldsets = (
        ('Patient Information', {
            'fields': ('patient', 'medical_record', 'related_condition')
        }),
        ('Provider Information', {
            'fields': ('provider', 'availability_block')
        }),
        ('Appointment Details', {
            'fields': ('appointment_type', 'reason', 'notes', 'status', 'priority')
        }),
        ('Scheduling', {
            'fields': ('scheduled_time', 'end_time', 'duration_minutes', 'timezone')
        }),
        ('Reminders', {
            'fields': ('reminders_enabled', 'reminder_sent', 'reminder_sent_time')
        }),
        ('Billing', {
            'fields': ('insurance_verified', 'copay_amount', 'copay_collected')
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by')
        }),
    )
    
    def patient_name_link(self, obj):
        """Show patient name with link to patient detail page."""
        if obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, obj.patient_name)
        return "Unknown Patient"
    patient_name_link.short_description = 'Patient'
    
    def provider_name_link(self, obj):
        """Show provider name with link to provider detail page."""
        if obj.provider:
            url = reverse('admin:users_user_change', args=[obj.provider.id])
            return format_html('<a href="{}">{}</a>', url, obj.provider_name)
        return "Unknown Provider"
    provider_name_link.short_description = 'Provider'


class ConsultationAdmin(admin.ModelAdmin):
    """Admin interface for telemedicine consultations."""
    list_display = ('id', 'get_patient', 'get_provider', 'platform', 'status', 'start_time', 'duration')
    list_filter = ('status', 'platform', 'created_at', 'recording_enabled')
    search_fields = ('appointment__patient__first_name', 'appointment__patient__last_name', 
                      'appointment__provider__first_name', 'appointment__provider__last_name')
    readonly_fields = ('created_at', 'updated_at', 'duration')
    fieldsets = (
        ('Appointment Information', {
            'fields': ('appointment',)
        }),
        ('Consultation Status', {
            'fields': ('status', 'platform')
        }),
        ('Timing', {
            'fields': ('start_time', 'end_time', 'duration', 'patient_join_time', 'provider_join_time')
        }),
        ('Clinical Data', {
            'fields': ('notes', 'diagnosis', 'treatment_plan', 'follow_up_required', 'follow_up_date', 'vital_signs', 'treatments')
        }),
        ('Meeting Details', {
            'fields': ('meeting_id', 'join_url', 'password', 'platform_data')
        }),
        ('Recording', {
            'fields': ('recording_enabled', 'recording_consent', 'recording_url')
        }),
        ('Technical', {
            'fields': ('technical_issues', 'connection_quality')
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def get_patient(self, obj):
        """Get patient name from appointment."""
        if obj.appointment and obj.appointment.patient:
            return obj.appointment.patient_name
        return "Unknown Patient"
    get_patient.short_description = 'Patient'
    
    def get_provider(self, obj):
        """Get provider name from appointment."""
        if obj.appointment and obj.appointment.provider:
            return obj.appointment.provider_name
        return "Unknown Provider"
    get_provider.short_description = 'Provider'


class PrescriptionAdmin(admin.ModelAdmin):
    """Admin interface for electronic prescriptions."""
    list_display = ('id', 'medication_name', 'get_patient', 'get_provider', 'status', 'prescribed_date')
    list_filter = ('status', 'prescription_type', 'prescribed_date', 'generic_allowed')
    search_fields = ('medication_name', 'patient__first_name', 'patient__last_name', 
                      'provider__first_name', 'provider__last_name')
    readonly_fields = ('prescribed_date', 'prescribed_time', 'created_at', 'updated_at')
    fieldsets = (
        ('Patient and Provider', {
            'fields': ('patient', 'provider', 'consultation')
        }),
        ('Prescription Details', {
            'fields': ('prescription_type', 'status', 'ndc_code')
        }),
        ('Medication', {
            'fields': ('medication_name', 'dosage', 'frequency', 'duration', 'quantity', 'refills', 'instructions')
        }),
        ('Dates', {
            'fields': ('prescribed_date', 'prescribed_time', 'fill_date', 'expiration_date')
        }),
        ('Pharmacy', {
            'fields': ('pharmacy_notes', 'pharmacy_id', 'external_rx_id')
        }),
        ('E-Prescription', {
            'fields': ('is_electronically_sent', 'sent_timestamp', 'send_method', 'electronic_rx_reference')
        }),
        ('Options', {
            'fields': ('generic_allowed', 'prior_authorization_required', 'drug_interaction_checked', 'drug_allergy_checked')
        }),
        ('Patient Notification', {
            'fields': ('patient_notified', 'patient_notification_time')
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def get_patient(self, obj):
        """Get patient name."""
        if obj.patient:
            return f"{obj.patient.first_name} {obj.patient.last_name}"
        return "Unknown Patient"
    get_patient.short_description = 'Patient'
    
    def get_provider(self, obj):
        """Get provider name."""
        if obj.provider:
            return f"Dr. {obj.provider.last_name}"
        return "Unknown Provider"
    get_provider.short_description = 'Provider'


class ProviderAvailabilityAdmin(admin.ModelAdmin):
    """Admin interface for provider availability scheduling."""
    list_display = ('id', 'provider', 'start_time', 'end_time', 'is_available', 'duration_minutes', 'max_appointments')
    list_filter = ('is_available', 'created_at')
    search_fields = ('provider__first_name', 'provider__last_name', 'notes')
    readonly_fields = ('created_at',)
    fieldsets = (
        ('Provider', {
            'fields': ('provider',)
        }),
        ('Time Slot', {
            'fields': ('start_time', 'end_time', 'is_available')
        }),
        ('Recurrence', {
            'fields': ('recurrence_pattern',)
        }),
        ('Appointment Settings', {
            'fields': ('appointment_types', 'slot_duration_minutes', 'max_appointments')
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
        ('Audit', {
            'fields': ('created_at',)
        }),
    )


class WaitingRoomAdmin(admin.ModelAdmin):
    """Admin interface for virtual waiting rooms."""
    list_display = ('id', 'name', 'provider', 'is_active', 'estimated_wait_time', 'get_patient_count')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'provider__first_name', 'provider__last_name', 'custom_message')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'provider', 'is_active')
        }),
        ('Wait Time', {
            'fields': ('estimated_wait_time',)
        }),
        ('Messages', {
            'fields': ('custom_message',)
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def get_patient_count(self, obj):
        """Get count of patients currently in waiting room."""
        return obj.patients.filter(status='waiting').count()
    get_patient_count.short_description = 'Waiting Patients'


class WaitingRoomPatientAdmin(admin.ModelAdmin):
    """Admin interface for patients in virtual waiting rooms."""
    list_display = ('id', 'get_patient', 'waiting_room', 'status', 'checked_in_time', 'wait_duration')
    list_filter = ('status', 'checked_in_time')
    search_fields = ('appointment__patient__first_name', 'appointment__patient__last_name', 'notes')
    readonly_fields = ('checked_in_time', 'ready_time')
    fieldsets = (
        ('Waiting Room', {
            'fields': ('waiting_room', 'appointment')
        }),
        ('Status', {
            'fields': ('status',)
        }),
        ('Timing', {
            'fields': ('checked_in_time', 'ready_time')
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
    )
    
    def get_patient(self, obj):
        """Get patient name from appointment."""
        if obj.appointment and obj.appointment.patient:
            return obj.appointment.patient_name
        return "Unknown Patient"
    get_patient.short_description = 'Patient'


class ConsultationNoteAdmin(admin.ModelAdmin):
    """Admin interface for consultation notes with templates."""
    list_display = ('id', 'get_consultation_id', 'get_patient', 'is_complete', 'completed_at')
    list_filter = ('is_complete', 'created_at', 'template_used')
    search_fields = ('chief_complaint', 'consultation__appointment__patient__first_name', 
                      'consultation__appointment__patient__last_name')
    readonly_fields = ('created_at', 'updated_at', 'completed_at')
    fieldsets = (
        ('Consultation', {
            'fields': ('consultation', 'created_by', 'is_complete', 'completed_at', 'template_used')
        }),
        ('SOAP Note', {
            'fields': ('subjective', 'objective', 'assessment', 'plan')
        }),
        ('Structured Data', {
            'fields': ('chief_complaint', 'history_present_illness', 'past_medical_history', 
                      'medications', 'allergies', 'review_of_systems', 'physical_examination', 
                      'diagnostic_results', 'vital_signs')
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def get_consultation_id(self, obj):
        """Get consultation ID."""
        if obj.consultation:
            return obj.consultation.id
        return None
    get_consultation_id.short_description = 'Consultation ID'
    
    def get_patient(self, obj):
        """Get patient name from consultation's appointment."""
        if obj.consultation and obj.consultation.appointment and obj.consultation.appointment.patient:
            return obj.consultation.appointment.patient_name
        return "Unknown Patient"
    get_patient.short_description = 'Patient'


# Register models with their admin classes
admin.site.register(Appointment, AppointmentAdmin)
admin.site.register(Consultation, ConsultationAdmin)
admin.site.register(Prescription, PrescriptionAdmin)
admin.site.register(ProviderAvailability, ProviderAvailabilityAdmin)
admin.site.register(WaitingRoom, WaitingRoomAdmin)
admin.site.register(WaitingRoomPatient, WaitingRoomPatientAdmin)
admin.site.register(ConsultationNote, ConsultationNoteAdmin)
