from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    Medication, Prescription, MedicationIntake, MedicationReminder,
    AdherenceRecord, SideEffect, DrugInteraction
)

class MedicationIntakeInline(admin.TabularInline):
    """Inline admin for medication intakes."""
    model = MedicationIntake
    extra = 0
    fields = ('scheduled_time', 'actual_time', 'status', 'dosage_taken', 'recorded_by')
    readonly_fields = ('created_at',)
    max_num = 10
    can_delete = False
    verbose_name_plural = "Recent Intakes"

    def get_queryset(self, request):
        """Limit to the 10 most recent intakes."""
        qs = super().get_queryset(request)
        return qs.order_by('-scheduled_time')[:10]


class MedicationReminderInline(admin.TabularInline):
    """Inline admin for medication reminders."""
    model = MedicationReminder
    extra = 0
    fields = ('reminder_type', 'message', 'scheduled_time', 'frequency', 'is_active')
    readonly_fields = ('last_sent',)


class SideEffectInline(admin.TabularInline):
    """Inline admin for side effects."""
    model = SideEffect
    extra = 0
    fields = ('description', 'severity', 'onset_date', 'ongoing', 'reported_to_doctor')


@admin.register(Medication)
class MedicationAdmin(admin.ModelAdmin):
    """Admin interface for medications."""
    list_display = ('name', 'patient_link', 'dosage', 'frequency', 'medication_type_display', 
                   'active', 'is_expired_display', 'for_rare_condition', 'start_date')
    list_filter = ('active', 'medication_type', 'for_rare_condition', 'is_specialty_medication', 
                  'route', 'prescription_required')
    search_fields = ('name', 'patient__username', 'patient__email', 'ndc_code', 'rxnorm_code')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by', 'fhir_resource_id')
    date_hierarchy = 'start_date'
    inlines = [MedicationIntakeInline, MedicationReminderInline, SideEffectInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'generic_name', 'medication_type', 'route', 'ndc_code', 'rxnorm_code')
        }),
        ('Dosage and Frequency', {
            'fields': ('dosage', 'dosage_unit', 'strength', 'frequency', 'frequency_unit', 
                      'times_per_frequency', 'specific_times')
        }),
        ('Duration', {
            'fields': ('start_date', 'end_date', 'ongoing', 'active')
        }),
        ('Patient and Provider', {
            'fields': ('patient', 'prescriber', 'medical_record', 'condition')
        }),
        ('Rare Condition', {
            'fields': ('for_rare_condition', 'is_specialty_medication', 'orphan_drug'),
            'classes': ('collapse',),
        }),
        ('Prescription', {
            'fields': ('prescription_required', 'prescription', 'refills_allowed', 
                      'refills_remaining', 'last_refill_date'),
            'classes': ('collapse',),
        }),
        ('Pharmacy', {
            'fields': ('pharmacy_name', 'pharmacy_phone'),
            'classes': ('collapse',),
        }),
        ('Side Effects and Interactions', {
            'fields': ('potential_side_effects', 'known_interactions'),
            'classes': ('collapse',),
        }),
        ('Adherence', {
            'fields': ('adherence_schedule', 'last_reminded_at'),
            'classes': ('collapse',),
        }),
        ('Instructions', {
            'fields': ('instructions',),
        }),
        ('FHIR', {
            'fields': ('fhir_resource_id',),
            'classes': ('collapse',),
        }),
        ('Meta', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',),
        }),
    )
    
    def patient_link(self, obj):
        """Link to patient admin page."""
        if obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, obj.patient.get_full_name() or obj.patient.username)
        return "-"
    patient_link.short_description = "Patient"
    
    def medication_type_display(self, obj):
        """Display medication type."""
        return obj.get_medication_type_display()
    medication_type_display.short_description = "Type"
    
    def is_expired_display(self, obj):
        """Display if medication is expired."""
        if obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Active</span>')
    is_expired_display.short_description = "Status"


@admin.register(Prescription)
class PrescriptionAdmin(admin.ModelAdmin):
    """Admin interface for prescriptions."""
    list_display = ('prescription_number', 'medication_name', 'patient_link', 'prescriber_link', 
                   'status_display', 'prescribed_date', 'is_expired_display')
    list_filter = ('status', 'prescribed_date', 'is_electronic')
    search_fields = ('prescription_number', 'medication_name', 'patient__username', 
                    'patient__email', 'pharmacy_name')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by', 'fhir_resource_id')
    date_hierarchy = 'prescribed_date'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('prescription_number', 'status', 'medication_name')
        }),
        ('Dosage and Details', {
            'fields': ('dosage', 'frequency', 'quantity', 'refills', 'instructions')
        }),
        ('Dates', {
            'fields': ('prescribed_date', 'fill_date', 'expiration_date')
        }),
        ('Patient and Provider', {
            'fields': ('patient', 'prescriber')
        }),
        ('Pharmacy', {
            'fields': ('pharmacy_name', 'pharmacy_phone', 'pharmacy_address')
        }),
        ('E-Prescription', {
            'fields': ('is_electronic', 'electronic_routing_id'),
            'classes': ('collapse',),
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
        ('FHIR', {
            'fields': ('fhir_resource_id',),
            'classes': ('collapse',),
        }),
        ('Meta', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',),
        }),
    )
    
    def patient_link(self, obj):
        """Link to patient admin page."""
        if obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, obj.patient.get_full_name() or obj.patient.username)
        return "-"
    patient_link.short_description = "Patient"
    
    def prescriber_link(self, obj):
        """Link to prescriber admin page."""
        if obj.prescriber:
            url = reverse('admin:users_user_change', args=[obj.prescriber.id])
            return format_html('<a href="{}">{}</a>', url, obj.prescriber.get_full_name() or obj.prescriber.username)
        return "-"
    prescriber_link.short_description = "Prescriber"
    
    def status_display(self, obj):
        """Display status with color."""
        colors = {
            'pending': 'orange',
            'active': 'green',
            'filled': 'blue',
            'expired': 'red',
            'cancelled': 'red',
            'completed': 'gray'
        }
        color = colors.get(obj.status, 'black')
        return format_html('<span style="color: {};">{}</span>',
                         color, obj.get_status_display())
    status_display.short_description = "Status"
    
    def is_expired_display(self, obj):
        """Display if prescription is expired."""
        if obj.is_expired():
            return format_html('<span style="color: red;">Yes</span>')
        days = obj.days_until_expiration()
        if days is not None and days < 7:
            return format_html('<span style="color: orange;">In {} days</span>', days)
        return format_html('<span style="color: green;">No</span>')
    is_expired_display.short_description = "Expired"


@admin.register(MedicationIntake)
class MedicationIntakeAdmin(admin.ModelAdmin):
    """Admin interface for medication intakes."""
    # Fixed list_display - either include only fields that exist or add the missing methods
    list_display = ('medication_name', 'patient_name', 'scheduled_time', 'actual_time', 
                   'status_display', 'recorded_by_name', 'recorded_via')
    
    list_filter = ('status', 'recorded_via', 'scheduled_time')
    search_fields = ('medication__name', 'notes', 'skip_reason')
    readonly_fields = ('created_at',)
    date_hierarchy = 'scheduled_time'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('medication', 'scheduled_time', 'actual_time', 'status')
        }),
        ('Details', {
            'fields': ('dosage_taken', 'skip_reason', 'notes')
        }),
        ('Recording', {
            'fields': ('recorded_by', 'recorded_via', 'created_at')
        }),
    )
    
    def medication_name(self, obj):
        """Display medication name with link."""
        if obj.medication:
            url = reverse('admin:medication_medication_change', args=[obj.medication.id])
            return format_html('<a href="{}">{}</a>', url, obj.medication.name)
        return "-"
    medication_name.short_description = "Medication"
    
    def patient_name(self, obj):
        """Display patient name with link."""
        if hasattr(obj, 'patient') and obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.patient.get_full_name() or obj.patient.username)
        elif hasattr(obj.medication, 'patient') and obj.medication.patient:
            url = reverse('admin:users_user_change', args=[obj.medication.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.medication.patient.get_full_name() or obj.medication.patient.username)
        return "-"
    patient_name.short_description = "Patient"
    
    def status_display(self, obj):
        """Display status with color."""
        colors = {
            'taken': 'green',
            'skipped': 'orange',
            'missed': 'red',
            'rescheduled': 'blue'
        }
        color = colors.get(obj.status, 'black')
        return format_html('<span style="color: {};">{}</span>',
                         color, obj.get_status_display())
    status_display.short_description = "Status"
    
    def recorded_by_name(self, obj):
        """Display recorded by name."""
        if obj.recorded_by:
            return obj.recorded_by.get_full_name() or obj.recorded_by.username
        return "-"
    recorded_by_name.short_description = "Recorded By"


@admin.register(DrugInteraction)
class DrugInteractionAdmin(admin.ModelAdmin):
    """Admin interface for drug interactions."""
    list_display = ('interaction_meds', 'patient_name', 'severity_display', 
                   'detected_date', 'is_resolved_display', 'patient_notified', 'provider_notified')
    list_filter = ('severity', 'patient_notified', 'provider_notified', 'detected_date')
    search_fields = ('description', 'medication_a__name', 'medication_b__name', 
                    'patient__username', 'patient__email', 'resolution_action')
    readonly_fields = ('created_at', 'updated_at', 'created_by')
    date_hierarchy = 'detected_date'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('medication_a', 'medication_b', 'patient', 'description', 'severity')
        }),
        ('Resolution', {
            'fields': ('detected_date', 'resolved_date', 'resolution_action')
        }),
        ('Notifications', {
            'fields': ('patient_notified', 'provider_notified')
        }),
        ('Meta', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',),
        }),
    )
    
    def interaction_meds(self, obj):
        """Display interacting medications."""
        med_a_url = reverse('admin:medication_medication_change', args=[obj.medication_a.id])
        med_b_url = reverse('admin:medication_medication_change', args=[obj.medication_b.id])
        return format_html(
            '<a href="{}">{}</a> + <a href="{}">{}</a>',
            med_a_url, obj.medication_a.name,
            med_b_url, obj.medication_b.name
        )
    interaction_meds.short_description = "Interacting Medications"
    
    def patient_name(self, obj):
        """Display patient name with link."""
        if obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.patient.get_full_name() or obj.patient.username)
        return "-"
    patient_name.short_description = "Patient"
    
    def severity_display(self, obj):
        """Display severity with color."""
        colors = {
            'minor': 'green',
            'moderate': 'orange',
            'major': 'red',
            'contraindicated': 'darkred'
        }
        color = colors.get(obj.severity, 'black')
        return format_html('<span style="color: {};">{}</span>',
                         color, obj.get_severity_display())
    severity_display.short_description = "Severity"
    
    def is_resolved_display(self, obj):
        """Display resolution status."""
        if obj.is_resolved():
            return format_html('<span style="color: green;">Yes</span>')
        return format_html('<span style="color: red;">No</span>')
    is_resolved_display.short_description = "Resolved"


@admin.register(MedicationReminder)
class MedicationReminderAdmin(admin.ModelAdmin):
    """Admin interface for medication reminders."""
    list_display = ('message_short', 'medication_name', 'patient_name', 'reminder_type_display', 
                   'scheduled_time', 'frequency_display', 'is_active', 'last_sent')
    list_filter = ('reminder_type', 'frequency', 'is_active', 'send_email', 'send_push', 'send_sms')
    search_fields = ('message', 'medication__name', 'patient__username', 'patient__email')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'scheduled_time'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('medication', 'patient', 'reminder_type', 'message')
        }),
        ('Schedule', {
            'fields': ('frequency', 'scheduled_time', 'recurrence_pattern', 'is_active')
        }),
        ('Reminder Window', {
            'fields': ('window_before', 'window_after')
        }),
        ('Notification Methods', {
            'fields': ('send_email', 'send_push', 'send_sms')
        }),
        ('Status', {
            'fields': ('last_sent',)
        }),
        ('Meta', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',),
        }),
    )
    
    def message_short(self, obj):
        """Display shortened message."""
        if len(obj.message) > 50:
            return f"{obj.message[:50]}..."
        return obj.message
    message_short.short_description = "Message"
    
    def medication_name(self, obj):
        """Display medication name with link."""
        if obj.medication:
            url = reverse('admin:medication_medication_change', args=[obj.medication.id])
            return format_html('<a href="{}">{}</a>', url, obj.medication.name)
        return "-"
    medication_name.short_description = "Medication"
    
    def patient_name(self, obj):
        """Display patient name with link."""
        if obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.patient.get_full_name() or obj.patient.username)
        return "-"
    patient_name.short_description = "Patient"
    
    def reminder_type_display(self, obj):
        """Display reminder type."""
        return obj.get_reminder_type_display()
    reminder_type_display.short_description = "Type"
    
    def frequency_display(self, obj):
        """Display frequency."""
        return obj.get_frequency_display()
    frequency_display.short_description = "Frequency"


@admin.register(AdherenceRecord)
class AdherenceRecordAdmin(admin.ModelAdmin):
    """Admin interface for adherence records."""
    list_display = ('medication_name', 'patient_name', 'period_type_display', 'period_range', 
                   'adherence_rate_display', 'doses_taken', 'doses_missed')
    list_filter = ('period_type', 'period_start', 'period_end')
    search_fields = ('medication__name', 'patient__username', 'patient__email', 'notes')
    readonly_fields = ('created_at', 'doses_scheduled', 'doses_taken', 'doses_skipped', 
                      'doses_missed', 'adherence_rate', 'average_delay')
    date_hierarchy = 'period_start'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('medication', 'patient', 'period_type')
        }),
        ('Period', {
            'fields': ('period_start', 'period_end')
        }),
        ('Metrics', {
            'fields': ('doses_scheduled', 'doses_taken', 'doses_skipped', 'doses_missed', 
                     'adherence_rate', 'average_delay')
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
        ('Meta', {
            'fields': ('created_at',),
            'classes': ('collapse',),
        }),
    )
    
    def medication_name(self, obj):
        """Display medication name with link."""
        if obj.medication:
            url = reverse('admin:medication_medication_change', args=[obj.medication.id])
            return format_html('<a href="{}">{}</a>', url, obj.medication.name)
        return "-"
    medication_name.short_description = "Medication"
    
    def patient_name(self, obj):
        """Display patient name with link."""
        if obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.patient.get_full_name() or obj.patient.username)
        return "-"
    patient_name.short_description = "Patient"
    
    def period_type_display(self, obj):
        """Display period type."""
        return obj.get_period_type_display()
    period_type_display.short_description = "Period Type"
    
    def period_range(self, obj):
        """Display period range."""
        return f"{obj.period_start} to {obj.period_end}"
    period_range.short_description = "Period"
    
    def adherence_rate_display(self, obj):
        """Display adherence rate with color."""
        rate = obj.adherence_rate
        if rate >= 90:
            color = 'green'
        elif rate >= 75:
            color = 'orange'
        else:
            color = 'red'
        return format_html('<span style="color: {};">{:.1f}%</span>', color, rate)
    adherence_rate_display.short_description = "Adherence Rate"


@admin.register(SideEffect)
class SideEffectAdmin(admin.ModelAdmin):
    """Admin interface for side effects."""
    # Fixed list_display with all necessary methods
    list_display = ('description_short', 'medication_name', 'patient_name', 'severity_display', 
                   'onset_date', 'ongoing_display', 'reported_to_doctor')
    
    list_filter = ('severity', 'ongoing', 'reported_to_doctor', 'medication_adjusted', 'medication_stopped')
    search_fields = ('description', 'medication__name', 'notes')
    readonly_fields = ('created_at', 'updated_at', 'created_by')
    date_hierarchy = 'onset_date'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('medication', 'patient', 'description', 'severity')
        }),
        ('Dates', {
            'fields': ('onset_date', 'resolution_date', 'ongoing')
        }),
        ('Reporting', {
            'fields': ('reported_to_doctor', 'doctor_notified_date')
        }),
        ('Actions Taken', {
            'fields': ('medication_adjusted', 'medication_stopped')
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
        ('Meta', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',),
        }),
    )
    
    def description_short(self, obj):
        """Display shortened description."""
        if len(obj.description) > 50:
            return f"{obj.description[:50]}..."
        return obj.description
    description_short.short_description = "Description"
    
    def medication_name(self, obj):
        """Display medication name with link."""
        if obj.medication:
            url = reverse('admin:medication_medication_change', args=[obj.medication.id])
            return format_html('<a href="{}">{}</a>', url, obj.medication.name)
        return "-"
    medication_name.short_description = "Medication"
    
    def patient_name(self, obj):
        """Display patient name with link."""
        if hasattr(obj, 'patient') and obj.patient:
            url = reverse('admin:users_user_change', args=[obj.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.patient.get_full_name() or obj.patient.username)
        elif hasattr(obj.medication, 'patient') and obj.medication.patient:
            url = reverse('admin:users_user_change', args=[obj.medication.patient.id])
            return format_html('<a href="{}">{}</a>', url, 
                            obj.medication.patient.get_full_name() or obj.medication.patient.username)
        return "-"
    patient_name.short_description = "Patient"
    
    def severity_display(self, obj):
        """Display severity with color."""
        colors = {
            'mild': 'green',
            'moderate': 'orange',
            'severe': 'red',
            'life_threatening': 'darkred'
        }
        color = colors.get(obj.severity, 'black')
        return format_html('<span style="color: {};">{}</span>',
                         color, obj.get_severity_display())
    severity_display.short_description = "Severity"
    
    def ongoing_display(self, obj):
        """Display ongoing status."""
        if obj.ongoing:
            return format_html('<span style="color: red;">Yes</span>')
        return format_html('<span style="color: green;">No</span>')
    ongoing_display.short_description = "Ongoing"
