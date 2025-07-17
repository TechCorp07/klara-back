from django.db import models
from django.conf import settings
from django.utils import timezone
from django_cryptography.fields import encrypt
from healthcare.models import MedicalRecord, Condition, Treatment

class Appointment(models.Model):
    """Model for telemedicine appointments with enhanced HIPAA compliance."""
    class Status(models.TextChoices):
        REQUESTED = 'requested', 'Requested'
        SCHEDULED = 'scheduled', 'Scheduled'
        CONFIRMED = 'confirmed', 'Confirmed'
        CHECKED_IN = 'checked_in', 'Checked In'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'
        NO_SHOW = 'no_show', 'No Show'
    
    class AppointmentType(models.TextChoices):
        VIDEO_CONSULTATION = 'video_consultation', 'Video Consultation'
        PHONE_CONSULTATION = 'phone_consultation', 'Phone Consultation'
        IN_PERSON = 'in_person', 'In-Person Visit'
        FOLLOW_UP = 'follow_up', 'Follow-up Visit'
        INITIAL_CONSULTATION = 'initial_consultation', 'Initial Consultation'
    
    class Priority(models.TextChoices):
        ROUTINE = 'routine', 'Routine'
        URGENT = 'urgent', 'Urgent'
        EMERGENCY = 'emergency', 'Emergency'
    
    # Core fields
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='patient_appointments'
    )
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='provider_appointments'
    )
    medical_record = models.ForeignKey(
        MedicalRecord, 
        on_delete=models.SET_NULL, 
        related_name='appointments',
        null=True,
        blank=True
    )
    related_condition = models.ForeignKey(
        Condition,
        on_delete=models.SET_NULL,
        related_name='appointments',
        null=True,
        blank=True,
        help_text="Specific condition this appointment is related to"
    )
    
    # Scheduling fields
    scheduled_time = models.DateTimeField()
    end_time = models.DateTimeField()
    duration_minutes = models.IntegerField(default=30, help_text="Appointment duration in minutes")
    timezone = models.CharField(max_length=50, default="UTC")
    
    # Status and type
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.REQUESTED)
    appointment_type = models.CharField(
        max_length=25, 
        choices=AppointmentType.choices, 
        default=AppointmentType.VIDEO_CONSULTATION
    )
    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.ROUTINE
    )
    
    # Enhanced fields
    reason = encrypt(models.TextField(help_text="Reason for the appointment - PHI data"))
    notes = encrypt(models.TextField(blank=True, help_text="Provider notes - PHI data"))
    encrypted_metadata = encrypt(models.JSONField(default=dict, blank=True, help_text="Additional encrypted PHI data"))
    
    # Reminders
    reminders_enabled = models.BooleanField(default=True)
    reminder_sent = models.BooleanField(default=False)
    reminder_sent_time = models.DateTimeField(null=True, blank=True)
    
    # Payment and billing info
    insurance_verified = models.BooleanField(default=False)
    copay_amount = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    copay_collected = models.BooleanField(default=False)
    
    # Availability info (for providers)
    availability_block = models.ForeignKey(
        'ProviderAvailability',
        on_delete=models.SET_NULL,
        related_name='appointments',
        null=True,
        blank=True
    )
    
    # Time tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Audit fields
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_appointments',
        null=True,
        blank=True
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='updated_appointments',
        null=True,
        blank=True
    )
    
    @property
    def appointment_type_display(self):
        return self.get_appointment_type_display()
    
    @property
    def patient_name(self):
        return f"{self.patient.first_name} {self.patient.last_name}" if self.patient else "Unknown Patient"
    
    @property
    def provider_name(self):
        return f"Dr. {self.provider.last_name}" if self.provider else "Unknown Provider"
    
    @property
    def is_telemedicine(self):
        return self.appointment_type in [
            self.AppointmentType.VIDEO_CONSULTATION,
            self.AppointmentType.PHONE_CONSULTATION
        ]
    
    @property
    def needs_reminder(self):
        """Check if appointment needs a reminder."""
        if not self.reminders_enabled or self.reminder_sent:
            return False
        
        if self.status not in [self.Status.SCHEDULED, self.Status.CONFIRMED]:
            return False
        
        now = timezone.now()
        time_until_appointment = self.scheduled_time - now
        
        # Send reminder 24 hours before appointment
        return 0 < time_until_appointment.total_seconds() < 86400
    
    def __str__(self):
        return f"{self.get_appointment_type_display()} - {self.patient_name} with {self.provider_name} on {self.scheduled_time.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-scheduled_time']
        permissions = [
            ("can_view_all_appointments", "Can view all appointments"),
            ("can_manage_appointments", "Can manage appointments"),
        ]


class Consultation(models.Model):
    """Model for telemedicine consultations with enhanced features."""
    class Status(models.TextChoices):
        SCHEDULED = 'scheduled', 'Scheduled'
        READY = 'ready', 'Ready'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'
        TECHNICAL_ISSUES = 'technical_issues', 'Technical Issues'
    
    class Platform(models.TextChoices):
        ZOOM = 'zoom', 'Zoom'
        TEAMS = 'teams', 'Microsoft Teams'
        WEBEX = 'webex', 'Cisco Webex'
        CUSTOM = 'custom', 'Custom Platform'
    
    # Basic info
    appointment = models.ForeignKey(Appointment, on_delete=models.CASCADE, related_name='consultations')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.SCHEDULED)
    platform = models.CharField(
        max_length=20, 
        choices=Platform.choices, 
        default=Platform.ZOOM
    )
    
    # Timing info
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(null=True, blank=True, help_text="Duration in minutes")
    patient_join_time = models.DateTimeField(null=True, blank=True)
    provider_join_time = models.DateTimeField(null=True, blank=True)
    
    # Clinical data (encrypted)
    notes = encrypt(models.TextField(blank=True))
    diagnosis = encrypt(models.TextField(blank=True))
    treatment_plan = encrypt(models.TextField(blank=True))
    follow_up_required = models.BooleanField(default=False)
    follow_up_date = models.DateField(null=True, blank=True)
    vital_signs = encrypt(models.JSONField(default=dict, blank=True))
    
    # Related treatments
    treatments = models.ManyToManyField(
        Treatment,
        related_name='consultations',
        blank=True
    )
    
    # Meeting platform details
    meeting_id = encrypt(models.CharField(max_length=255, blank=True))
    join_url = encrypt(models.URLField(blank=True))
    password = encrypt(models.CharField(max_length=100, blank=True))
    host_key = encrypt(models.CharField(max_length=100, blank=True))
    platform_data = encrypt(models.JSONField(default=dict, blank=True))
    
    # Recording
    recording_enabled = models.BooleanField(default=False)
    recording_url = encrypt(models.URLField(blank=True))
    recording_consent = models.BooleanField(default=False)
    
    # Technical details
    technical_issues = models.TextField(blank=True)
    connection_quality = models.IntegerField(null=True, blank=True, help_text="Connection quality (1-5)")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    @property
    def patient(self):
        return self.appointment.patient if self.appointment else None
    
    @property
    def provider(self):
        return self.appointment.provider if self.appointment else None
    
    @property
    def is_completed(self):
        return self.status == self.Status.COMPLETED
    
    def calculate_duration(self):
        """Calculate consultation duration from start/end time."""
        if self.start_time and self.end_time:
            duration_seconds = (self.end_time - self.start_time).total_seconds()
            self.duration = int(duration_seconds / 60)
            return self.duration
        return None
    
    def __str__(self):
        appointment_str = str(self.appointment) if self.appointment else "Unknown Appointment"
        return f"Consultation for {appointment_str} ({self.get_status_display()})"
    
    class Meta:
        ordering = ['-created_at']
        permissions = [
            ("can_start_consultations", "Can start consultations"),
            ("can_join_consultations", "Can join consultations"),
        ]


class Prescription(models.Model):
    """Model for electronic prescriptions with enhanced tracking."""
    class Status(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        PENDING = 'pending', 'Pending'
        ACTIVE = 'active', 'Active'
        FILLED = 'filled', 'Filled'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'
        EXPIRED = 'expired', 'Expired'
        DENIED = 'denied', 'Denied'
    
    class PrescriptionType(models.TextChoices):
        MEDICATION = 'medication', 'Medication'
        EQUIPMENT = 'equipment', 'Medical Equipment'
        PROCEDURE = 'procedure', 'Procedure'
        THERAPY = 'therapy', 'Therapy'
    
    # Core fields
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='patient_prescriptions'
    )
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='telemedicine_provider_prescriptions'
    )
    consultation = models.ForeignKey(
        Consultation, 
        on_delete=models.SET_NULL, 
        related_name='prescriptions',
        null=True,
        blank=True
    )
    
    # Prescription details
    prescription_type = models.CharField(
        max_length=20,
        choices=PrescriptionType.choices,
        default=PrescriptionType.MEDICATION
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    
    # Medication details (encrypted)
    medication_name = encrypt(models.CharField(max_length=255))
    dosage = encrypt(models.CharField(max_length=100))
    frequency = encrypt(models.CharField(max_length=100))
    duration = encrypt(models.CharField(max_length=100))
    quantity = encrypt(models.CharField(max_length=100))
    refills = models.IntegerField(default=0)
    instructions = encrypt(models.TextField())
    
    # Dates
    prescribed_date = models.DateField(auto_now_add=True)
    prescribed_time = models.DateTimeField(auto_now_add=True)
    fill_date = models.DateField(null=True, blank=True)
    expiration_date = models.DateField(null=True, blank=True)
    
    # External pharmacy info
    pharmacy_notes = encrypt(models.TextField(blank=True))
    pharmacy_id = models.CharField(max_length=100, blank=True)
    external_rx_id = models.CharField(max_length=100, blank=True, unique=True, null=True)
    
    # Patient info
    patient_notified = models.BooleanField(default=False)
    patient_notification_time = models.DateTimeField(null=True, blank=True)
    
    # E-prescription details
    is_electronically_sent = models.BooleanField(default=False)
    sent_timestamp = models.DateTimeField(null=True, blank=True)
    send_method = models.CharField(max_length=50, blank=True)
    electronic_rx_reference = models.CharField(max_length=255, blank=True)
    
    # Medication details
    ndc_code = models.CharField(max_length=50, blank=True, help_text="National Drug Code")
    generic_allowed = models.BooleanField(default=True)
    prior_authorization_required = models.BooleanField(default=False)
    
    # Safety checks
    drug_interaction_checked = models.BooleanField(default=False)
    drug_allergy_checked = models.BooleanField(default=False)
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.medication_name} for {self.patient.get_full_name()}"
    
    @property
    def is_active(self):
        return self.status == self.Status.ACTIVE
    
    @property
    def days_until_expiration(self):
        if not self.expiration_date:
            return None
        delta = self.expiration_date - timezone.now().date()
        return delta.days
    
    def check_expiration(self):
        """Check if prescription has expired and update status."""
        if self.expiration_date and timezone.now().date() > self.expiration_date:
            if self.status != self.Status.EXPIRED:
                self.status = self.Status.EXPIRED
                self.save(update_fields=['status'])
            return True
        return False
    
    class Meta:
        ordering = ['-prescribed_time']
        permissions = [
            ("can_prescribe", "Can create prescriptions"),
            ("can_view_all_prescriptions", "Can view all prescriptions"),
        ]


class ProviderAvailability(models.Model):
    """Model for provider availability scheduling."""
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='availability_slots'
    )
    
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    is_available = models.BooleanField(default=True)
    
    recurrence_pattern = models.CharField(max_length=255, blank=True, help_text="iCal RRULE format for recurring availability")
    appointment_types = models.JSONField(default=list, help_text="List of appointment types available during this slot")
    slot_duration_minutes = models.IntegerField(default=15, help_text="Minimum appointment slot duration")
    max_appointments = models.IntegerField(default=1, help_text="Maximum number of appointments per slot")
    
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    @property
    def is_booked(self):
        """Check if availability is fully booked."""
        count = self.appointments.exclude(status__in=[
            Appointment.Status.CANCELLED, 
            Appointment.Status.COMPLETED,
            Appointment.Status.NO_SHOW
        ]).count()
        return count >= self.max_appointments
    
    @property
    def duration_minutes(self):
        """Calculate the duration of the availability slot in minutes."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return int(delta.total_seconds() / 60)
        return 0
    
    def __str__(self):
        return f"{self.provider.get_full_name()} - {self.start_time.strftime('%Y-%m-%d %H:%M')} to {self.end_time.strftime('%H:%M')}"
    
    class Meta:
        ordering = ['start_time']
        verbose_name = "Provider Availability"
        verbose_name_plural = "Provider Availabilities"


class WaitingRoom(models.Model):
    """Model for virtual waiting room."""
    name = models.CharField(max_length=255)
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='waiting_rooms'
    )
    
    is_active = models.BooleanField(default=True)
    estimated_wait_time = models.IntegerField(default=0, help_text="Estimated wait time in minutes")
    custom_message = models.TextField(blank=True, help_text="Custom message for patients in waiting room")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Waiting Room for {self.provider.get_full_name()}"
    
    class Meta:
        ordering = ['provider', 'name']


class WaitingRoomPatient(models.Model):
    """Model for patients in virtual waiting room."""
    class Status(models.TextChoices):
        WAITING = 'waiting', 'Waiting'
        READY = 'ready', 'Ready for Consultation'
        CANCELLED = 'cancelled', 'Cancelled'
        COMPLETED = 'completed', 'Completed'
    
    waiting_room = models.ForeignKey(
        WaitingRoom,
        on_delete=models.CASCADE,
        related_name='patients'
    )
    appointment = models.ForeignKey(
        Appointment,
        on_delete=models.CASCADE,
        related_name='waiting_room_entries'
    )
    
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.WAITING)
    checked_in_time = models.DateTimeField(auto_now_add=True)
    ready_time = models.DateTimeField(null=True, blank=True, help_text="Time when provider marked patient as ready")
    
    notes = models.TextField(blank=True)
    
    @property
    def patient(self):
        return self.appointment.patient
    
    @property
    def wait_duration(self):
        """Calculate current wait duration in minutes."""
        if self.status == self.Status.WAITING:
            delta = timezone.now() - self.checked_in_time
            return int(delta.total_seconds() / 60)
        elif self.status == self.Status.READY and self.ready_time:
            delta = self.ready_time - self.checked_in_time
            return int(delta.total_seconds() / 60)
        return 0
    
    def __str__(self):
        return f"{self.patient.get_full_name()} in {self.waiting_room.name} ({self.get_status_display()})"
    
    class Meta:
        ordering = ['checked_in_time']


class ConsultationNote(models.Model):
    """Model for structured consultation notes with templates."""
    consultation = models.OneToOneField(
        Consultation,
        on_delete=models.CASCADE,
        related_name='detailed_notes'
    )
    
    # SOAP Note fields
    subjective = encrypt(models.TextField(blank=True, help_text="Patient's subjective experience"))
    objective = encrypt(models.TextField(blank=True, help_text="Objective observations"))
    assessment = encrypt(models.TextField(blank=True, help_text="Provider's assessment"))
    plan = encrypt(models.TextField(blank=True, help_text="Treatment plan"))
    
    # Additional structured fields
    chief_complaint = encrypt(models.TextField(blank=True))
    history_present_illness = encrypt(models.TextField(blank=True))
    past_medical_history = encrypt(models.TextField(blank=True))
    medications = encrypt(models.TextField(blank=True))
    allergies = encrypt(models.TextField(blank=True))
    review_of_systems = encrypt(models.TextField(blank=True))
    physical_examination = encrypt(models.TextField(blank=True))
    diagnostic_results = encrypt(models.TextField(blank=True))
    
    # Vitals
    vital_signs = encrypt(models.JSONField(default=dict, blank=True))
    
    # Note completeness
    is_complete = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    template_used = models.CharField(max_length=100, blank=True)
    
    # Timeline
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='authored_notes'
    )
    
    def __str__(self):
        return f"Notes for {self.consultation}"
    
    def mark_complete(self):
        """Mark the note as complete."""
        self.is_complete = True
        self.completed_at = timezone.now()
        self.save(update_fields=['is_complete', 'completed_at'])
    
    class Meta:
        ordering = ['-created_at']
