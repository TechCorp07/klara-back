from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from healthcare.fields import EncryptedCharField, EncryptedJSONField, EncryptedTextField, EncryptedDateField
from healthcare.models import MedicalRecord, Condition
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth import get_user_model

User = get_user_model()

class Medication(models.Model):
    """
    Model for medications including standard and rare condition medications.
    """
    class MedicationType(models.TextChoices):
        PILL = 'pill', _('Pill')
        CAPSULE = 'capsule', _('Capsule')
        LIQUID = 'liquid', _('Liquid')
        INJECTION = 'injection', _('Injection')
        INHALER = 'inhaler', _('Inhaler')
        PATCH = 'patch', _('Patch')
        CREAM = 'cream', _('Cream')
        DROPS = 'drops', _('Drops')
        OTHER = 'other', _('Other')
    
    class FrequencyUnit(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        HOURLY = 'hourly', _('Hourly')
        AS_NEEDED = 'as_needed', _('As Needed')
        CUSTOM = 'custom', _('Custom')
    
    class RouteOfAdministration(models.TextChoices):
        ORAL = 'oral', _('Oral')
        INTRAVENOUS = 'intravenous', _('Intravenous')
        INTRAMUSCULAR = 'intramuscular', _('Intramuscular')
        SUBCUTANEOUS = 'subcutaneous', _('Subcutaneous')
        TOPICAL = 'topical', _('Topical')
        INHALATION = 'inhalation', _('Inhalation')
        OCULAR = 'ocular', _('Ocular')
        NASAL = 'nasal', _('Nasal')
        RECTAL = 'rectal', _('Rectal')
        OTHER = 'other', _('Other')
    
    # Basic information
    name = EncryptedCharField(max_length=255)
    generic_name = EncryptedCharField(max_length=255, blank=True, null=True)
    ndc_code = EncryptedCharField(max_length=50, blank=True, null=True, help_text="National Drug Code")
    rxnorm_code = EncryptedCharField(max_length=50, blank=True, null=True, help_text="RxNorm Code")
    medication_type = models.CharField(max_length=20, choices=MedicationType.choices, default=MedicationType.PILL)
    route = models.CharField(max_length=20, choices=RouteOfAdministration.choices, default=RouteOfAdministration.ORAL)
    
    # Dosage information
    dosage = EncryptedCharField(max_length=100)
    dosage_unit = models.CharField(max_length=50, blank=True, null=True)
    strength = EncryptedCharField(max_length=100, blank=True, null=True)
    
    # Frequency and timing
    frequency = EncryptedCharField(max_length=100)
    frequency_unit = models.CharField(max_length=20, choices=FrequencyUnit.choices, default=FrequencyUnit.DAILY)
    times_per_frequency = models.PositiveSmallIntegerField(default=1)
    specific_times = EncryptedJSONField(blank=True, null=True, help_text="JSON array of specific times for medication")
    
    # Enhanced rare disease fields
    clinical_trial_id = models.CharField(max_length=100, blank=True, null=True, help_text="Associated clinical trial ID")
    protocol_number = models.CharField(max_length=100, blank=True, null=True, help_text="Custom drug protocol number")
    manufacturing_batch = models.CharField(max_length=100, blank=True, null=True, help_text="Batch number for custom drugs")
    
    # Enhanced monitoring for rare diseases
    requires_lab_monitoring = models.BooleanField(default=False)
    lab_monitoring_frequency = models.CharField(
        max_length=20,
        choices=[
            ('weekly', 'Weekly'),
            ('biweekly', 'Bi-weekly'),
            ('monthly', 'Monthly'),
            ('quarterly', 'Quarterly'),
        ],
        blank=True, null=True
    )
    
    # Temperature and storage requirements for specialized drugs
    storage_temperature = models.CharField(max_length=50, blank=True, help_text="e.g., 'Store at 2-8°C'")
    special_handling_instructions = models.TextField(blank=True)
    
    # Cost tracking for rare disease medications
    cost_per_dose = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    insurance_coverage = models.BooleanField(default=False)
    prior_authorization_required = models.BooleanField(default=False)
    
    # Efficacy tracking
    efficacy_markers = models.JSONField(default=list, help_text="Biomarkers to track for efficacy")
    baseline_measurements = models.JSONField(default=dict, help_text="Baseline measurements before starting")
    
    # Duration
    start_date = EncryptedDateField()
    end_date = EncryptedDateField(blank=True, null=True)
    ongoing = models.BooleanField(default=False)
    
    # Instructions
    instructions = EncryptedTextField(blank=True, null=True)
    
    # Status
    active = models.BooleanField(default=True)
    
    # Patient and provider associations
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='medications')
    prescriber = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        related_name='medication_prescribed_medications',
        null=True, blank=True
    )
    
    # Medical record association
    medical_record = models.ForeignKey(
        MedicalRecord,
        on_delete=models.CASCADE,
        related_name='medication_medications',
        null=True, blank=True
    )
    
    # Related condition
    condition = models.ForeignKey(
        Condition,
        on_delete=models.SET_NULL,
        related_name='medications',
        null=True, blank=True
    )
    
    # Rare condition tracking
    for_rare_condition = models.BooleanField(default=False)
    is_specialty_medication = models.BooleanField(default=False)
    orphan_drug = models.BooleanField(default=False, help_text="Medication developed specifically for rare conditions")
    
    # Prescription information
    prescription_required = models.BooleanField(default=True)
    prescription = models.OneToOneField(
        'Prescription',
        on_delete=models.SET_NULL,
        related_name='medication',
        null=True, blank=True
    )
    refills_allowed = models.PositiveSmallIntegerField(default=0)
    refills_remaining = models.PositiveSmallIntegerField(default=0)
    last_refill_date = models.DateField(blank=True, null=True)
    
    # Pharmacy information
    pharmacy_name = EncryptedCharField(max_length=255, blank=True, null=True)
    pharmacy_phone = EncryptedCharField(max_length=20, blank=True, null=True)
    
    # Side effects and interactions
    potential_side_effects = EncryptedTextField(blank=True, null=True)
    known_interactions =EncryptedTextField(blank=True, null=True)
    
    # Adherence tracking
    adherence_schedule = models.JSONField(default=dict, blank=True, help_text="Scheduled times for adherence tracking")
    last_reminded_at = models.DateTimeField(blank=True, null=True)
    
    # FHIR Integration
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    effectiveness_ratings = models.JSONField(default=list)  # Store effectiveness ratings
    side_effects_history = models.JSONField(default=list)   # Track side effects over time
    adherence_goal = models.FloatField(default=0.90)        # Patient's adherence goal
    is_rare_condition_med = models.BooleanField(default=False)
    smart_reminders_enabled = models.BooleanField(default=True)

    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='medication_created_medications',
        null=True, blank=True
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='updated_medications',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.name} - {self.dosage}"
    
    def is_expired(self):
        """Check if medication is expired."""
        if not self.end_date:
            return False
        return self.end_date < timezone.now().date()
    
    def days_remaining(self):
        """Calculate days remaining for this medication."""
        if not self.end_date or self.ongoing:
            return None
        return (self.end_date - timezone.now().date()).days
    
    def needs_refill(self):
        """Check if medication needs refill."""
        if not self.prescription_required:
            return False
        return self.refills_remaining <= 0
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = "Medication"
        verbose_name_plural = "Medications"


class Prescription(models.Model):
    """
    Model for tracking prescriptions.
    """
    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        ACTIVE = 'active', _('Active')
        FILLED = 'filled', _('Filled')
        EXPIRED = 'expired', _('Expired')
        CANCELLED = 'cancelled', _('Cancelled')
        COMPLETED = 'completed', _('Completed')
    
    # Basic prescription information
    prescription_number = EncryptedCharField(max_length=100, unique=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    
    # Dates
    prescribed_date = models.DateField()
    fill_date = models.DateField(blank=True, null=True)
    expiration_date = models.DateField(blank=True, null=True)
    
    # Patient and provider
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='prescriptions')
    prescriber = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        related_name='medication_provider_prescriptions',
        null=True, blank=True
    )
    
    # Medication details
    medication_name = EncryptedCharField(max_length=255)
    dosage = EncryptedCharField(max_length=100)
    frequency = EncryptedCharField(max_length=100)
    quantity = EncryptedCharField(max_length=50)
    refills = models.PositiveSmallIntegerField(default=0)
    
    # Pharmacy details
    pharmacy_name = EncryptedCharField(max_length=255, blank=True, null=True)
    pharmacy_phone = EncryptedCharField(max_length=20, blank=True, null=True)
    pharmacy_address = EncryptedTextField(blank=True, null=True)
    
    # E-prescription details
    is_electronic = models.BooleanField(default=False)
    electronic_routing_id = EncryptedCharField(max_length=100, blank=True, null=True)
    
    # Instructions and notes
    instructions = EncryptedTextField(blank=True, null=True)
    notes = EncryptedTextField(blank=True, null=True)
    
    # FHIR Integration
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_prescriptions',
        null=True, blank=True
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='updated_prescriptions',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"Prescription {self.prescription_number} - {self.medication_name}"
    
    def is_expired(self):
        """Check if prescription is expired."""
        if not self.expiration_date:
            return False
        return self.expiration_date < timezone.now().date()
    
    def days_until_expiration(self):
        """Calculate days until prescription expires."""
        if not self.expiration_date:
            return None
        return (self.expiration_date - timezone.now().date()).days
    
    class Meta:
        ordering = ['-prescribed_date']
        verbose_name = "Prescription"
        verbose_name_plural = "Prescriptions"


class MedicationIntake(models.Model):
    """
    Model for tracking medication intake events for adherence monitoring.
    """
    class Status(models.TextChoices):
        TAKEN = 'taken', _('Taken')
        SKIPPED = 'skipped', _('Skipped')
        MISSED = 'missed', _('Missed')
        RESCHEDULED = 'rescheduled', _('Rescheduled')
    
    # Basic information
    medication = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='intakes')
    scheduled_time = models.DateTimeField()
    actual_time = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.MISSED)
    
    # Dose information
    dosage_taken = EncryptedCharField(max_length=100, blank=True, null=True)
    
    # Skip reason
    skip_reason = EncryptedTextField(blank=True, null=True)
    
    # Notes
    notes = EncryptedTextField(blank=True, null=True)
    
    # Record information
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='recorded_intakes',
        null=True, blank=True
    )
    recorded_via = models.CharField(max_length=50, blank=True, help_text="app, wearable, caregiver, etc.")
    
    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        status = self.get_status_display()
        return f"{self.medication.name} - {status} at {self.actual_time or self.scheduled_time}"
    
    def is_late(self):
        """Check if medication intake is late."""
        if self.status != self.Status.MISSED:
            return False
        now = timezone.now()
        return self.scheduled_time < now
    
    def minutes_late(self):
        """Calculate minutes late for missed or late intake."""
        if not self.is_late():
            return 0
        delta = timezone.now() - self.scheduled_time
        return int(delta.total_seconds() / 60)
    
    class Meta:
        ordering = ['-scheduled_time']
        verbose_name = "Medication Intake"
        verbose_name_plural = "Medication Intakes"


class MedicationReminder(models.Model):
    """
    Model for medication reminders.
    """
    class ReminderType(models.TextChoices):
        DOSE = 'dose', _('Dose Reminder')
        REFILL = 'refill', _('Refill Reminder')
        APPOINTMENT = 'appointment', _('Appointment Reminder')
        LAB = 'lab', _('Lab Test Reminder')
    
    class Frequency(models.TextChoices):
        ONCE = 'once', _('Once')
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        CUSTOM = 'custom', _('Custom')
    
    # Basic information
    medication = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='reminders')
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='medication_reminders')
    
    # Reminder details
    reminder_type = models.CharField(max_length=20, choices=ReminderType.choices, default=ReminderType.DOSE)
    message = EncryptedTextField()
    frequency = models.CharField(max_length=20, choices=Frequency.choices, default=Frequency.DAILY)
    
    # Timing
    scheduled_time = models.DateTimeField()
    recurrence_pattern = models.CharField(max_length=255, blank=True, null=True, help_text="iCal RRULE format")
    window_before = models.PositiveIntegerField(default=0, help_text="Minutes before scheduled time to start sending reminders")
    window_after = models.PositiveIntegerField(default=0, help_text="Minutes after scheduled time to stop sending reminders")
    
    # Status
    is_active = models.BooleanField(default=True)
    last_sent = models.DateTimeField(blank=True, null=True)
    
    # Notification preferences
    send_email = models.BooleanField(default=True)
    send_push = models.BooleanField(default=True)
    send_sms = models.BooleanField(default=False)
    
    # Smartwatch integration
    send_smartwatch = models.BooleanField(default=False)
    smartwatch_delivery_confirmed = models.BooleanField(default=False)
    
    # Enhanced for rare diseases
    is_critical = models.BooleanField(default=False, help_text="Critical reminder for rare disease medication")
    escalation_enabled = models.BooleanField(default=False, help_text="Escalate to provider if missed")
    escalation_delay_minutes = models.PositiveIntegerField(default=60, help_text="Minutes before escalating")
    
    # Tracking
    times_sent = models.PositiveIntegerField(default=0)
    patient_acknowledged = models.BooleanField(default=False)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    
    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_medication_reminders',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.get_reminder_type_display()} for {self.medication.name}"
    
    def is_due(self):
        """Check if reminder is due to be sent."""
        if not self.is_active:
            return False
            
        now = timezone.now()
        
        # If reminder was already sent today
        if self.last_sent and self.last_sent.date() == now.date() and self.frequency != self.Frequency.ONCE:
            return False
            
        # Calculate window
        earliest = self.scheduled_time - timezone.timedelta(minutes=self.window_before)
        latest = self.scheduled_time + timezone.timedelta(minutes=self.window_after)
        
        return earliest <= now <= latest
    
    class Meta:
        ordering = ['scheduled_time']
        verbose_name = "Medication Reminder"
        verbose_name_plural = "Medication Reminders"


class AdherenceRecord(models.Model):
    """
    Model for tracking medication adherence over time.
    """
    class Period(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')
    
    # Basic information
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='adherence_records')
    medication = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='adherence_records')
    
    # Time period
    period_type = models.CharField(max_length=20, choices=Period.choices, default=Period.WEEKLY)
    period_start = models.DateField()
    period_end = models.DateField()
    
    # Adherence metrics
    doses_scheduled = models.PositiveIntegerField(default=0)
    doses_taken = models.PositiveIntegerField(default=0)
    doses_skipped = models.PositiveIntegerField(default=0)
    doses_missed = models.PositiveIntegerField(default=0)
    
    # Calculated fields
    adherence_rate = models.FloatField(default=0.0, help_text="Percentage of doses taken on time")
    average_delay = models.FloatField(default=0.0, help_text="Average minutes late for doses")
    
    # Notes and explanations
    notes = EncryptedTextField(blank=True, null=True)
    
    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Adherence for {self.medication.name} - {self.period_start} to {self.period_end}"
    
    def calculate_adherence_rate(self):
        """Calculate the adherence rate as a percentage."""
        if self.doses_scheduled == 0:
            return 0.0
        return (self.doses_taken / self.doses_scheduled) * 100.0
    
    def update_from_intakes(self):
        """Update adherence record based on medication intakes in the period."""
        intakes = MedicationIntake.objects.filter(
            medication=self.medication,
            scheduled_time__date__gte=self.period_start,
            scheduled_time__date__lte=self.period_end
        )
        
        self.doses_scheduled = intakes.count()
        self.doses_taken = intakes.filter(status=MedicationIntake.Status.TAKEN).count()
        self.doses_skipped = intakes.filter(status=MedicationIntake.Status.SKIPPED).count()
        self.doses_missed = intakes.filter(status=MedicationIntake.Status.MISSED).count()
        
        # Calculate adherence rate
        self.adherence_rate = self.calculate_adherence_rate()
        
        # Calculate average delay for taken doses
        taken_intakes = intakes.filter(status=MedicationIntake.Status.TAKEN)
        if taken_intakes.exists():
            total_delay = 0
            count = 0
            for intake in taken_intakes:
                if intake.actual_time and intake.scheduled_time:
                    delay = (intake.actual_time - intake.scheduled_time).total_seconds() / 60
                    if delay > 0:  # Only count positive delays (late)
                        total_delay += delay
                        count += 1
            
            self.average_delay = total_delay / count if count > 0 else 0
        
        self.save()
    
    class Meta:
        ordering = ['-period_start']
        verbose_name = "Adherence Record"
        verbose_name_plural = "Adherence Records"


class SideEffect(models.Model):
    """
    Model for tracking medication side effects experienced by patients.
    """
    class Severity(models.TextChoices):
        MILD = 'mild', _('Mild')
        MODERATE = 'moderate', _('Moderate')
        SEVERE = 'severe', _('Severe')
        LIFE_THREATENING = 'life_threatening', _('Life Threatening')
    
    # Basic information
    medication = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='side_effects')
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reported_side_effects')
    
    # Side effect details
    description = EncryptedTextField()
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MILD)
    
    # Timing
    onset_date = models.DateField()
    resolution_date = models.DateField(blank=True, null=True)
    ongoing = models.BooleanField(default=True)
    
    # Action taken
    reported_to_doctor = models.BooleanField(default=False)
    doctor_notified_date = models.DateField(blank=True, null=True)
    medication_adjusted = models.BooleanField(default=False)
    medication_stopped = models.BooleanField(default=False)
    
    # Additional notes
    notes = EncryptedTextField(blank=True, null=True)
    
    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_side_effects',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.medication.name} - {self.description[:50]}"
    
    def duration_days(self):
        """Calculate duration of side effect in days."""
        if self.ongoing:
            return (timezone.now().date() - self.onset_date).days
        elif self.resolution_date:
            return (self.resolution_date - self.onset_date).days
        return None
    
    class Meta:
        ordering = ['-onset_date']
        verbose_name = "Side Effect"
        verbose_name_plural = "Side Effects"


class DrugInteraction(models.Model):
    """
    Model for tracking potential drug interactions.
    """
    class Severity(models.TextChoices):
        MINOR = 'minor', _('Minor')
        MODERATE = 'moderate', _('Moderate')
        MAJOR = 'major', _('Major')
        CONTRAINDICATED = 'contraindicated', _('Contraindicated')
    
    # Interacting medications
    medication_a = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='interactions_as_a')
    medication_b = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='interactions_as_b')
    
    # Patient reference
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='drug_interactions')
    
    # Interaction details
    description = EncryptedTextField()
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MODERATE)
    
    # Action taken
    detected_date = models.DateField(auto_now_add=True)
    resolved_date = models.DateField(blank=True, null=True)
    resolution_action = EncryptedTextField(blank=True, null=True)
    
    # Notification status
    patient_notified = models.BooleanField(default=False)
    provider_notified = models.BooleanField(default=False)
    
    # Meta information
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_interactions',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"Interaction between {self.medication_a.name} and {self.medication_b.name}"
    
    def is_resolved(self):
        """Check if interaction is resolved."""
        return self.resolved_date is not None
    
    class Meta:
        ordering = ['-detected_date']
        verbose_name = "Drug Interaction"
        verbose_name_plural = "Drug Interactions"
        # Ensure each medication pair is only registered once for a patient
        unique_together = [['medication_a', 'medication_b', 'patient']]


class MedicationAdherence(models.Model):
    """Enhanced medication adherence tracking with effectiveness and mood data."""
    
    prescription = models.ForeignKey('Prescription', on_delete=models.CASCADE, related_name='adherence_records')
    date = models.DateField()
    scheduled_time = models.DateTimeField()
    taken = models.BooleanField()
    taken_time = models.DateTimeField(null=True, blank=True)
    effectiveness_rating = models.IntegerField(null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(5)])  # 1-5
    mood_before = models.IntegerField(null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(5)])           # 1-5
    mood_after = models.IntegerField(null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(5)])            # 1-5
    symptoms_before = models.JSONField(default=list)
    symptoms_after = models.JSONField(default=list)
    side_effects = models.JSONField(default=list)
    notes = models.TextField(blank=True)
    missed_reason = models.CharField(max_length=100, blank=True, choices=[
        ('forgot', 'Forgot to take it'),
        ('side_effects', 'Experienced side effects'),
        ('feeling_better', 'Feeling better'),
        ('ran_out', 'Ran out of medication'),
        ('travel', 'Traveling/not at home'),
        ('cost', 'Cost concerns'),
        ('other', 'Other reason'),
    ])
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-scheduled_time']
        unique_together = ['prescription', 'scheduled_time']
        
    def __str__(self):
        status = "Taken" if self.taken else "Missed"
        return f"{self.prescription.medication_name} - {self.date} - {status}"
