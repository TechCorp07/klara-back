from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django_cryptography.fields import encrypt

class MedicalRecord(models.Model):
    """Model for patient medical records with enhanced security and HIPAA compliance."""
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='medical_records')
    medical_record_number = encrypt(models.CharField(max_length=50, unique=True))
    date_of_birth = encrypt(models.DateField())
    gender = encrypt(models.CharField(max_length=20))
    blood_type = encrypt(models.CharField(max_length=10, blank=True, null=True))
    height = encrypt(models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True))  # in cm
    weight = encrypt(models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True))  # in kg
    
    # Enhanced patient data
    ethnicity = encrypt(models.CharField(max_length=50, blank=True, null=True))
    preferred_language = models.CharField(max_length=50, blank=True, null=True)
    emergency_contact_name = encrypt(models.CharField(max_length=100, blank=True, null=True))
    emergency_contact_phone = encrypt(models.CharField(max_length=20, blank=True, null=True))
    emergency_contact_relationship = models.CharField(max_length=50, blank=True, null=True)
    
    # Provider relationships
    primary_physician = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        related_name='primary_patients',
        limit_choices_to={'role': 'provider'},
        blank=True, 
        null=True
    )
    
    # Rare condition flag
    has_rare_condition = models.BooleanField(default=False)
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    fhir_last_updated = models.DateTimeField(blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_medical_records',
        null=True, blank=True
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='updated_medical_records',
        null=True, blank=True
    )
    
    # Consent fields
    data_sharing_authorized = models.BooleanField(default=False)
    research_participation_consent = models.BooleanField(default=False)
    research_consent_date = models.DateTimeField(blank=True, null=True)
    
    # Versioning
    version = models.IntegerField(default=1)  # For tracking record versions
    is_active = models.BooleanField(default=True)  # For soft deletion
    
    def __str__(self):
        return f"Medical Record #{self.medical_record_number} - {self.patient.get_full_name()}"
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = "Medical Record"
        verbose_name_plural = "Medical Records"
        permissions = [
            ("view_phi", "Can view protected health information"),
            ("export_records", "Can export medical records"),
        ]


class RareConditionRegistry(models.Model):
    """Model for tracking rare conditions and their characteristics."""
    name = models.CharField(max_length=255, unique=True)
    identifier = models.CharField(max_length=50, blank=True, null=True)  # ORPHA, OMIM or other code
    description = models.TextField()
    prevalence = models.CharField(max_length=100, blank=True)
    inheritance_pattern = models.CharField(max_length=100, blank=True)
    onset_age = models.CharField(max_length=100, blank=True)
    specialty_category = models.CharField(max_length=100, blank=True)
    
    # Research and treatment information
    known_treatments = models.TextField(blank=True)
    biomarkers = models.TextField(blank=True)
    research_resources = models.TextField(blank=True)
    patient_organizations = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.identifier})" if self.identifier else self.name
    
    class Meta:
        ordering = ['name']
        verbose_name = "Rare Condition Registry"
        verbose_name_plural = "Rare Condition Registry"


class Medication(models.Model):
    """Model for patient medications with enhanced tracking for adherence."""
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='healthcare_medications')
    name = encrypt(models.CharField(max_length=255))
    dosage = encrypt(models.CharField(max_length=100))
    frequency = encrypt(models.CharField(max_length=100))
    instructions = encrypt(models.TextField(blank=True))
    start_date = encrypt(models.DateField())
    end_date = encrypt(models.DateField(blank=True, null=True))
    active = models.BooleanField(default=True)
    reason = encrypt(models.TextField(blank=True))
    
    # Enhanced medication tracking
    medication_type = models.CharField(max_length=50, blank=True)  # e.g., pill, injection, liquid
    is_specialty_medication = models.BooleanField(default=False)
    for_rare_condition = models.BooleanField(default=False)
    orphan_drug = models.BooleanField(default=False)  # For medications developed specifically for rare conditions
    refill_count = models.IntegerField(default=0)
    refill_until = models.DateField(blank=True, null=True)
    pharmacy_notes = encrypt(models.TextField(blank=True))
    
    # Side effects monitoring
    side_effects_reported = models.BooleanField(default=False)
    side_effects_notes = encrypt(models.TextField(blank=True))
    
    # Adherence tracking
    adherence_schedule = models.JSONField(blank=True, null=True)  # For storing complex medication schedules
    last_reminded_at = models.DateTimeField(blank=True, null=True)
    
    # Healthcare provider
    prescriber = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        related_name='healthcare_prescribed_medications',
        limit_choices_to={'role': 'provider'},
        blank=True, 
        null=True
    )
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='healthcare_created_medications',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.name} - {self.dosage}"
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = "Medication"
        verbose_name_plural = "Medications"


class MedicationIntake(models.Model):
    """Model for tracking medication intake and adherence."""
    medication = models.ForeignKey(Medication, on_delete=models.CASCADE, related_name='intakes')
    taken_at = models.DateTimeField()
    dosage_taken = models.CharField(max_length=100)
    skipped = models.BooleanField(default=False)
    skip_reason = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True
    )
    recorded_via = models.CharField(max_length=50, blank=True)  # e.g., app, wearable, caregiver
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        status = "Skipped" if self.skipped else "Taken"
        return f"{self.medication.name} - {status} at {self.taken_at}"
    
    class Meta:
        ordering = ['-taken_at']


class Allergy(models.Model):
    """Model for patient allergies."""
    class Severity(models.TextChoices):
        MILD = 'mild', _('Mild')
        MODERATE = 'moderate', _('Moderate')
        SEVERE = 'severe', _('Severe')
        LIFE_THREATENING = 'life_threatening', _('Life-threatening')
    
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='allergies')
    agent = encrypt(models.CharField(max_length=255))
    reaction = encrypt(models.TextField(blank=True))
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MODERATE)
    diagnosed_date = encrypt(models.DateField(blank=True, null=True))
    
    # Enhanced allergy data
    allergy_type = models.CharField(max_length=50, blank=True)  # e.g., medication, food, environmental
    verification_status = models.CharField(max_length=50, blank=True)  # e.g., confirmed, suspected
    last_occurrence = encrypt(models.DateField(blank=True, null=True))
    treatment_notes = encrypt(models.TextField(blank=True))
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_allergies',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.agent} - {self.severity}"
    
    class Meta:
        ordering = ['-severity', 'agent']
        verbose_name = "Allergy"
        verbose_name_plural = "Allergies"


class Condition(models.Model):
    """Model for patient medical conditions with comprehensive rare condition support."""
    class Status(models.TextChoices):
        ACTIVE = 'active', _('Active')
        RESOLVED = 'resolved', _('Resolved')
        REMISSION = 'remission', _('In Remission')
        RECURRENCE = 'recurrence', _('Recurrence')
        INACTIVE = 'inactive', _('Inactive')
    
    class Category(models.TextChoices):
        GENERAL = 'general', _('General')
        RARE = 'rare', _('Rare Condition')
        CHRONIC = 'chronic', _('Chronic')
        ACUTE = 'acute', _('Acute')
        CONGENITAL = 'congenital', _('Congenital')
    
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='conditions')
    name = encrypt(models.CharField(max_length=255))
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    category = models.CharField(max_length=15, choices=Category.choices, default=Category.GENERAL)
    diagnosed_date = encrypt(models.DateField(blank=True, null=True))
    resolved_date = encrypt(models.DateField(blank=True, null=True))
    notes = encrypt(models.TextField(blank=True))
    
    # Enhanced condition data
    icd10_code = encrypt(models.CharField(max_length=20, blank=True, null=True))
    is_primary = models.BooleanField(default=False)
    diagnosing_provider = encrypt(models.CharField(max_length=255, blank=True, null=True))
    
    # Rare condition specific fields
    is_rare_condition = models.BooleanField(default=False)
    rare_condition = models.ForeignKey(
        RareConditionRegistry, 
        on_delete=models.SET_NULL,
        related_name='patient_conditions',
        null=True, blank=True
    )
    
    # Generic biomarker/genetics tracking
    biomarker_status = models.JSONField(blank=True, null=True)  # For storing key biomarkers and status
    genetic_information = encrypt(models.TextField(blank=True, null=True))  # For genetic information
    
    # Condition progression tracking
    progression_metrics = models.JSONField(blank=True, null=True)  # For condition-specific metrics
    last_assessment_date = models.DateField(blank=True, null=True)
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_conditions',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.name} - {self.get_status_display()}"
    
    class Meta:
        ordering = ['-is_primary', '-created_at']
        verbose_name = "Medical Condition"
        verbose_name_plural = "Medical Conditions"


class ConditionFlare(models.Model):
    """Model for tracking flares or exacerbations of conditions."""
    condition = models.ForeignKey(Condition, on_delete=models.CASCADE, related_name='flares')
    onset_date = encrypt(models.DateField())
    resolved_date = encrypt(models.DateField(blank=True, null=True))
    symptoms = encrypt(models.TextField())
    severity = models.IntegerField(help_text="Scale of 1-10")
    hospitalized = models.BooleanField(default=False)
    treatment = encrypt(models.TextField(blank=True))
    notes = encrypt(models.TextField(blank=True))
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Flare on {self.onset_date} - {self.condition.name}"
    
    class Meta:
        ordering = ['-onset_date']


class Symptom(models.Model):
    """Model for tracking symptoms, particularly important for rare condition tracking."""
    condition = models.ForeignKey(Condition, on_delete=models.CASCADE, related_name='symptoms')
    name = encrypt(models.CharField(max_length=255))
    description = encrypt(models.TextField(blank=True))
    first_observed = encrypt(models.DateField())
    last_observed = encrypt(models.DateField(blank=True, null=True))
    is_active = models.BooleanField(default=True)
    
    # Severity tracking
    severity = models.IntegerField(default=1, help_text="Scale of 1-10")
    frequency = models.CharField(max_length=50, blank=True)  # e.g., daily, weekly, intermittent
    duration = models.CharField(max_length=50, blank=True)  # e.g., minutes, hours, constant
    
    # Impact tracking
    impact_daily_life = models.IntegerField(default=1, help_text="Scale of 1-10")
    impact_notes = encrypt(models.TextField(blank=True))
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='recorded_symptoms',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.name} (Severity: {self.severity}/10)"
    
    class Meta:
        ordering = ['-severity', 'name']


class Immunization(models.Model):
    """Model for patient immunizations."""
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='immunizations')
    vaccine = encrypt(models.CharField(max_length=255))
    date_administered = encrypt(models.DateField())
    administered_by = encrypt(models.CharField(max_length=255, blank=True))
    lot_number = encrypt(models.CharField(max_length=100, blank=True))
    notes = encrypt(models.TextField(blank=True))
    
    # Enhanced immunization data
    manufacturer = encrypt(models.CharField(max_length=100, blank=True))
    dose_number = models.IntegerField(blank=True, null=True)
    series_doses = models.IntegerField(blank=True, null=True)
    route = models.CharField(max_length=50, blank=True)  # e.g., intramuscular, oral
    site = models.CharField(max_length=50, blank=True)  # e.g., left arm, right thigh
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_immunizations',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.vaccine} - {self.date_administered}"
    
    class Meta:
        ordering = ['-date_administered']


class LabTest(models.Model):
    """Model for patient lab tests."""
    class Status(models.TextChoices):
        ORDERED = 'ordered', _('Ordered')
        PENDING = 'pending', _('Pending')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')
    
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='lab_tests')
    name = encrypt(models.CharField(max_length=255))
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ORDERED)
    ordered_date = encrypt(models.DateField())
    ordered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        related_name='ordered_lab_tests',
        limit_choices_to={'role': 'provider'},
        blank=True, 
        null=True
    )
    completed_date = encrypt(models.DateField(blank=True, null=True))
    notes = encrypt(models.TextField(blank=True))
    
    # Enhanced lab test data
    lab_location = encrypt(models.CharField(max_length=255, blank=True))
    test_type = models.CharField(max_length=100, blank=True)  # e.g., blood, urine, imaging
    fasting_required = models.BooleanField(default=False)
    priority = models.CharField(max_length=20, blank=True)  # e.g., routine, stat, urgent
    
    # Rare condition specific
    for_rare_condition_monitoring = models.BooleanField(default=False)
    related_condition = models.ForeignKey(
        Condition,
        on_delete=models.SET_NULL,
        related_name='related_lab_tests',
        null=True, blank=True
    )
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_lab_tests',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.name} - {self.get_status_display()}"
    
    class Meta:
        ordering = ['-ordered_date']


class LabResult(models.Model):
    """Model for patient lab test results."""
    lab_test = models.ForeignKey(LabTest, on_delete=models.CASCADE, related_name='results')
    test_name = encrypt(models.CharField(max_length=255))
    value = encrypt(models.CharField(max_length=100))
    unit = encrypt(models.CharField(max_length=50, blank=True))
    reference_range = encrypt(models.CharField(max_length=100, blank=True))
    is_abnormal = models.BooleanField(default=False)
    notes = encrypt(models.TextField(blank=True))
    
    # Enhanced lab result data
    result_date = models.DateTimeField(auto_now_add=True)
    interpreted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='interpreted_lab_results',
        limit_choices_to={'role': 'provider'},
        null=True, blank=True
    )
    interpretation = encrypt(models.TextField(blank=True))
    
    # Rare condition tracking
    biomarker_significance = encrypt(models.TextField(blank=True))  # Interpretation for rare condition monitoring
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_lab_results',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.test_name}: {self.value} {self.unit}"
    
    class Meta:
        ordering = ['-result_date']


class VitalSign(models.Model):
    """Model for patient vital signs, including wearable integration."""
    MEASUREMENT_TYPES = [
        ('blood_pressure', 'Blood Pressure'),
        ('heart_rate', 'Heart Rate'),
        ('temperature', 'Temperature'),
        ('respiratory_rate', 'Respiratory Rate'),
        ('oxygen_saturation', 'Oxygen Saturation'),
        ('weight', 'Weight'),
        ('height', 'Height'),
        ('bmi', 'Body Mass Index'),
        ('pain', 'Pain Level'),
        ('glucose', 'Blood Glucose'),
        ('steps', 'Steps Count'),
        ('sleep', 'Sleep Duration'),
        ('activity', 'Activity Level'),
    ]
    
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='vital_signs', null=True, blank=True)
    measurement_type = models.CharField(max_length=50, choices=MEASUREMENT_TYPES)
    value = encrypt(models.CharField(max_length=100))  # Store as string to handle different formats
    unit = models.CharField(max_length=50, blank=True)
    measured_at = models.DateTimeField()
    source = models.CharField(max_length=100, blank=True)  # e.g., manual, withings, fitbit, apple_health, google_fit
    source_device_id = models.CharField(max_length=255, blank=True)
    notes = encrypt(models.TextField(blank=True))
    
    # Specific vital sign fields
    blood_pressure = encrypt(models.CharField(max_length=20, blank=True))  # e.g., "120/80"
    heart_rate = encrypt(models.IntegerField(null=True, blank=True))
    temperature = encrypt(models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True))
    respiratory_rate = encrypt(models.IntegerField(null=True, blank=True))
    oxygen_saturation = encrypt(models.IntegerField(null=True, blank=True))
    
    # Enhanced vitals data
    is_abnormal = models.BooleanField(default=False)
    context = models.CharField(max_length=100, blank=True)  # e.g., resting, after exercise, during illness
    
    # Correlation with rare condition
    related_to_condition = models.ForeignKey(
        Condition,
        on_delete=models.SET_NULL,
        related_name='condition_vitals',
        null=True, blank=True
    )
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_vital_signs',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.get_measurement_type_display()}: {self.value} {self.unit} ({self.measured_at})"
    
    class Meta:
        ordering = ['-measured_at']


class Treatment(models.Model):
    """Model for treatments and procedures."""
    class Status(models.TextChoices):
        PLANNED = 'planned', _('Planned')
        IN_PROGRESS = 'in_progress', _('In Progress')
        COMPLETED = 'completed', _('Completed')
        CANCELLED = 'cancelled', _('Cancelled')
    
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='treatments')
    name = encrypt(models.CharField(max_length=255))
    treatment_type = models.CharField(max_length=100)  # e.g., procedure, therapy, surgery
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.PLANNED)
    start_date = encrypt(models.DateField())
    end_date = encrypt(models.DateField(blank=True, null=True))
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='provided_treatments',
        limit_choices_to={'role': 'provider'},
        null=True, blank=True
    )
    location = encrypt(models.CharField(max_length=255, blank=True))
    notes = encrypt(models.TextField(blank=True))
    
    # Enhanced treatment data
    reason = encrypt(models.TextField(blank=True))
    outcome = encrypt(models.TextField(blank=True))
    complications = encrypt(models.TextField(blank=True))
    follow_up_required = models.BooleanField(default=False)
    follow_up_notes = encrypt(models.TextField(blank=True))
    
    # Rare condition specific
    for_rare_condition = models.BooleanField(default=False)
    related_condition = models.ForeignKey(
        Condition,
        on_delete=models.SET_NULL,
        related_name='condition_treatments',
        null=True, blank=True
    )
    is_experimental = models.BooleanField(default=False)
    part_of_clinical_trial = models.BooleanField(default=False)
    clinical_trial_id = models.CharField(max_length=100, blank=True, null=True)
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_treatments',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.name} - {self.get_status_display()}"
    
    class Meta:
        ordering = ['-start_date']


class FamilyHistory(models.Model):
    """Model for family medical history with rare condition tracking."""
    RELATIONSHIP_CHOICES = [
        ('mother', 'Mother'),
        ('father', 'Father'),
        ('sister', 'Sister'),
        ('brother', 'Brother'),
        ('daughter', 'Daughter'),
        ('son', 'Son'),
        ('grandmother_maternal', 'Maternal Grandmother'),
        ('grandfather_maternal', 'Maternal Grandfather'),
        ('grandmother_paternal', 'Paternal Grandmother'),
        ('grandfather_paternal', 'Paternal Grandfather'),
        ('aunt_maternal', 'Maternal Aunt'),
        ('uncle_maternal', 'Maternal Uncle'),
        ('aunt_paternal', 'Paternal Aunt'),
        ('uncle_paternal', 'Paternal Uncle'),
        ('cousin', 'Cousin'),
        ('other', 'Other'),
    ]
    
    medical_record = models.ForeignKey(MedicalRecord, on_delete=models.CASCADE, related_name='family_history')
    relationship = models.CharField(max_length=25, choices=RELATIONSHIP_CHOICES)
    condition = encrypt(models.CharField(max_length=255))
    diagnosed_age = encrypt(models.IntegerField(blank=True, null=True))
    notes = encrypt(models.TextField(blank=True))
    is_deceased = models.BooleanField(default=False)
    deceased_age = encrypt(models.IntegerField(blank=True, null=True))
    deceased_reason = encrypt(models.CharField(max_length=255, blank=True))
    
    # Rare condition specific
    is_rare_condition = models.BooleanField(default=False)
    rare_condition = models.ForeignKey(
        RareConditionRegistry,
        on_delete=models.SET_NULL,
        related_name='family_history_entries',
        null=True, blank=True
    )
    
    # FHIR fields
    fhir_resource_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_family_history',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.get_relationship_display()}: {self.condition}"
    
    class Meta:
        ordering = ['relationship']
        verbose_name = "Family History"
        verbose_name_plural = "Family History"


class HealthDataConsent(models.Model):
    """Model for tracking detailed health data consent."""
    CONSENT_TYPES = [
        ('provider_access', 'Healthcare Provider Access'),
        ('research', 'Research Use'),
        ('caregiver_access', 'Caregiver Access'),
        ('data_sharing', 'Data Sharing with Third Parties'),
        ('medication_tracking', 'Medication Adherence Tracking'),
        ('vitals_monitoring', 'Vitals Monitoring'),
        ('wearable_integration', 'Wearable Device Integration'),
    ]
    
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='health_data_consents',
        limit_choices_to={'role': 'patient'}
    )
    consent_type = models.CharField(max_length=25, choices=CONSENT_TYPES)
    consented = models.BooleanField(default=False)
    consented_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    notes = models.TextField(blank=True)
    
    # For specific access
    authorized_entity = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='authorized_health_data',
        null=True, blank=True
    )
    
    # Metadata
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        status = "Granted" if self.consented else "Declined"
        return f"{self.get_consent_type_display()}: {status} by {self.patient.username}"
    
    class Meta:
        ordering = ['-consented_at']
        unique_together = [['patient', 'consent_type', 'authorized_entity']]


class HealthDataAuditLog(models.Model):
    """Model for tracking access to health data for HIPAA compliance."""
    ACTION_TYPES = [
        ('view', 'View'),
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('export', 'Export'),
        ('import', 'Import'),
        ('share', 'Share'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='health_data_access_logs',
        null=True, blank=True
    )
    action = models.CharField(max_length=10, choices=ACTION_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # What was accessed
    resource_type = models.CharField(max_length=50)  # e.g., MedicalRecord, Medication
    resource_id = models.CharField(max_length=50)
    patient_id = models.CharField(max_length=50)
    
    # Additional details
    access_reason = models.CharField(max_length=255, blank=True)
    details = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.get_action_display()} on {self.resource_type} #{self.resource_id} by {self.user}"
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Health Data Audit Log"
        verbose_name_plural = "Health Data Audit Logs"


class EHRIntegration(models.Model):
    """Model for tracking EHR integrations."""
    INTEGRATION_TYPES = [
        ('epic', 'Epic'),
        ('cerner', 'Cerner'),
        ('allscripts', 'Allscripts'),
        ('meditech', 'Meditech'),
        ('athenahealth', 'Athenahealth'),
        ('nextgen', 'NextGen'),
        ('eclinicalworks', 'eClinicalWorks'),
        ('other', 'Other')
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('pending', 'Pending'),
        ('failed', 'Failed'),
        ('inactive', 'Inactive')
    ]
    
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='ehr_integrations',
        limit_choices_to={'role': 'patient'}
    )
    integration_type = models.CharField(max_length=20, choices=INTEGRATION_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    external_id = encrypt(models.CharField(max_length=255, blank=True, null=True))
    integration_details = models.JSONField(blank=True, null=True)
    last_sync = models.DateTimeField(blank=True, null=True)
    
    # Authentication and access
    access_token = encrypt(models.TextField(blank=True, null=True))
    refresh_token = encrypt(models.TextField(blank=True, null=True))
    token_expiry = models.DateTimeField(blank=True, null=True)
    
    # Consent
    consent_granted = models.BooleanField(default=False)
    consent_date = models.DateTimeField(blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_ehr_integrations',
        null=True, blank=True
    )
    
    def __str__(self):
        return f"{self.get_integration_type_display()} integration for {self.patient.username} - {self.get_status_display()}"
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = "EHR Integration"
        verbose_name_plural = "EHR Integrations"


class WearableIntegration(models.Model):
    """Model for tracking wearable device integrations."""
    DEVICE_TYPES = [
        ('apple_health', 'Apple Health'),
        ('google_fit', 'Google Fit'),
        ('fitbit', 'Fitbit'),
        ('samsung_health', 'Samsung Health'),
        ('withings', 'Withings'),
        ('garmin', 'Garmin'),
        ('whoop', 'Whoop'),
        ('oura', 'Oura Ring'),
        ('other', 'Other')
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('pending', 'Pending'),
        ('failed', 'Failed'),
        ('inactive', 'Inactive')
    ]
    
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='healthcare_wearable_integrations',
        limit_choices_to={'role': 'patient'}
    )
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES)
    device_name = encrypt(models.CharField(max_length=255, blank=True, null=True))
    device_id = encrypt(models.CharField(max_length=255, blank=True, null=True))
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    integration_details = models.JSONField(blank=True, null=True)
    last_sync = models.DateTimeField(blank=True, null=True)
    
    # Authentication and access
    access_token = encrypt(models.TextField(blank=True, null=True))
    refresh_token = encrypt(models.TextField(blank=True, null=True))
    token_expiry = models.DateTimeField(blank=True, null=True)
    
    # Data collection settings
    collect_heart_rate = models.BooleanField(default=True)
    collect_steps = models.BooleanField(default=True)
    collect_sleep = models.BooleanField(default=True)
    collect_activity = models.BooleanField(default=True)
    collect_blood_pressure = models.BooleanField(default=False)
    collect_blood_glucose = models.BooleanField(default=False)
    collect_oxygen = models.BooleanField(default=False)
    
    # Consent
    consent_granted = models.BooleanField(default=False)
    consent_date = models.DateTimeField(blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.get_device_type_display()} integration for {self.patient.username} - {self.get_status_display()}"
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = "Wearable Integration"
        verbose_name_plural = "Wearable Integrations"


class ReferralNetwork(models.Model):
    """Model for rare condition specialist referral network."""
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='referral_specialties',
        limit_choices_to={'role': 'provider'}
    )
    specialty = models.CharField(max_length=255)
    
    # Rare condition specialization
    rare_conditions_specialty = models.BooleanField(default=False)
    specific_conditions = models.ManyToManyField(
        RareConditionRegistry,
        related_name='specialist_providers',
        blank=True
    )
    
    years_experience = models.IntegerField(default=0)
    location = models.CharField(max_length=255)
    accepting_patients = models.BooleanField(default=True)
    telemedicine_available = models.BooleanField(default=False)
    insurance_accepted = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.provider.get_full_name()} - {self.specialty}"
    
    class Meta:
        ordering = ['specialty', '-years_experience']
        verbose_name = "Referral Network Entry"
        verbose_name_plural = "Referral Network"
