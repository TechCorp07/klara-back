"""
NMOSD-specific neurological indicators for Klararety platform.
Implements specialized models and services for NMOSD monitoring.
"""
from django.db import models
from django.conf import settings
from fhir.models.observation import FHIRObservation
from fhir.models.patient import FHIRPatient


class NMOSDNeurologicalIndicator(models.Model):
    """
    Base model for NMOSD-specific neurological indicators.
    Provides common fields and functionality for all NMOSD indicators.
    """
    observation = models.OneToOneField(
        FHIRObservation,
        on_delete=models.CASCADE,
        related_name='nmosd_indicator_details',
        help_text="Associated FHIR Observation"
    )
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.CASCADE,
        related_name='nmosd_indicators',
        help_text="Patient this indicator is for"
    )
    
    indicator_type = models.CharField(
        max_length=50,
        choices=[
            ('tremor', 'Tremor'),
            ('gait', 'Gait Analysis'),
            ('balance', 'Balance'),
            ('fatigue', 'Fatigue'),
            ('vision', 'Vision'),
            ('pain', 'Pain'),
            ('spasticity', 'Spasticity'),
            ('cognition', 'Cognition'),
            ('other', 'Other')
        ],
        help_text="Type of NMOSD indicator"
    )
    
    measurement_date = models.DateTimeField(help_text="When the measurement was taken")
    device_type = models.CharField(max_length=100, help_text="Type of device used for measurement")
    device_model = models.CharField(max_length=100, blank=True, help_text="Model of device used")
    
    severity_score = models.IntegerField(
        help_text="Severity score (0-10, where 0 is none and 10 is severe)"
    )
    
    previous_score = models.IntegerField(null=True, blank=True, help_text="Previous severity score")
    trend = models.CharField(
        max_length=20,
        choices=[
            ('improving', 'Improving'),
            ('stable', 'Stable'),
            ('worsening', 'Worsening'),
            ('unknown', 'Unknown')
        ],
        default='unknown',
        help_text="Trend compared to previous measurements"
    )
    
    is_clinically_significant = models.BooleanField(
        default=False,
        help_text="Whether this measurement is clinically significant"
    )
    
    notes = models.TextField(blank=True, help_text="Additional notes about the measurement")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "NMOSD Neurological Indicator"
        verbose_name_plural = "NMOSD Neurological Indicators"
        ordering = ['-measurement_date']
        indexes = [
            models.Index(fields=['patient']),
            models.Index(fields=['indicator_type']),
            models.Index(fields=['measurement_date']),
            models.Index(fields=['severity_score']),
            models.Index(fields=['trend']),
            models.Index(fields=['is_clinically_significant']),
        ]
    
    def __str__(self):
        return f"{self.get_indicator_type_display()} for {self.patient.name} ({self.measurement_date})"
    
    def calculate_trend(self):
        if self.previous_score is None:
            return 'unknown'
        if self.severity_score < self.previous_score:
            return 'improving'
        elif self.severity_score == self.previous_score:
            return 'stable'
        else:
            return 'worsening'
    
    def save(self, *args, **kwargs):
        if self.previous_score is not None:
            self.trend = self.calculate_trend()
        super().save(*args, **kwargs)
        
        # Update associated FHIR Observation
        observation = self.observation
        observation.is_nmosd_indicator = True
        observation.nmosd_indicator_type = self.indicator_type
        
        extensions = observation.extension or []
        # Remove existing NMOSD-related extensions
        extensions = [
            ext for ext in extensions
            if not ext.get('url', '').endswith('nmosd-severity-score')
            and not ext.get('url', '').endswith('nmosd-trend')
            and not ext.get('url', '').endswith('nmosd-clinically-significant')
        ]
        
        extensions.append({
            "url": "https://klararety.com/fhir/StructureDefinition/nmosd-severity-score",
            "valueInteger": self.severity_score
        })
        extensions.append({
            "url": "https://klararety.com/fhir/StructureDefinition/nmosd-trend",
            "valueString": self.trend
        })
        extensions.append({
            "url": "https://klararety.com/fhir/StructureDefinition/nmosd-clinically-significant",
            "valueBoolean": self.is_clinically_significant
        })
        
        observation.extension = extensions
        observation.save()


class TremorMeasurement(NMOSDNeurologicalIndicator):
    tremor_frequency = models.FloatField(help_text="Tremor frequency in Hz")
    tremor_amplitude = models.FloatField(help_text="Tremor amplitude in mm")
    tremor_location = models.CharField(
        max_length=50,
        choices=[
            ('hand_right', 'Right Hand'),
            ('hand_left', 'Left Hand'),
            ('arm_right', 'Right Arm'),
            ('arm_left', 'Left Arm'),
            ('leg_right', 'Right Leg'),
            ('leg_left', 'Left Leg'),
            ('head', 'Head'),
            ('trunk', 'Trunk'),
            ('other', 'Other')
        ],
        help_text="Location of tremor"
    )
    tremor_type = models.CharField(
        max_length=50,
        choices=[
            ('rest', 'Rest Tremor'),
            ('postural', 'Postural Tremor'),
            ('kinetic', 'Kinetic Tremor'),
            ('intention', 'Intention Tremor'),
            ('task_specific', 'Task-Specific Tremor'),
            ('other', 'Other')
        ],
        help_text="Type of tremor"
    )
    impact_on_activities = models.IntegerField(
        help_text="Impact on daily activities (0-10, where 0 is none and 10 is severe)"
    )
    
    class Meta:
        verbose_name = "Tremor Measurement"
        verbose_name_plural = "Tremor Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'tremor'
        super().save(*args, **kwargs)


class GaitAnalysis(NMOSDNeurologicalIndicator):
    walking_speed = models.FloatField(help_text="Walking speed in m/s")
    step_length = models.FloatField(help_text="Step length in cm")
    stride_length = models.FloatField(help_text="Stride length in cm")
    cadence = models.FloatField(help_text="Cadence in steps/min")
    gait_symmetry = models.FloatField(help_text="Gait symmetry index (0-1, where 1 is perfect symmetry)")
    stability_score = models.FloatField(help_text="Stability score (0-100, where 100 is perfect stability)")
    fall_risk = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low Risk'),
            ('moderate', 'Moderate Risk'),
            ('high', 'High Risk')
        ]
    )
    distance_walked = models.FloatField(help_text="Distance walked in meters")
    test_duration = models.IntegerField(help_text="Test duration in seconds")
    
    class Meta:
        verbose_name = "Gait Analysis"
        verbose_name_plural = "Gait Analyses"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'gait'
        super().save(*args, **kwargs)


class BalanceMeasurement(NMOSDNeurologicalIndicator):
    sway_area = models.FloatField(help_text="Sway area in cm²")
    sway_velocity = models.FloatField(help_text="Sway velocity in cm/s")
    center_of_pressure = models.JSONField(default=dict, help_text="Center of pressure coordinates")
    test_condition = models.CharField(
        max_length=50,
        choices=[
            ('eyes_open', 'Eyes Open'),
            ('eyes_closed', 'Eyes Closed'),
            ('foam_surface', 'Foam Surface'),
            ('tandem_stance', 'Tandem Stance'),
            ('single_leg', 'Single Leg Stance'),
            ('other', 'Other')
        ]
    )
    test_duration = models.IntegerField(help_text="Test duration in seconds")
    completed_test = models.BooleanField(default=True, help_text="Whether the patient completed the test")
    
    class Meta:
        verbose_name = "Balance Measurement"
        verbose_name_plural = "Balance Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'balance'
        super().save(*args, **kwargs)


class FatigueMeasurement(NMOSDNeurologicalIndicator):
    fatigue_scale = models.CharField(
        max_length=50,
        choices=[
            ('fss', 'Fatigue Severity Scale'),
            ('mfis', 'Modified Fatigue Impact Scale'),
            ('vas', 'Visual Analog Scale'),
            ('other', 'Other')
        ]
    )
    scale_score = models.FloatField(help_text="Score on the fatigue scale")
    scale_max_score = models.FloatField(help_text="Maximum possible score on the scale")
    fatigue_type = models.CharField(
        max_length=50,
        choices=[
            ('physical', 'Physical Fatigue'),
            ('mental', 'Mental Fatigue'),
            ('mixed', 'Mixed Fatigue')
        ]
    )
    impact_on_activities = models.IntegerField(
        help_text="Impact on daily activities (0-10, where 0 is none and 10 is severe)"
    )
    
    class Meta:
        verbose_name = "Fatigue Measurement"
        verbose_name_plural = "Fatigue Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'fatigue'
        super().save(*args, **kwargs)


class VisionMeasurement(NMOSDNeurologicalIndicator):
    visual_acuity_right = models.CharField(max_length=20, help_text="Visual acuity in right eye (e.g., 20/20)")
    visual_acuity_left = models.CharField(max_length=20, help_text="Visual acuity in left eye (e.g., 20/20)")
    visual_field_defect = models.BooleanField(default=False)
    visual_field_details = models.TextField(blank=True)
    color_vision_defect = models.BooleanField(default=False)
    color_vision_details = models.TextField(blank=True)
    optic_neuritis_history = models.BooleanField(default=False)
    optic_neuritis_active = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Vision Measurement"
        verbose_name_plural = "Vision Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'vision'
        super().save(*args, **kwargs)


class PainMeasurement(NMOSDNeurologicalIndicator):
    pain_scale = models.CharField(
        max_length=50,
        choices=[
            ('nrs', 'Numeric Rating Scale'),
            ('vas', 'Visual Analog Scale'),
            ('faces', 'Faces Pain Scale'),
            ('other', 'Other')
        ]
    )
    pain_location = models.JSONField(default=list, help_text="Location(s) of pain")
    pain_quality = models.CharField(
        max_length=50,
        choices=[
            ('sharp', 'Sharp'),
            ('dull', 'Dull'),
            ('burning', 'Burning'),
            ('tingling', 'Tingling'),
            ('shooting', 'Shooting'),
            ('throbbing', 'Throbbing'),
            ('other', 'Other')
        ]
    )
    pain_pattern = models.CharField(
        max_length=50,
        choices=[
            ('constant', 'Constant'),
            ('intermittent', 'Intermittent'),
            ('paroxysmal', 'Paroxysmal'),
            ('other', 'Other')
        ]
    )
    pain_triggers = models.TextField(blank=True)
    pain_relief = models.TextField(blank=True)
    
    class Meta:
        verbose_name = "Pain Measurement"
        verbose_name_plural = "Pain Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'pain'
        super().save(*args, **kwargs)


class SpasticityMeasurement(NMOSDNeurologicalIndicator):
    spasticity_scale = models.CharField(
        max_length=50,
        choices=[
            ('ashworth', 'Modified Ashworth Scale'),
            ('tardieu', 'Tardieu Scale'),
            ('penn', 'Penn Spasm Frequency Scale'),
            ('other', 'Other')
        ]
    )
    spasticity_location = models.CharField(
        max_length=50,
        choices=[
            ('arm_right', 'Right Arm'),
            ('arm_left', 'Left Arm'),
            ('leg_right', 'Right Leg'),
            ('leg_left', 'Left Leg'),
            ('trunk', 'Trunk'),
            ('generalized', 'Generalized'),
            ('other', 'Other')
        ]
    )
    spasticity_score = models.FloatField(help_text="Score on the spasticity scale")
    spasticity_triggers = models.TextField(blank=True)
    impact_on_mobility = models.IntegerField(
        help_text="Impact on mobility (0-10, where 0 is none and 10 is severe)"
    )
    impact_on_activities = models.IntegerField(
        help_text="Impact on daily activities (0-10, where 0 is none and 10 is severe)"
    )
    
    class Meta:
        verbose_name = "Spasticity Measurement"
        verbose_name_plural = "Spasticity Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'spasticity'
        super().save(*args, **kwargs)


class CognitionMeasurement(NMOSDNeurologicalIndicator):
    """
    Specialized model for cognition measurements in NMOSD patients.
    """
    # Cognitive test used
    cognitive_test = models.CharField(max_length=100, help_text="Name of cognitive test used")
    cognitive_score = models.FloatField(help_text="Score on the cognitive test")
    cognitive_max_score = models.FloatField(help_text="Maximum possible score on the cognitive test")
    
    # Cognitive domains
    domains_affected = models.JSONField(default=list, help_text="List of cognitive domains affected (e.g. memory, attention)")
    
    # Impact on daily living
    impact_on_activities = models.IntegerField(
        help_text="Impact on daily activities (0-10, where 0 is none and 10 is severe)"
    )
    
    class Meta:
        verbose_name = "Cognition Measurement"
        verbose_name_plural = "Cognition Measurements"
    
    def save(self, *args, **kwargs):
        self.indicator_type = 'cognition'
        super().save(*args, **kwargs)
