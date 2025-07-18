import uuid
import json
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from healthcare.fields import EncryptedCharField, EncryptedTextField, EncryptedDateField
from cryptography.fernet import Fernet
from django.conf import settings
from datetime import timedelta


class PharmaceuticalTenant(models.Model):
    """
    Represents pharmaceutical companies using the platform.
    Enables multi-tenant data isolation for competing pharmaceutical companies.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    
    # Pharmaceutical company details
    regulatory_id = models.CharField(max_length=100, unique=True, help_text="FDA or regulatory body ID")
    contact_email = models.EmailField()
    primary_therapeutic_areas = models.JSONField(default=list, help_text="List of therapeutic focus areas")
    
    # Platform configuration
    is_active = models.BooleanField(default=True)
    features_enabled = models.JSONField(default=dict, help_text="Tenant-specific feature flags")
    branding_config = models.JSONField(default=dict, help_text="Custom branding and UI configuration")
    
    # Compliance and audit
    created_at = models.DateTimeField(auto_now_add=True)
    last_audit_date = models.DateTimeField(null=True, blank=True)
    compliance_status = models.CharField(max_length=20, default='ACTIVE', choices=[
        ('ACTIVE', 'Active'),
        ('UNDER_REVIEW', 'Under Review'),
        ('SUSPENDED', 'Suspended'),
        ('TERMINATED', 'Terminated')
    ])
    
    class Meta:
        db_table = 'pharmaceutical_tenants'
        verbose_name = 'Pharmaceutical Tenant'
        verbose_name_plural = 'Pharmaceutical Tenants'
    
    def __str__(self):
        return self.name


class User(AbstractUser):
    """Custom user model for Klararety Health Platform."""
    
    class Role(models.TextChoices):
        PATIENT = 'patient', _('Patient')
        PROVIDER = 'provider', _('Healthcare Provider')
        PHARMCO = 'pharmco', _('Pharmaceutical Company')
        ADMIN = 'admin', _('Administrator')
        SUPERUSER = 'superuser', _('Super Administrator')
        CAREGIVER = 'caregiver', _('Caregiver')
        RESEARCHER = 'researcher', _('Researcher')
        COMPLIANCE = 'compliance', _('Compliance Officer')
    
    # Basic information
    email = models.EmailField(_('email address'), unique=True)
    phone_number = models.CharField(max_length=20, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.PATIENT)
    profile_image = models.ImageField(
        upload_to='profile_images/',
        null=True, 
        blank=True,
        help_text="User profile image" )
    
    # Security fields
    two_factor_enabled = models.BooleanField(default=False)
    login_attempts = models.IntegerField(default=0)
    account_locked = models.BooleanField(default=False)
    account_locked_time = models.DateTimeField(null=True, blank=True)
    password_last_changed = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    security_questions_set = models.BooleanField(default=False)
    
    # Consent tracking
    terms_accepted = models.BooleanField(default=False)
    hipaa_privacy_acknowledged = models.BooleanField(default=False)
    hipaa_privacy_acknowledged_at = models.DateTimeField(null=True, blank=True)
    
    # Role-specific consent fields
    data_sharing_consent = models.BooleanField(default=False)
    caregiver_authorization_acknowledged = models.BooleanField(default=False)  # For caregivers
    phi_handling_acknowledged = models.BooleanField(default=False)  # For pharmco/researchers
    
    # Approval tracking
    is_approved = models.BooleanField(default=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_users')
    
    # Email verification
    email_verified = models.BooleanField(default=False)
    email_verification_token = models.UUIDField(default=uuid.uuid4, editable=False, null=True, blank=True)
    email_verification_sent_at = models.DateTimeField(null=True, blank=True)
    
    # Password reset
    reset_password_token = models.UUIDField(null=True, blank=True)
    reset_password_token_created_at = models.DateTimeField(null=True, blank=True)
    
    # Pharmaceutical tenant association
    pharmaceutical_tenants = models.ManyToManyField(
        PharmaceuticalTenant, 
        blank=True, 
        related_name='users',
        help_text="Pharmaceutical companies this user has access to"
    )
    primary_pharmaceutical_tenant = models.ForeignKey(
        PharmaceuticalTenant, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='primary_users',
        help_text="Primary pharmaceutical tenant for this user"
    )
    
    # JWT token management
    jwt_secret_version = models.IntegerField(default=1, help_text="Version for JWT secret rotation")
    last_token_refresh = models.DateTimeField(null=True, blank=True)

    # Research participation tracking
    research_participant_id = models.CharField(max_length=100, null=True, blank=True, unique=True)
    research_enrollment_date = models.DateTimeField(null=True, blank=True)

    # Profile creation flag
    profile_created = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    def save(self, *args, **kwargs):
        # Ensure username equals email
        if self.email:
            self.username = self.email
        super().save(*args, **kwargs)
    
    def approve_user(self, approver):
        """Approve a user's account and create their profile."""
        self.is_approved = True
        self.approved_at = timezone.now()
        self.approved_by = approver
        self.save(update_fields=['is_approved', 'approved_at', 'approved_by'])
        
        # Create profile after approval
        if not self.profile_created:
            self.create_profile()

    def create_profile(self):
        """Create the appropriate profile based on user role with stored registration data."""
        if self.profile_created:
            return
    
        try:
            # Get stored registration data
            reg_data = TemporaryRegistrationData.objects.get(email=self.email)
            profile_data = reg_data.profile_data
            
            if self.role == self.Role.PATIENT:
                PatientProfile.objects.create(
                    user=self,
                    **{k: v for k, v in profile_data.items() if hasattr(PatientProfile, k)}
                )
            elif self.role == self.Role.PROVIDER:
                ProviderProfile.objects.create(
                    user=self,
                    **{k: v for k, v in profile_data.items() if hasattr(ProviderProfile, k)}
                )
            elif self.role == self.Role.PHARMCO:
                PharmcoProfile.objects.create(
                    user=self,
                    **{k: v for k, v in profile_data.items() if hasattr(PharmcoProfile, k)}
                )
            elif self.role == self.Role.CAREGIVER:
                CaregiverProfile.objects.create(
                    user=self,
                    **{k: v for k, v in profile_data.items() if hasattr(CaregiverProfile, k)}
                )
            elif self.role == self.Role.RESEARCHER:
                ResearcherProfile.objects.create(
                    user=self,
                    **{k: v for k, v in profile_data.items() if hasattr(ResearcherProfile, k)}
                )
            elif self.role == self.Role.COMPLIANCE:
                ComplianceProfile.objects.create(
                    user=self,
                    **{k: v for k, v in profile_data.items() if hasattr(ComplianceProfile, k)}
                )
            
            self.profile_created = True
            self.save(update_fields=['profile_created'])
            
            # Clean up temporary data
            reg_data.delete()
        
        except TemporaryRegistrationData.DoesNotExist:
            # Create minimal profile if no temp data
            if self.role == self.Role.PATIENT:
                PatientProfile.objects.create(user=self)
            # Add other roles as needed

            self.profile_created = True
            self.save(update_fields=['profile_created'])
    
    def lock_account(self):
        """Lock account after too many failed login attempts."""
        self.account_locked = True
        self.account_locked_time = timezone.now()
        self.save(update_fields=['account_locked', 'account_locked_time'])
    
    def unlock_account(self):
        """Unlock account."""
        self.account_locked = False
        self.account_locked_time = None
        self.login_attempts = 0
        self.save(update_fields=['account_locked', 'account_locked_time', 'login_attempts'])
    
    def increment_login_attempt(self):
        """Increment failed login attempts."""
        self.login_attempts += 1
        if self.login_attempts >= 5:
            self.lock_account()
        else:
            self.save(update_fields=['login_attempts'])
    
    def generate_email_verification_token(self):
        """Generate a new email verification token."""
        self.email_verification_token = uuid.uuid4()
        self.email_verification_sent_at = timezone.now()
        self.save(update_fields=['email_verification_token', 'email_verification_sent_at'])
        return self.email_verification_token
    
    def verify_email(self):
        """Mark email as verified."""
        self.email_verified = True
        self.email_verification_token = None
        self.email_verification_sent_at = None
        self.save(update_fields=['email_verified', 'email_verification_token', 'email_verification_sent_at'])
    
    def generate_password_reset_token(self):
        """Generate password reset token."""
        self.reset_password_token = uuid.uuid4()
        self.reset_password_token_created_at = timezone.now()
        self.save(update_fields=['reset_password_token', 'reset_password_token_created_at'])
        return self.reset_password_token
    
    def clear_password_reset_token(self):
        """Clear password reset token."""
        self.reset_password_token = None
        self.reset_password_token_created_at = None
        self.save(update_fields=['reset_password_token', 'reset_password_token_created_at'])
    
    def record_consent(self, consent_type, consented=True):
        """Record consent with e-signature."""
        return ConsentRecord.objects.create(
            user=self,
            consent_type=consent_type,
            consented=consented,
            signature_timestamp=timezone.now()
        )
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


class TemporaryRegistrationData(models.Model):
    """Store registration data temporarily until user approval."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='temp_registration_data')
    data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Temp data for {self.user.email}"
    
    class Meta:
        verbose_name = "Temporary Registration Data"
        verbose_name_plural = "Temporary Registration Data"


class TwoFactorDevice(models.Model):
    """Two-factor authentication device."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='two_factor_device')
    secret_key = models.CharField(max_length=255)
    confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"2FA Device for {self.user.username}"


class PatientProfile(models.Model):
    """Patient profile with healthcare information."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='patient_profile')
    
    # Personal medical information
    medical_id = EncryptedCharField(max_length=50, blank=True)
    blood_type = EncryptedCharField(max_length=10, blank=True)
    allergies = EncryptedTextField(blank=True)
    
    # Emergency contact
    emergency_contact_name = EncryptedCharField(max_length=255, blank=True)
    emergency_contact_phone = EncryptedCharField(max_length=20, blank=True)
    emergency_contact_relationship = models.CharField(max_length=50, blank=True)
    
    # Primary condition
    primary_condition = EncryptedCharField(max_length=255, blank=True)
    condition_diagnosis_date = EncryptedDateField(null=True, blank=True)
    
    # Consent preferences
    medication_adherence_monitoring_consent = models.BooleanField(default=False)
    medication_adherence_consent_date = models.DateTimeField(null=True, blank=True)
    vitals_monitoring_consent = models.BooleanField(default=False)
    vitals_monitoring_consent_date = models.DateTimeField(null=True, blank=True)
    research_participation_consent = models.BooleanField(default=False)
    research_consent_date = models.DateTimeField(null=True, blank=True)
    
    # Identity verification
    identity_verified = models.BooleanField(default=False)
    identity_verification_date = models.DateTimeField(null=True, blank=True)
    identity_verification_method = models.CharField(max_length=50, blank=True)
    verification_deadline_notified = models.BooleanField(default=False)
    first_login_date = models.DateTimeField(null=True, blank=True)
    
    # Notification preferences for medication adherence
    medication_reminder_enabled = models.BooleanField(default=True)
    medication_reminder_methods = models.JSONField(default=list, help_text="['email', 'sms', 'push', 'smartwatch']")
    medication_reminder_frequency = models.CharField(
        max_length=20,
        choices=[
            ('immediate', 'Immediate'),
            ('15min', '15 minutes before'),
            ('30min', '30 minutes before'),
            ('1hour', '1 hour before'),
        ],
        default='immediate'
    )
    
    # Appointment reminders
    appointment_reminder_enabled = models.BooleanField(default=True)
    appointment_reminder_methods = models.JSONField(default=list)
    appointment_reminder_advance_days = models.PositiveIntegerField(default=1)
    
    # Smart watch integration for reminders
    smartwatch_device_id = models.CharField(max_length=255, blank=True, null=True)
    smartwatch_integration_active = models.BooleanField(default=False)
    
        # Rare disease specific fields
    rare_disease_diagnosed = models.BooleanField(default=False)
    rare_disease_conditions = models.JSONField(default=list, help_text="List of rare conditions")
    rare_disease_diagnosis_date = models.DateField(null=True, blank=True)
    genetic_counseling_received = models.BooleanField(default=False)
    
    # Custom drug protocol participation
    custom_drug_protocols = models.JSONField(default=list, help_text="Active custom drug protocols")
    protocol_adherence_monitoring = models.BooleanField(default=False)
    
    # Family history tracking for genetics
    family_history_data = models.JSONField(default=dict, help_text="Structured family medical history")
    genetic_data_sharing_consent = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Patient Profile: {self.user.username}"
    
    def record_first_login(self):
        """Record first login for verification deadline."""
        if not self.first_login_date:
            self.first_login_date = timezone.now()
            self.save(update_fields=['first_login_date'])
    
    def days_until_verification_required(self):
        """Calculate days until verification deadline."""
        if self.identity_verified or not self.first_login_date:
            return None
        deadline = self.first_login_date + timedelta(days=30)
        return max(0, (deadline - timezone.now()).days)
    
    def verify_identity(self, method='E_SIGNATURE'):
        """Mark identity as verified."""
        self.identity_verified = True
        self.identity_verification_date = timezone.now()
        self.identity_verification_method = method
        self.save(update_fields=['identity_verified', 'identity_verification_date', 'identity_verification_method'])


class ProviderProfile(models.Model):
    """Healthcare provider profile."""
    
    SPECIALTY_CHOICES = [
        ('RARE_DISEASE', 'Rare Disease Specialist'),
        ('GENETICS', 'Medical Genetics'),
        ('NEUROLOGY', 'Neurology'),
        ('ONCOLOGY', 'Oncology'),
        ('CARDIOLOGY', 'Cardiology'),
        ('ENDOCRINOLOGY', 'Endocrinology'),
        ('IMMUNOLOGY', 'Immunology'),
        ('PEDIATRICS', 'Pediatrics'),
        ('INTERNAL_MEDICINE', 'Internal Medicine'),
        ('FAMILY_MEDICINE', 'Family Medicine'),
        ('OTHER', 'Other Specialty'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='provider_profile')
    
    # Professional information
    medical_license_number = models.CharField(max_length=50)
    npi_number = models.CharField(max_length=10)  # National Provider Identifier
    specialty = models.CharField(max_length=40, choices=SPECIALTY_CHOICES)
    practice_name = models.CharField(max_length=255)
    practice_address = models.TextField()
    
    # Availability
    accepting_new_patients = models.BooleanField(default=True)
    telemedicine_available = models.BooleanField(default=False)
    
    # Additional fields
    years_of_experience = models.PositiveSmallIntegerField(default=0)
    rare_condition_specialties = models.TextField(blank=True)
    
    def __str__(self):
        return f"Provider Profile: {self.user.username}"


class PharmcoProfile(models.Model):
    """Pharmaceutical company profile."""
    
    ROLE_CHOICES = [
        ('RESEARCHER', 'Researcher'),
        ('CLINICAL_AFFAIRS', 'Clinical Affairs'),
        ('REGULATORY_AFFAIRS', 'Regulatory Affairs'),
        ('MEDICAL_AFFAIRS', 'Medical Affairs'),
        ('DATA_SCIENTIST', 'Data Scientist'),
        ('COMPLIANCE_OFFICER', 'Compliance Officer'),
        ('EXECUTIVE', 'Executive'),
        ('OTHER', 'Other'),
    ]
    
    RESEARCH_FOCUS_CHOICES = [
        ('RARE_DISEASES', 'Rare Diseases'),
        ('ONCOLOGY', 'Oncology'),
        ('NEUROLOGY', 'Neurology'),
        ('CARDIOLOGY', 'Cardiology'),
        ('IMMUNOLOGY', 'Immunology'),
        ('ENDOCRINOLOGY', 'Endocrinology'),
        ('PEDIATRICS', 'Pediatrics'),
        ('GENETICS', 'Genetics'),
        ('DRUG_DEVELOPMENT', 'Drug Development'),
        ('CLINICAL_TRIALS', 'Clinical Trials'),
        ('OTHER', 'Other'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='pharmco_profile')
    
    # Company information
    company_name = models.CharField(max_length=255)
    role_at_company = models.CharField(max_length=50, choices=ROLE_CHOICES)  # Added based on requirements
    regulatory_id = models.CharField(max_length=100)  # FDA establishment identifier, EIN, etc.
    primary_research_focus = models.CharField(max_length=50, choices=RESEARCH_FOCUS_CHOICES)
    
    # Additional fields
    company_address = models.TextField(blank=True)
    monitored_medications = models.TextField(blank=True)
    
    def __str__(self):
        return f"Pharmco Profile: {self.user.username}"


class CaregiverProfile(models.Model):
    """Caregiver profile."""
    CAREGIVER_TYPES = [
        ('FAMILY', 'Family Member'),
        ('PROFESSIONAL', 'Professional Caregiver'),
        ('FRIEND', 'Friend'),
        ('LEGAL_GUARDIAN', 'Legal Guardian'),
        ('HEALTHCARE_PROXY', 'Healthcare Proxy'),
        ('OTHER', 'Other'),
    ]
    
    RELATIONSHIP_CHOICES = [
        ('PARENT', 'Parent'),
        ('SPOUSE', 'Spouse/Partner'),
        ('CHILD', 'Child'),
        ('SIBLING', 'Sibling'),
        ('GRANDPARENT', 'Grandparent'),
        ('GRANDCHILD', 'Grandchild'),
        ('FRIEND', 'Friend'),
        ('PROFESSIONAL_CAREGIVER', 'Professional Caregiver'),
        ('LEGAL_GUARDIAN', 'Legal Guardian'),
        ('HEALTHCARE_PROXY', 'Healthcare Proxy'),
        ('OTHER_FAMILY', 'Other Family Member'),
        ('OTHER', 'Other'),
    ]
    
    ACCESS_LEVELS = [
        ('VIEW_ONLY', 'View Only'),
        ('SCHEDULE', 'Scheduling'),
        ('MEDICATIONS', 'Medication Management'),
        ('FULL', 'Full Access'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='caregiver_profile')
    
    # Caregiver information
    relationship_to_patient = models.CharField(max_length=30, choices=RELATIONSHIP_CHOICES)
    caregiver_type = models.CharField(max_length=20, choices=CAREGIVER_TYPES)  # Added based on requirements
    patient_email = models.EmailField()  # Patient they're requesting to care for
    
    # Access control
    access_level = models.CharField(max_length=20, choices=ACCESS_LEVELS, default='VIEW_ONLY')
    authorization_documentation = models.BooleanField(default=False)
    
    # Status
    is_primary_caregiver = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    
    def __str__(self):
        return f"Caregiver Profile: {self.user.username}"


class ResearcherProfile(models.Model):
    """Clinical researcher profile."""
    
    RESEARCHER_TYPES = [
        ('ACADEMIC', 'Academic Researcher'),
        ('CLINICAL', 'Clinical Researcher'),
        ('INDUSTRY', 'Industry Researcher'),
        ('GOVERNMENT', 'Government Researcher'),
        ('NON_PROFIT', 'Non-Profit Researcher'),
    ]
    
    RESEARCH_AREAS = [
        ('RARE_DISEASES', 'Rare Diseases'),
        ('ONCOLOGY', 'Oncology'),
        ('NEUROLOGY', 'Neurology'),
        ('GENETICS', 'Genetics'),
        ('DRUG_DEVELOPMENT', 'Drug Development'),
        ('CLINICAL_TRIALS', 'Clinical Trials'),
        ('BIOMARKERS', 'Biomarkers'),
        ('GENOMICS', 'Genomics'),
        ('OTHER', 'Other'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='researcher_profile')
    
    # Institution information
    institution_name = models.CharField(max_length=255)
    institution_type = models.CharField(max_length=20, choices=RESEARCHER_TYPES)
    department = models.CharField(max_length=255, blank=True)
    research_id = models.CharField(max_length=100, unique=True)  # ORCID, institutional ID
    
    # Research focus
    primary_research_area = models.CharField(max_length=50, choices=RESEARCH_AREAS)
    research_interests = models.TextField(help_text="Detailed research interests")
    current_studies = models.JSONField(default=list, help_text="Active research studies")
    
    # Credentials
    highest_degree = models.CharField(max_length=50)
    years_experience = models.PositiveIntegerField(default=0)
    publications_count = models.PositiveIntegerField(default=0)
    
    # Verification
    institutional_verification = models.BooleanField(default=False)
    verification_documents = models.JSONField(default=list)
    
    def __str__(self):
        return f"Researcher Profile: {self.user.username} - {self.institution_name}"


class ComplianceProfile(models.Model):
    """Compliance officer profile."""
    
    COMPLIANCE_ROLES = [
        ('HIPAA_OFFICER', 'HIPAA Compliance Officer'),
        ('DPO', 'Data Protection Officer'),
        ('QUALITY_ASSURANCE', 'Quality Assurance'),
        ('REGULATORY_AFFAIRS', 'Regulatory Affairs'),
        ('AUDIT_MANAGER', 'Audit Manager'),
        ('CHIEF_COMPLIANCE', 'Chief Compliance Officer'),
    ]
    
    CERTIFICATION_TYPES = [
        ('CHC', 'Certified in Healthcare Compliance'),
        ('CIPP', 'Certified Information Privacy Professional'),
        ('CISA', 'Certified Information Systems Auditor'),
        ('CISSP', 'Certified Information Systems Security Professional'),
        ('OTHER', 'Other'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='compliance_profile')
    
    # Professional information
    organization_name = models.CharField(max_length=255)
    compliance_role = models.CharField(max_length=30, choices=COMPLIANCE_ROLES)
    license_number = models.CharField(max_length=100, blank=True)
    
    # Areas of responsibility
    compliance_areas = models.JSONField(default=list, help_text="Areas of compliance oversight")
    audit_permissions = models.JSONField(default=list, help_text="Systems they can audit")
    
    # Certifications
    certifications = models.JSONField(default=list, help_text="Professional certifications")
    certification_expiry = models.DateField(null=True, blank=True)
    
    # Access permissions
    can_view_all_phi = models.BooleanField(default=False)
    can_generate_reports = models.BooleanField(default=True)
    can_audit_access_logs = models.BooleanField(default=True)
    
    def __str__(self):
        return f"Compliance Profile: {self.user.username} - {self.organization_name}"


class CaregiverRequest(models.Model):
    """Pending caregiver-patient relationship requests."""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('DENIED', 'Denied'),
        ('EXPIRED', 'Expired'),
    ]
    
    caregiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='caregiver_requests')
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='patient_caregiver_requests')
    relationship = models.CharField(max_length=100)
    requested_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    
    # Response tracking
    responded_at = models.DateTimeField(null=True, blank=True)
    response_notes = models.TextField(blank=True)
    
    # Notification tracking
    patient_notified = models.BooleanField(default=False)
    reminder_sent = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ('caregiver', 'patient')
        ordering = ['-requested_at']
    
    def __str__(self):
        return f"Caregiver request: {self.caregiver.email} → {self.patient.email}"
    
    def approve(self):
        """Approve caregiver request."""
        self.status = 'APPROVED'
        self.responded_at = timezone.now()
        self.save()
        
        PatientAuthorizedCaregiver.objects.get_or_create(
            patient=self.patient.patient_profile,
            caregiver=self.caregiver,
            defaults={
                'access_level': 'VIEW_ONLY',
                'authorized_by': self.patient
            }
        )
        
        # Update caregiver profile with patient email
        caregiver_profile = self.caregiver.caregiver_profile
        caregiver_profile.patient_email = self.patient.email
        caregiver_profile.save()
    
    def deny(self, reason=''):
        """Deny caregiver request."""
        self.status = 'DENIED'
        self.responded_at = timezone.now()
        self.response_notes = reason
        self.save()


class EmergencyAccess(models.Model):
    """Emergency PHI access following HIPAA break-glass procedures."""
    REASON_CHOICES = [
        ('LIFE_THREATENING', 'Life-Threatening Emergency'),
        ('URGENT_CARE', 'Urgent Care Required'),
        ('PATIENT_UNABLE', 'Patient Unable to Provide Consent'),
        ('IMMINENT_DANGER', 'Imminent Danger to Patient'),
        ('OTHER', 'Other Emergency'),
    ]
    
    # Request information
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='emergency_accesses')
    patient_identifier = EncryptedCharField(max_length=255)
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    detailed_reason = models.TextField()
    
    # Access tracking
    requested_at = models.DateTimeField(auto_now_add=True)
    accessed_at = models.DateTimeField(auto_now=True)
    access_ended_at = models.DateTimeField(null=True, blank=True)
    phi_accessed = models.TextField(blank=True)
    
    # Technical tracking
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Review tracking
    reviewed = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_emergencies')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)
    access_justified = models.BooleanField(null=True)
    
    # Notification tracking
    notifications_sent = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-requested_at']
        verbose_name = 'Emergency Access'
        verbose_name_plural = 'Emergency Accesses'
    
    def __str__(self):
        return f"Emergency access by {self.requester.username} at {self.requested_at}"
    
    def end_access(self, phi_accessed_summary=''):
        """End emergency access session."""
        self.access_ended_at = timezone.now()
        self.phi_accessed = phi_accessed_summary
        self.save()
    
    def review(self, reviewer, notes, justified):
        """Record compliance review."""
        self.reviewed = True
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.review_notes = notes
        self.access_justified = justified
        self.save()
    
    @property
    def duration(self):
        """Calculate access duration."""
        if self.access_ended_at:
            return self.access_ended_at - self.requested_at
        return timezone.now() - self.requested_at
    
    @property
    def is_active(self):
        """Check if access is still active."""
        return self.access_ended_at is None


class ConsentRecord(models.Model):
    """E-signature consent records for HIPAA compliance."""
    CONSENT_TYPES = [
        ('TERMS_OF_SERVICE', 'Terms of Service'),
        ('PRIVACY_NOTICE', 'HIPAA Privacy Notice'),
        ('MEDICATION_MONITORING', 'Medication Adherence Monitoring'),
        ('VITALS_MONITORING', 'Vitals Monitoring'),
        ('RESEARCH_PARTICIPATION', 'Research Participation'),
        ('DATA_SHARING', 'Data Sharing'),
        ('CAREGIVER_ACCESS', 'Caregiver Access Authorization'),
        ('PHI_HANDLING', 'PHI Handling Agreement'),
        ('IDENTITY_VERIFICATION', 'Identity Verification'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='consent_records')
    consent_type = models.CharField(max_length=30, choices=CONSENT_TYPES)
    consented = models.BooleanField()
    
    # E-signature details
    signature_timestamp = models.DateTimeField(auto_now_add=True)
    signature_ip = models.GenericIPAddressField(null=True, blank=True)
    signature_user_agent = models.TextField(blank=True)
    
    # Document version tracking
    document_version = models.CharField(max_length=20, blank=True)
    document_checksum = models.CharField(max_length=64, blank=True)  # SHA-256 hash
    
    # Additional metadata
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-signature_timestamp']
        verbose_name = 'Consent Record'
        verbose_name_plural = 'Consent Records'
    
    def __str__(self):
        return f"{self.user.email} - {self.get_consent_type_display()} - {self.signature_timestamp}"
    
    def revoke(self, reason=''):
        """Revoke consent."""
        self.revoked = True
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.save()


class HIPAADocument(models.Model):
    """HIPAA compliance documents for e-signature."""
    DOCUMENT_TYPES = [
        ('PRIVACY_NOTICE', 'Notice of Privacy Practices'),
        ('TERMS_OF_SERVICE', 'Terms of Service'),
        ('PATIENT_RIGHTS', 'Patient Rights'),
        ('DATA_USE', 'Data Use Agreement'),
        ('CAREGIVER_AGREEMENT', 'Caregiver Authorization Agreement'),
        ('RESEARCH_CONSENT', 'Research Participation Consent'),
    ]
    
    title = models.CharField(max_length=255)
    document_type = models.CharField(max_length=30, choices=DOCUMENT_TYPES)
    version = models.CharField(max_length=20)
    content = models.TextField()  # Markdown or HTML content
    
    # Document metadata
    effective_date = models.DateField()
    expiration_date = models.DateField(null=True, blank=True)
    active = models.BooleanField(default=True)
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_documents')
    checksum = models.CharField(max_length=64)  # SHA-256 hash for integrity
    
    class Meta:
        unique_together = ('document_type', 'version')
        ordering = ['-effective_date', 'document_type']
    
    def __str__(self):
        return f"{self.title} v{self.version}"
    
    def generate_checksum(self):
        """Generate SHA-256 checksum of document content."""
        import hashlib
        return hashlib.sha256(self.content.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        # Generate checksum before saving
        self.checksum = self.generate_checksum()
        super().save(*args, **kwargs)


class PatientAuthorizedCaregiver(models.Model):
    """Many-to-many relationship for patient-caregiver authorization."""
    patient = models.ForeignKey(PatientProfile, on_delete=models.CASCADE, related_name='caregiver_authorizations')
    caregiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='patient_authorizations')
    authorized_at = models.DateTimeField(auto_now_add=True)
    access_level = models.CharField(max_length=20, choices=CaregiverProfile.ACCESS_LEVELS)
    
    # Authorization tracking
    authorized_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='caregiver_authorizations_granted')
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ('patient', 'caregiver')
    
    def __str__(self):
        return f"{self.patient.user.email} → {self.caregiver.email}"


class UserSession(models.Model):
    """
    Distributed session storage for maintaining user context across authentication events.
    Eliminates race conditions by providing authoritative session state.
    """
    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='active_sessions')
    pharmaceutical_tenant = models.ForeignKey(PharmaceuticalTenant, on_delete=models.CASCADE, null=True, blank=True)
    
    # Session metadata
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    
    # Client information for audit trails
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_fingerprint = models.CharField(max_length=255, null=True, blank=True)
    
    # Healthcare-specific session context (encrypted)
    patient_context = models.TextField(null=True, blank=True, help_text="Encrypted patient workflow context")
    clinical_context = models.TextField(null=True, blank=True, help_text="Encrypted clinical workflow state")
    research_context = models.TextField(null=True, blank=True, help_text="Encrypted research session context")
    
    # Emergency access tracking
    is_emergency_session = models.BooleanField(default=False)
    emergency_reason = models.CharField(max_length=100, null=True, blank=True)
    emergency_approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='approved_emergency_sessions'
    )
    
    class Meta:
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['pharmaceutical_tenant', 'is_active']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Default session timeout of 20 minutes for HIPAA compliance
            self.expires_at = timezone.now() + timedelta(minutes=20)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def extend_session(self, minutes=20):
        """Extend session timeout - called on user activity"""
        self.expires_at = timezone.now() + timedelta(minutes=minutes)
        self.last_activity = timezone.now()
        self.save(update_fields=['expires_at', 'last_activity'])
    
    def encrypt_context(self, context_data, context_type):
        """Encrypt sensitive session context data"""
        if not context_data:
            return None
        
        # Use Django's SECRET_KEY for encryption (in production, use dedicated key)
        cipher_suite = Fernet(settings.SESSION_ENCRYPTION_KEY if hasattr(settings, 'SESSION_ENCRYPTION_KEY') else Fernet.generate_key())
        encrypted_data = cipher_suite.encrypt(json.dumps(context_data).encode())
        return encrypted_data.decode()
    
    def decrypt_context(self, encrypted_context):
        """Decrypt sensitive session context data"""
        if not encrypted_context:
            return None
        
        cipher_suite = Fernet(settings.SESSION_ENCRYPTION_KEY if hasattr(settings, 'SESSION_ENCRYPTION_KEY') else Fernet.generate_key())
        decrypted_data = cipher_suite.decrypt(encrypted_context.encode())
        return json.loads(decrypted_data.decode())


class RefreshToken(models.Model):
    """
    JWT refresh token management with automatic rotation.
    Eliminates race conditions in token refresh operations.
    """
    token_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='refresh_tokens')
    session = models.OneToOneField(UserSession, on_delete=models.CASCADE, related_name='refresh_token')
    
    # Token management
    token_hash = models.CharField(max_length=255, unique=True)  # Hashed token for security
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)
    
    # Token rotation tracking
    previous_token = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    rotation_count = models.IntegerField(default=0)
    
    # Security tracking
    created_ip = models.GenericIPAddressField()
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'refresh_tokens'
        indexes = [
            models.Index(fields=['user', 'is_revoked']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['token_hash']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Refresh tokens expire after 24 hours
            self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def revoke(self):
        """Revoke this refresh token and all its descendants"""
        self.is_revoked = True
        self.save(update_fields=['is_revoked'])


class ResearchConsent(models.Model):
    """
    Enhanced research consent tracking for pharmaceutical research compliance.
    Supports granular consent per research study and pharmaceutical tenant.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='research_consents')
    pharmaceutical_tenant = models.ForeignKey(PharmaceuticalTenant, on_delete=models.CASCADE)
    
    # Consent details
    study_identifier = models.CharField(max_length=100, help_text="Research study or drug trial identifier")
    consent_type = models.CharField(max_length=50, choices=[
        ('GENERAL_RESEARCH', 'General Research Participation'),
        ('DRUG_EFFICACY', 'Drug Efficacy Research'),
        ('FAMILY_HISTORY', 'Family Medical History Research'),
        ('GENETIC_DATA', 'Genetic Data Research'),
        ('LONGITUDINAL_STUDY', 'Longitudinal Health Study'),
        ('ADHERENCE_MONITORING', 'Medication Adherence Monitoring'),
        ('OUTCOMES_RESEARCH', 'Clinical Outcomes Research'),
        ('BIOMARKER_RESEARCH', 'Biomarker Research'),
    ])
    
    # Consent status
    consented = models.BooleanField(default=False)
    consent_date = models.DateTimeField(null=True, blank=True)
    consent_version = models.CharField(max_length=20, default='1.0')
    
    # Withdrawal tracking
    withdrawn = models.BooleanField(default=False)
    withdrawal_date = models.DateTimeField(null=True, blank=True)
    withdrawal_reason = models.TextField(null=True, blank=True)
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    consent_document_url = models.URLField(null=True, blank=True, help_text="Link to signed consent document")
    
    # Family consent inheritance (for family medical history research)
    inherited_from_family_member = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        help_text="If consent inherited from family member"
    )
    
    class Meta:
        db_table = 'research_consents'
        unique_together = ['user', 'pharmaceutical_tenant', 'study_identifier', 'consent_type']
        indexes = [
            models.Index(fields=['pharmaceutical_tenant', 'study_identifier']),
            models.Index(fields=['user', 'consented']),
            models.Index(fields=['consent_date']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.consent_type} - {self.pharmaceutical_tenant.name}"


class AuditTrail(models.Model):
    """
    Comprehensive audit logging for pharmaceutical research compliance.
    Tracks all user actions involving PHI and research data.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Who and when
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    session = models.ForeignKey(UserSession, on_delete=models.SET_NULL, null=True, blank=True)
    pharmaceutical_tenant = models.ForeignKey(PharmaceuticalTenant, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # What happened
    action_type = models.CharField(max_length=50, choices=[
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
        ('TOKEN_REFRESH', 'Token Refresh'),
        ('PATIENT_ACCESS', 'Patient Data Access'),
        ('EHR_ACCESS', 'EHR Data Access'),
        ('RESEARCH_DATA_ACCESS', 'Research Data Access'),
        ('CONSENT_GRANTED', 'Research Consent Granted'),
        ('CONSENT_WITHDRAWN', 'Research Consent Withdrawn'),
        ('EMERGENCY_ACCESS', 'Emergency Access Used'),
        ('CROSS_TENANT_ACCESS', 'Cross-Tenant Data Access'),
        ('DATA_EXPORT', 'Data Export'),
        ('PERMISSION_CHANGE', 'Permission Modified'),
        ('SECURITY_EVENT', 'Security Event'),
    ])
    resource_type = models.CharField(max_length=50, null=True, blank=True)
    resource_id = models.CharField(max_length=255, null=True, blank=True)
    action_description = models.TextField()
    
    # Context and metadata
    request_data = models.JSONField(null=True, blank=True, help_text="Sanitized request data")
    response_status = models.CharField(max_length=10, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Research-specific tracking
    study_identifier = models.CharField(max_length=100, null=True, blank=True)
    patient_identifier = models.CharField(max_length=255, null=True, blank=True)  # Encrypted/hashed
    research_purpose = models.CharField(max_length=255, null=True, blank=True)
    
    # Risk and compliance
    risk_level = models.CharField(max_length=20, default='LOW', choices=[
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Risk'),
    ])
    compliance_flags = models.JSONField(default=list, help_text="Compliance violations or notes")
    
    class Meta:
        db_table = 'audit_trails'
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['pharmaceutical_tenant', 'timestamp']),
            models.Index(fields=['action_type', 'timestamp']),
            models.Index(fields=['study_identifier']),
            models.Index(fields=['risk_level']),
        ]
    
    def __str__(self):
        return f"{self.action_type} by {self.user} at {self.timestamp}"

