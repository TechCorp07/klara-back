# serializers.py
from django.utils import timezone
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db import transaction

from .models import (
    AuditTrail, PatientProfile, PharmaceuticalTenant, ProviderProfile, PharmcoProfile,
    CaregiverProfile, ResearchConsent, ResearcherProfile, ComplianceProfile,
    CaregiverRequest, EmergencyAccess, ConsentRecord, HIPAADocument, UserSession
)

User = get_user_model()



class PharmaceuticalTenantSerializer(serializers.ModelSerializer):
    """
    Serializer for pharmaceutical tenant information.
    Used in user context and tenant switching operations.
    """
    class Meta:
        model = PharmaceuticalTenant
        fields = [
            'id', 'name', 'slug', 'primary_therapeutic_areas', 
            'is_active', 'features_enabled', 'compliance_status'
        ]
        read_only_fields = ['id', 'slug', 'compliance_status']


class UserSerializer(serializers.ModelSerializer):
    """Base user serializer."""
    role_display = serializers.CharField(source='get_role_display', read_only=True)
        # Pharmaceutical tenant context
    primary_pharmaceutical_tenant = PharmaceuticalTenantSerializer(read_only=True)
    pharmaceutical_tenants = PharmaceuticalTenantSerializer(many=True, read_only=True)
    
    # JWT and session context
    jwt_secret_version = serializers.IntegerField(read_only=True)
    last_token_refresh = serializers.DateTimeField(read_only=True)
    
    # Enhanced security fields
    password_last_changed = serializers.DateTimeField(read_only=True)
    failed_login_attempts = serializers.IntegerField(read_only=True)
    account_locked_until = serializers.DateTimeField(read_only=True)
    
    # Research participation
    research_participant_id = serializers.CharField(read_only=True)
    research_enrollment_date = serializers.DateTimeField(read_only=True)
    
    # Active sessions count
    active_sessions_count = serializers.SerializerMethodField()
    
    def get_active_sessions_count(self, obj):
        return obj.active_sessions.filter(
            is_active=True,
            expires_at__gt=timezone.now()
        ).count()

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone_number', 'date_of_birth', 'role', 'role_display',
            'two_factor_enabled', 'date_joined', 'is_approved',
            'approved_at', 'email_verified', 'terms_accepted',
            'hipaa_privacy_acknowledged', 'primary_pharmaceutical_tenant',
            'pharmaceutical_tenants', 'jwt_secret_version', 'last_token_refresh',
            'password_last_changed', 'failed_login_attempts', 'account_locked_until',
            'research_participant_id', 'research_enrollment_date',
            'active_sessions_count',
        )
        read_only_fields = (
            'id', 'username', 'date_joined', 'role_display',
            'two_factor_enabled', 'is_approved', 'approved_at',
            'email_verified'
        )
    
    def validate_email(self, value):
        """Ensure email is unique."""
        if self.instance:
            if User.objects.exclude(pk=self.instance.pk).filter(email=value).exists():
                raise serializers.ValidationError("This email is already registered.")
        else:
            if User.objects.filter(email=value).exists():
                raise serializers.ValidationError("This email is already registered.")
        return value


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration with role-specific fields."""
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    
    # Common consent fields
    terms_accepted = serializers.BooleanField(required=True)
    hipaa_privacy_acknowledged = serializers.BooleanField(required=True)
    
    # Role-specific fields
    # Caregiver fields
    relationship_to_patient = serializers.ChoiceField(
        choices=CaregiverProfile.RELATIONSHIP_CHOICES,
        required=False
    )
    caregiver_type = serializers.ChoiceField(
        choices=CaregiverProfile.CAREGIVER_TYPES,
        required=False
    )
    patient_email = serializers.EmailField(required=False)
    caregiver_authorization_acknowledged = serializers.BooleanField(required=False)
    
    # Provider fields
    medical_license_number = serializers.CharField(required=False)
    npi_number = serializers.RegexField(
        regex=r'^\d{10}$',
        required=False,
        error_messages={'invalid': "NPI number must be exactly 10 digits"}
    )
    specialty = serializers.ChoiceField(
        choices=ProviderProfile.SPECIALTY_CHOICES,
        required=False
    )
    practice_name = serializers.CharField(required=False)
    practice_address = serializers.CharField(required=False)
    accepting_new_patients = serializers.BooleanField(required=False, default=True)
    
    # Pharmaceutical company fields
    company_name = serializers.CharField(required=False)
    role_at_company = serializers.ChoiceField(
        choices=PharmcoProfile.ROLE_CHOICES,
        required=False
    )
    regulatory_id = serializers.CharField(required=False)
    primary_research_focus = serializers.ChoiceField(
        choices=PharmcoProfile.RESEARCH_FOCUS_CHOICES,
        required=False
    )
    phi_handling_acknowledged = serializers.BooleanField(required=False)
    
    # Researcher fields
    institution = serializers.CharField(required=False)
    primary_research_area = serializers.ChoiceField(
        choices=ResearcherProfile.RESEARCH_AREAS,
        required=False
    )
    qualifications_background = serializers.CharField(required=False)
    irb_approval_confirmed = serializers.BooleanField(required=False)
    
    # Compliance officer fields
    organization = serializers.CharField(required=False)
    job_title = serializers.CharField(required=False)
    compliance_certification = serializers.ChoiceField(
        choices=ComplianceProfile.CERTIFICATION_TYPES,
        required=False
    )
    primary_specialization = serializers.ChoiceField(
        choices=ComplianceProfile.COMPLIANCE_ROLES,
        required=False
    )
    regulatory_experience = serializers.CharField(required=False)
    
    class Meta:
        model = User
        fields = (
            'email', 'password', 'confirm_password', 'first_name', 
            'last_name', 'phone_number', 'date_of_birth', 'role',
            'terms_accepted', 'hipaa_privacy_acknowledged',
            # Caregiver fields
            'relationship_to_patient', 'caregiver_type', 'patient_email',
            'caregiver_authorization_acknowledged',
            # Provider fields
            'medical_license_number', 'npi_number', 'specialty',
            'practice_name', 'practice_address', 'accepting_new_patients',
            # Pharmco fields
            'company_name', 'role_at_company', 'regulatory_id',
            'primary_research_focus', 'phi_handling_acknowledged',
            # Researcher fields
            'institution', 'primary_research_area', 'qualifications_background',
            'irb_approval_confirmed',
            # Compliance fields
            'organization', 'job_title', 'compliance_certification',
            'primary_specialization', 'regulatory_experience'
        )
    
    def validate_email(self, value):
        """Validate email uniqueness and format."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already registered.")
        return value
    
    def validate_npi_number(self, value):
        """Validate NPI number format and uniqueness."""
        if value and ProviderProfile.objects.filter(npi_number=value).exists():
            raise serializers.ValidationError("This NPI number is already registered.")
        return value
    
    def validate_medical_license_number(self, value):
        """Validate medical license uniqueness."""
        if value and ProviderProfile.objects.filter(medical_license_number=value).exists():
            raise serializers.ValidationError("This medical license number is already registered.")
        return value
    
    def validate_patient_email(self, value):
        """Validate patient email exists for caregiver registration."""
        if value:
            try:
                patient = User.objects.get(email=value, role='patient')
                if not patient.is_approved:
                    raise serializers.ValidationError("The patient account must be approved first.")
            except User.DoesNotExist:
                raise serializers.ValidationError("No patient found with this email address.")
        return value
    
    def validate(self, data):
        """Validate passwords match and role-specific requirements."""
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords don't match."})
        
        role = data.get('role')
        
        # Validate role-specific required fields
        if role == 'patient':
            required_consents = ['terms_accepted', 'hipaa_privacy_acknowledged']
            for consent in required_consents:
                if not data.get(consent):
                    raise serializers.ValidationError({
                        consent: f"This field is required for patients."
                    })
        
        elif role == 'caregiver':
            required_fields = ['relationship_to_patient', 'caregiver_type', 
                             'patient_email', 'caregiver_authorization_acknowledged']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({
                        field: f"This field is required for caregivers."
                    })
            
            required_consents = ['terms_accepted', 'hipaa_privacy_acknowledged', 
                               'caregiver_authorization_acknowledged']
            for consent in required_consents:
                if not data.get(consent):
                    raise serializers.ValidationError({
                        consent: f"This field is required for caregivers."
                    })
        
        elif role == 'provider':
            required_fields = ['medical_license_number', 'npi_number', 
                             'specialty', 'practice_name', 'practice_address']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({
                        field: f"This field is required for healthcare providers."
                    })
        
        elif role == 'pharmco':
            required_fields = ['company_name', 'role_at_company', 
                             'regulatory_id', 'primary_research_focus',
                             'phi_handling_acknowledged']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({
                        field: f"This field is required for pharmaceutical companies."
                    })
        
        elif role == 'researcher':
            required_fields = ['institution', 'primary_research_area',
                             'qualifications_background', 'irb_approval_confirmed']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({
                        field: f"This field is required for researchers."
                    })
            
            if not data.get('phi_handling_acknowledged'):
                raise serializers.ValidationError({
                    'phi_handling_acknowledged': "PHI handling agreement is required for researchers."
                })
        
        elif role == 'compliance':
            required_fields = ['organization', 'job_title', 
                             'compliance_certification', 'primary_specialization',
                             'regulatory_experience']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({
                        field: f"This field is required for compliance officers."
                    })
        
        return data
    
    @transaction.atomic
    def create(self, validated_data):
        """Create user and store profile data for later creation upon approval."""
        
        # Extract profile fields based on the user's role
        profile_fields = {}
        role = validated_data['role']
        
        # Remove confirm_password first
        validated_data.pop('confirm_password', None)
        
        # Provider-specific fields
        provider_fields = [
            'medical_license_number', 'npi_number', 'specialty',
            'practice_name', 'practice_address', 'accepting_new_patients'
        ]
        for field in provider_fields:
            validated_data.pop(field, None)
        
        # Pharmaceutical company fields  
        pharmco_fields = [
            'company_name', 'role_at_company', 'regulatory_id',
            'primary_research_focus', 'phi_handling_acknowledged'
        ]
        for field in pharmco_fields:
            validated_data.pop(field, None)
        
        # Caregiver fields
        caregiver_fields = [
            'relationship_to_patient', 'caregiver_type', 'patient_email',
            'caregiver_authorization_acknowledged'
        ]
        for field in caregiver_fields:
            validated_data.pop(field, None)
        
        # Researcher fields
        researcher_fields = [
            'institution', 'primary_research_area', 'qualifications_background',
            'irb_approval_confirmed'
        ]
        for field in researcher_fields:
            validated_data.pop(field, None)
        
        # Compliance fields
        compliance_fields = [
            'organization', 'job_title', 'compliance_certification',
            'primary_specialization', 'regulatory_experience'
        ]
        for field in compliance_fields:
            validated_data.pop(field, None)
        
        # Now extract the specific fields we need for THIS user's role
        if role == 'caregiver':
            # Re-extract caregiver fields for profile creation
            profile_fields = {
                'relationship_to_patient': validated_data.get('relationship_to_patient', ''),
                'caregiver_type': validated_data.get('caregiver_type', ''),
                'patient_email': validated_data.get('patient_email', ''),
            }
            
        elif role == 'provider':
            # Re-extract provider fields for profile creation
            profile_fields = {
                'medical_license_number': validated_data.get('medical_license_number', ''),
                'npi_number': validated_data.get('npi_number', ''),
                'specialty': validated_data.get('specialty', ''),
                'practice_name': validated_data.get('practice_name', ''),
                'practice_address': validated_data.get('practice_address', ''),
                'accepting_new_patients': validated_data.get('accepting_new_patients', True),
            }
            
        elif role == 'pharmco':
            # Re-extract pharmco fields for profile creation
            profile_fields = {
                'company_name': validated_data.get('company_name', ''),
                'role_at_company': validated_data.get('role_at_company', ''),
                'regulatory_id': validated_data.get('regulatory_id', ''),
                'primary_research_focus': validated_data.get('primary_research_focus', ''),
            }
            validated_data['phi_handling_acknowledged'] = validated_data.get(
                'phi_handling_acknowledged', False
            )
            
        elif role == 'researcher':
            # Re-extract researcher fields for profile creation
            profile_fields = {
                'institution': validated_data.get('institution', ''),
                'primary_research_area': validated_data.get('primary_research_area', ''),
                'qualifications_background': validated_data.get('qualifications_background', ''),
                'irb_approval_confirmed': validated_data.get('irb_approval_confirmed', False),
            }
            validated_data['phi_handling_acknowledged'] = validated_data.get(
                'phi_handling_acknowledged', False
            )
            
        elif role == 'compliance':
            # Re-extract compliance fields for profile creation
            profile_fields = {
                'organization': validated_data.get('organization', ''),
                'job_title': validated_data.get('job_title', ''),
                'compliance_certification': validated_data.get('compliance_certification', ''),
                'primary_specialization': validated_data.get('primary_specialization', ''),
                'regulatory_experience': validated_data.get('regulatory_experience', ''),
            }
        
        # Create user with only User model fields
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.password_last_changed = timezone.now()
        user.save()
        
        # Store profile fields temporarily for creation upon approval
        if profile_fields:
            # Store the profile data for later use during approval
            from .utils import RegistrationDataManager
            RegistrationDataManager.store_registration_data(user, profile_fields)
        
        # Create caregiver request if applicable
        if role == 'caregiver' and profile_fields.get('patient_email'):
            try:
                patient = User.objects.get(
                    email=profile_fields['patient_email'], 
                    role='patient',
                    is_approved=True
                )
                CaregiverRequest.objects.create(
                    caregiver=user,
                    patient=patient,
                    relationship=profile_fields.get('relationship_to_patient', '')
                )
            except User.DoesNotExist:
                pass  # Patient not found or not approved yet
        
        return user

class LoginSerializer(serializers.Serializer):
    """Login serializer."""
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})


class TwoFactorAuthSerializer(serializers.Serializer):
    """2FA verification serializer."""
    user_id = serializers.IntegerField()
    token = serializers.CharField(max_length=6)


class TwoFactorSetupSerializer(serializers.Serializer):
    """2FA setup serializer."""
    token = serializers.CharField(max_length=6)


class TwoFactorDisableSerializer(serializers.Serializer):
    """2FA disable serializer."""
    password = serializers.CharField(style={'input_type': 'password'})


class PasswordResetRequestSerializer(serializers.Serializer):
    """Password reset request serializer."""
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Password reset confirmation serializer."""
    token = serializers.UUIDField()
    password = serializers.CharField(style={'input_type': 'password'})
    password_confirm = serializers.CharField(style={'input_type': 'password'})
    
    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords don't match."})
        validate_password(data['password'])
        return data


class EmailVerificationRequestSerializer(serializers.Serializer):
    """Email verification request serializer."""
    email = serializers.EmailField(required=False)


class EmailVerificationConfirmSerializer(serializers.Serializer):
    """Email verification confirmation serializer."""
    token = serializers.UUIDField()
    email = serializers.EmailField(required=False)


class PatientProfileSerializer(serializers.ModelSerializer):
    """Patient profile serializer."""
    user = UserSerializer(read_only=True)
    days_until_verification_required = serializers.SerializerMethodField()
    
    class Meta:
        model = PatientProfile
        fields = '__all__'
        read_only_fields = ('user', 'identity_verification_date', 'first_login_date')
    
    def get_days_until_verification_required(self, obj):
        return obj.days_until_verification_required()


class ProviderProfileSerializer(serializers.ModelSerializer):
    """Provider profile serializer."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = ProviderProfile
        fields = '__all__'
        read_only_fields = ('user',)


class PharmcoProfileSerializer(serializers.ModelSerializer):
    """Pharmaceutical company profile serializer."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = PharmcoProfile
        fields = '__all__'
        read_only_fields = ('user',)


class CaregiverProfileSerializer(serializers.ModelSerializer):
    """Caregiver profile serializer."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = CaregiverProfile
        fields = '__all__'
        read_only_fields = ('user',)


class ResearcherProfileSerializer(serializers.ModelSerializer):
    """Researcher profile serializer."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = ResearcherProfile
        fields = '__all__'
        read_only_fields = ('user', 'is_verified', 'verified_at', 'verified_by')


class ComplianceProfileSerializer(serializers.ModelSerializer):
    """Compliance officer profile serializer."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = ComplianceProfile
        fields = '__all__'
        read_only_fields = ('user', 'added_date')


class CaregiverRequestSerializer(serializers.ModelSerializer):
    """Caregiver request serializer."""
    caregiver = UserSerializer(read_only=True)
    patient = UserSerializer(read_only=True)
    
    class Meta:
        model = CaregiverRequest
        fields = '__all__'
        read_only_fields = (
            'caregiver', 'patient', 'requested_at', 
            'responded_at', 'patient_notified', 'reminder_sent'
        )


class EmergencyAccessSerializer(serializers.ModelSerializer):
    """Emergency access serializer."""
    requester = UserSerializer(read_only=True)
    duration = serializers.SerializerMethodField()
    is_active = serializers.BooleanField(read_only=True)
    reason = serializers.CharField(required=True, max_length=500)
    patient_id = serializers.CharField(required=False, max_length=100)
    urgency_level = serializers.ChoiceField(
        choices=[
            ('LIFE_THREATENING', 'Life Threatening'),
            ('URGENT_CARE', 'Urgent Care'),
            ('PATIENT_UNABLE', 'Patient Unable to Consent'),
            ('IMMINENT_DANGER', 'Imminent Danger'),
            ('OTHER', 'Other Emergency'),
        ],
        required=False,
        default='OTHER'
    )
    
    class Meta:
        model = EmergencyAccess
        fields = '__all__'
        read_only_fields = (
            'requester', 'requested_at', 'accessed_at', 'ip_address',
            'user_agent', 'reviewed', 'reviewed_by', 'reviewed_at',
            'access_justified', 'notifications_sent'
        )
    
    def get_duration(self, obj):
        if obj.duration:
            return str(obj.duration)
        return None


class ConsentRecordSerializer(serializers.ModelSerializer):
    """Consent record serializer."""
    user = UserSerializer(read_only=True)
    consent_type_display = serializers.CharField(
        source='get_consent_type_display', 
        read_only=True
    )
    
    class Meta:
        model = ConsentRecord
        fields = '__all__'
        read_only_fields = (
            'user', 'signature_timestamp', 'signature_ip',
            'signature_user_agent', 'document_checksum'
        )


class HIPAADocumentSerializer(serializers.ModelSerializer):
    """HIPAA document serializer."""
    document_type_display = serializers.CharField(
        source='get_document_type_display',
        read_only=True
    )
    is_signed_by_user = serializers.SerializerMethodField()
    
    class Meta:
        model = HIPAADocument
        fields = '__all__'
        read_only_fields = ('created_at', 'created_by', 'checksum')
    
    def get_is_signed_by_user(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        
        return ConsentRecord.objects.filter(
            user=request.user,
            consent_type=f'DOC_{obj.document_type}',
            document_version=obj.version,
            revoked=False
        ).exists()


class ProfileCompletionSerializer(serializers.Serializer):
    """Serializer for completing user profiles after approval."""
    
    # Common fields
    additional_info = serializers.CharField(required=False, allow_blank=True)
    
    # Patient-specific fields
    medical_id = serializers.CharField(required=False, allow_blank=True)
    blood_type = serializers.CharField(required=False, allow_blank=True)
    allergies = serializers.CharField(required=False, allow_blank=True)
    emergency_contact_name = serializers.CharField(required=False, allow_blank=True)
    emergency_contact_phone = serializers.CharField(required=False, allow_blank=True)
    emergency_contact_relationship = serializers.CharField(required=False, allow_blank=True)
    primary_condition = serializers.CharField(required=False, allow_blank=True)
    condition_diagnosis_date = serializers.DateField(required=False)
    
    def validate(self, data):
        """Validate profile completion data based on user role."""
        user = self.context['request'].user
        
        if user.role == 'patient':
            # Validate patient-specific requirements
            pass
        
        return data


class AdminCreationSerializer(serializers.ModelSerializer):
    """Serializer for creating admin users."""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'phone_number', 'password')
    
    def validate_email(self, value):
        """Ensure email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value


class JWTLoginResponseSerializer(serializers.Serializer):
    """
    Serializer for JWT login response.
    Provides comprehensive authentication response structure.
    """
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    token_type = serializers.CharField(default='Bearer')
    expires_in = serializers.IntegerField()
    user = UserSerializer()
    session = serializers.DictField()
    permissions = serializers.DictField()
    verification_warning = serializers.DictField(required=False)


class TenantSwitchSerializer(serializers.Serializer):
    """
    Serializer for pharmaceutical tenant switching.
    """
    tenant_id = serializers.UUIDField(required=True)


class ResearchConsentSerializer(serializers.ModelSerializer):
    """
    Enhanced serializer for research consent tracking.
    Supports pharmaceutical research compliance requirements.
    """
    user_email = serializers.CharField(source='user.email', read_only=True)
    pharmaceutical_tenant_name = serializers.CharField(
        source='pharmaceutical_tenant.name', 
        read_only=True
    )
    consent_type_display = serializers.CharField(
        source='get_consent_type_display', 
        read_only=True
    )
    is_active = serializers.SerializerMethodField()
    
    class Meta:
        model = ResearchConsent
        fields = [
            'id', 'user_email', 'pharmaceutical_tenant_name', 
            'study_identifier', 'consent_type', 'consent_type_display',
            'consented', 'consent_date', 'consent_version',
            'withdrawn', 'withdrawal_date', 'withdrawal_reason',
            'created_at', 'last_modified', 'consent_document_url',
            'is_active'
        ]
        read_only_fields = [
            'id', 'user_email', 'pharmaceutical_tenant_name', 
            'consent_type_display', 'created_at', 'last_modified', 'is_active'
        ]
    
    def get_is_active(self, obj):
        return obj.consented and not obj.withdrawn


class AuditTrailSerializer(serializers.ModelSerializer):
    """
    Serializer for audit trail records.
    Used in compliance reporting and security monitoring.
    """
    user_email = serializers.CharField(source='user.email', read_only=True)
    pharmaceutical_tenant_name = serializers.CharField(
        source='pharmaceutical_tenant.name', 
        read_only=True
    )
    action_type_display = serializers.CharField(
        source='get_action_type_display', 
        read_only=True
    )
    risk_level_display = serializers.CharField(
        source='get_risk_level_display', 
        read_only=True
    )
    
    class Meta:
        model = AuditTrail
        fields = [
            'id', 'user_email', 'pharmaceutical_tenant_name',
            'timestamp', 'action_type', 'action_type_display',
            'resource_type', 'resource_id', 'action_description',
            'response_status', 'ip_address', 'study_identifier',
            'patient_identifier', 'research_purpose', 'risk_level',
            'risk_level_display', 'compliance_flags'
        ]
        read_only_fields = ['id', 'timestamp']


class SessionContextSerializer(serializers.ModelSerializer):
    """
    Serializer for user session context.
    Handles session state for workflow preservation.
    """
    user_email = serializers.CharField(source='user.email', read_only=True)
    pharmaceutical_tenant_name = serializers.CharField(
        source='pharmaceutical_tenant.name', 
        read_only=True
    )
    emergency_approved_by_email = serializers.CharField(
        source='emergency_approved_by.email', 
        read_only=True
    )
    is_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'session_id', 'user_email', 'pharmaceutical_tenant_name',
            'created_at', 'last_activity', 'expires_at', 'is_active',
            'is_emergency_session', 'emergency_reason', 
            'emergency_approved_by_email', 'device_fingerprint', 'is_expired'
        ]
        read_only_fields = ['session_id', 'created_at']
    
    def get_is_expired(self, obj):
        return obj.is_expired()


class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer for token refresh requests.
    """
    refresh_token = serializers.CharField(required=True)


class SessionHealthSerializer(serializers.Serializer):
    """
    Serializer for session health check responses.
    """
    session = SessionContextSerializer()
    user = UserSerializer()
    permissions = serializers.DictField()


class UserSessionListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing user sessions (for account management).
    """
    pharmaceutical_tenant_name = serializers.CharField(
        source='pharmaceutical_tenant.name', 
        read_only=True
    )
    is_current_session = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    device_info = serializers.SerializerMethodField()
    location_info = serializers.SerializerMethodField()
    time_remaining = serializers.SerializerMethodField()
    session_duration = serializers.SerializerMethodField()
    
    # Masked/secure fields
    session_id_short = serializers.SerializerMethodField()
    ip_address_masked = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'session_id',
            'session_id_short',
            'created_at',
            'last_activity', 
            'expires_at',
            'is_active',
            'is_expired',
            'is_current_session',
            'is_emergency_session',
            'emergency_reason',
            'ip_address_masked',
            'device_info',
            'location_info',
            'time_remaining',
            'session_duration',
            'pharmaceutical_tenant_name'
        ]
        read_only_fields = ['__all__']
    
    def get_is_current_session(self, obj):
        """Check if this is the current session."""
        current_session_id = self.context.get('current_session_id')
        return str(obj.session_id) == str(current_session_id) if current_session_id else False
    
    def get_is_expired(self, obj):
        """Check if session is expired."""
        return obj.is_expired()
    
    def get_session_id_short(self, obj):
        """Return shortened session ID for security (show only first/last chars)."""
        session_str = str(obj.session_id)
        if len(session_str) > 8:
            return f"{session_str[:4]}...{session_str[-4:]}"
        return session_str
    
    def get_ip_address_masked(self, obj):
        """Mask IP address for privacy (show only first 3 octets for IPv4)."""
        if not obj.ip_address:
            return None
        
        ip = obj.ip_address
        if '.' in ip:  # IPv4
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        elif ':' in ip:  # IPv6
            parts = ip.split(':')
            if len(parts) >= 4:
                return f"{':'.join(parts[:3])}:***"
        
        return ip
    
    def get_device_info(self, obj):
        """Extract device information from user agent."""
        return self._parse_user_agent(obj.user_agent)
    
    def get_location_info(self, obj):
        """Get location information (placeholder for GeoIP integration)."""
        # In production, integrate with GeoIP service
        return {
            'ip_address': self.get_ip_address_masked(obj),
            'country': None,  # Would get from GeoIP
            'city': None,     # Would get from GeoIP
            'timezone': None  # Would get from GeoIP
        }
    
    def get_time_remaining(self, obj):
        """Calculate time remaining until session expires."""
        if obj.is_expired():
            return None
        
        remaining = obj.expires_at - timezone.now()
        return {
            'total_seconds': int(remaining.total_seconds()),
            'human_readable': self._format_duration(remaining)
        }
    
    def get_session_duration(self, obj):
        """Calculate how long the session has been active."""
        duration = obj.last_activity - obj.created_at
        return {
            'total_seconds': int(duration.total_seconds()),
            'human_readable': self._format_duration(duration)
        }
    
    def get_pharmaceutical_tenant_name(self, obj):
        """Get tenant name safely."""
        return obj.pharmaceutical_tenant.name if obj.pharmaceutical_tenant else None
    
    def _parse_user_agent(self, user_agent):
        """Parse user agent string to extract device/browser info."""
        if not user_agent:
            return {'browser': 'Unknown', 'device': 'Unknown', 'os': 'Unknown'}
        
        # Simple user agent parsing (in production, use a library like user-agents)
        browser = 'Unknown Browser'
        device_type = 'Desktop'
        os = 'Unknown OS'
        
        ua = user_agent.lower()
        
        # Browser detection
        if 'chrome' in ua and 'edge' not in ua:
            browser = 'Chrome'
        elif 'firefox' in ua:
            browser = 'Firefox'
        elif 'safari' in ua and 'chrome' not in ua:
            browser = 'Safari'
        elif 'edge' in ua:
            browser = 'Edge'
        elif 'opera' in ua:
            browser = 'Opera'
        
        # Device type detection
        if any(mobile in ua for mobile in ['mobile', 'android', 'iphone']):
            device_type = 'Mobile'
        elif any(tablet in ua for tablet in ['tablet', 'ipad']):
            device_type = 'Tablet'
        
        # OS detection
        if 'windows' in ua:
            os = 'Windows'
        elif 'mac' in ua:
            os = 'macOS'
        elif 'linux' in ua:
            os = 'Linux'
        elif 'android' in ua:
            os = 'Android'
        elif 'ios' in ua or 'iphone' in ua or 'ipad' in ua:
            os = 'iOS'
        
        return {
            'browser': browser,
            'device': device_type,
            'os': os,
            'full_user_agent': user_agent[:100] + '...' if len(user_agent) > 100 else user_agent
        }
    
    def _format_duration(self, duration):
        """Format timedelta into human readable string."""
        total_seconds = int(duration.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            return f"{minutes}m"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d {hours}h"


class PharmaceuticalTenantDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for pharmaceutical tenant management.
    """
    user_count = serializers.SerializerMethodField()
    active_studies = serializers.SerializerMethodField()
    compliance_status_display = serializers.CharField(
        source='get_compliance_status_display', 
        read_only=True
    )
    
    class Meta:
        model = PharmaceuticalTenant
        fields = [
            'id', 'name', 'slug', 'regulatory_id', 'contact_email',
            'primary_therapeutic_areas', 'is_active', 'features_enabled',
            'branding_config', 'created_at', 'last_audit_date',
            'compliance_status', 'compliance_status_display',
            'user_count', 'active_studies'
        ]
        read_only_fields = ['id', 'slug', 'created_at']
    
    def get_user_count(self, obj):
        return obj.users.filter(is_active=True).count()
    
    def get_active_studies(self, obj):
        return obj.research_consents.values('study_identifier').distinct().count()
