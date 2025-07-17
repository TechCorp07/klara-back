from rest_framework import permissions
from django.conf import settings
from users.models import User

class IsApprovedUser(permissions.BasePermission):
    """
    Allows access only to approved users.
    Admins are always considered approved.
    """
    message = "Your account is pending administrator approval."
    
    def has_permission(self, request, view):
        # Unauthenticated requests are denied
        if not request.user.is_authenticated:
            return False
            
        # Admins and staff are always approved
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # For all other actions, check if the user is approved
        return request.user.is_approved
        
    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class IsPatientOrProvider(permissions.BasePermission):
    """Allows access to patient or healthcare provider roles only."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role in ['patient', 'provider', 'admin'] or 
            request.user.is_staff
        )


class IsProviderOnly(permissions.BasePermission):
    """Allows access to healthcare provider roles only."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role in ['provider', 'admin'] or
            request.user.is_staff
        )


class IsPatientOrProviderForRecord(permissions.BasePermission):
    """
    Allows patients to access only their own medical records.
    Allows providers to access records of their patients.
    """
    def has_object_permission(self, request, view, obj):
        # Admin and staff can access everything
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Patient can access only their own records
        if request.user.role == 'patient':
            return obj.patient == request.user
            
        # Provider can access their patients' records
        if request.user.role == 'provider':
            return (
                obj.primary_physician == request.user or
                obj.patient in request.user.primary_patients.all()
            )
            
        # Caregiver can access their authorized patients' records
        if request.user.role == 'caregiver' and hasattr(request.user, 'caregiver_profile'):
            return obj.patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists()
            
        # Researchers with verified status can access data with research consent
        if request.user.role == 'researcher' and hasattr(request.user, 'researcher_profile'):
            if request.user.researcher_profile.is_verified:
                return obj.patient.research_consent
                
        # Compliance officers with PHI access can view all records
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            return request.user.compliance_profile.can_view_phi
            
        # Pharmaco can access medication adherence data for consented patients
        if request.user.role == 'pharmco':
            # Read-only access for consented data
            if request.method in permissions.SAFE_METHODS:
                return obj.patient.medication_adherence_monitoring_consent
        
        return False


class HasHealthDataConsent(permissions.BasePermission):
    """
    Verify the user has appropriate consent for accessing health data.
    Used for fine-grained access control to different data types.
    """
    def has_object_permission(self, request, view, obj):
        # Admin and staff can access everything
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Get the patient from the object
        if hasattr(obj, 'patient'):
            patient = obj.patient
        elif hasattr(obj, 'medical_record'):
            patient = obj.medical_record.patient
        elif hasattr(obj, 'lab_test') and hasattr(obj.lab_test, 'medical_record'):
            patient = obj.lab_test.medical_record.patient
        elif hasattr(obj, 'condition') and hasattr(obj.condition, 'medical_record'):
            patient = obj.condition.medical_record.patient
        else:
            # Can't determine patient, deny access
            return False
            
        # Patients can always access their own data
        if request.user == patient:
            return True
            
        # Provider access
        if request.user.role == 'provider':
            from .models import HealthDataConsent
            
            # Check if provider has explicit consent
            has_consent = HealthDataConsent.objects.filter(
                patient=patient,
                consent_type='provider_access',
                authorized_entity=request.user,
                consented=True
            ).exists()
            
            # Or check if provider is primary physician
            is_primary = False
            if hasattr(obj, 'medical_record'):
                is_primary = obj.medical_record.primary_physician == request.user
            elif hasattr(obj, 'lab_test') and hasattr(obj.lab_test, 'medical_record'):
                is_primary = obj.lab_test.medical_record.primary_physician == request.user
                
            return has_consent or is_primary
            
        # Caregiver access
        if request.user.role == 'caregiver' and hasattr(request.user, 'caregiver_profile'):
            # Check if caregiver is authorized
            if hasattr(patient, 'patient_profile'):
                is_authorized = patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists()
                
                # Check data type against caregiver access level
                if is_authorized:
                    access_level = request.user.caregiver_profile.access_level
                    
                    # View access is allowed for all levels
                    if request.method in permissions.SAFE_METHODS:
                        return True
                        
                    # Medication management permissions
                    if view.basename.lower() in ['medication', 'medicationintake']:
                        return access_level in ['MEDICATIONS', 'FULL']
                        
                    # Full access for FULL level
                    return access_level == 'FULL'
                    
            return False
            
        # Researcher access (for research consented data)
        if request.user.role == 'researcher' and hasattr(request.user, 'researcher_profile'):
            if request.user.researcher_profile.is_verified:
                # Only allow access to patients who consented to research
                if hasattr(patient, 'research_consent'):
                    return patient.research_consent
                elif hasattr(patient, 'medical_record') and hasattr(patient.medical_record, 'research_participation_consent'):
                    return patient.medical_record.research_participation_consent
                    
            return False
            
        # Pharma company access (for medication adherence)
        if request.user.role == 'pharmco':
            # Only read access for medication data
            if request.method in permissions.SAFE_METHODS:
                if view.basename.lower() in ['medication', 'medicationintake']:
                    return patient.medication_adherence_monitoring_consent
                    
            return False
            
        # Compliance officer access
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            # PHI access check
            return request.user.compliance_profile.can_view_phi
            
        return False


class CanViewAuditLogs(permissions.BasePermission):
    """Permission to view audit logs (admin, compliance)."""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
            
        # Admins can always view audit logs
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Compliance officers with audit log access
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            return request.user.compliance_profile.can_view_audit_logs
            
        return False


class IsProviderForReferral(permissions.BasePermission):
    """Permission for providers to create and manage referrals."""
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
            
        # Read access is public for providers and patients
        if request.method in permissions.SAFE_METHODS:
            return request.user.role in ['patient', 'provider', 'admin'] or request.user.is_staff
            
        # Write access only for providers and admins
        return request.user.role in ['provider', 'admin'] or request.user.is_staff
        
    def has_object_permission(self, request, view, obj):
        # Read access is public for providers and patients
        if request.method in permissions.SAFE_METHODS:
            return request.user.role in ['patient', 'provider', 'admin'] or request.user.is_staff
            
        # Providers can only update their own referral network entries
        if request.user.role == 'provider':
            return obj.provider == request.user
            
        # Admins can update any entry
        return request.user.role == 'admin' or request.user.is_staff
