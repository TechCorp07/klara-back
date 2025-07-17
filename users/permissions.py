# permissions.py
from rest_framework import permissions


class IsAdminOrSelfOnly(permissions.BasePermission):
    """
    Allow users to edit only their own profile unless they are admins.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the user or admin
        return obj == request.user or request.user.is_staff or request.user.role == 'admin'


class IsApprovedUser(permissions.BasePermission):
    """
    Allow access only to approved users.
    Admins and superusers are always considered approved.
    """
    message = "Your account is pending administrator approval."
    
    def has_permission(self, request, view):
        # Allow unapproved users to access certain endpoints
        if view.action in ['create', 'login', 'verify_2fa', 'check_status', 
                          'forgot_password', 'reset_password', 'verify_email']:
            return True
        
        # Check if user is authenticated
        if not request.user.is_authenticated:
            return False
        
        # Admins, staff, and superusers are always approved
        if request.user.is_staff or request.user.is_superuser or request.user.role == 'admin':
            return True
        
        # Check if user is approved
        return request.user.is_approved


class IsRoleOwnerOrReadOnly(permissions.BasePermission):
    """
    Allow owners of profiles to edit them.
    Read access is determined by the viewset's get_queryset method.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed based on queryset filtering
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner or admin
        if hasattr(obj, 'user'):
            return obj.user == request.user or request.user.is_staff or request.user.role == 'admin'
        
        return request.user.is_staff or request.user.role == 'admin'


class IsComplianceOfficer(permissions.BasePermission):
    """
    Allow compliance officers appropriate access to data.
    """
    def has_permission(self, request, view):
        # Always allow admins and superusers
        if request.user.is_staff or request.user.is_superuser or request.user.role == 'admin':
            return True
        
        # For compliance officers
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            # Read-only access for most views
            if request.method in permissions.SAFE_METHODS:
                profile = request.user.compliance_profile
                
                # Check specific permissions based on view type
                view_name = view.basename.lower() if hasattr(view, 'basename') else ''
                
                if 'audit' in view_name:
                    return profile.can_view_audit_logs
                elif 'patient' in view_name or 'phi' in view_name:
                    return profile.can_view_phi
                elif 'emergency' in view_name:
                    return profile.can_manage_emergencies
                
                # Default to allowing read access
                return True
            
            # Write permissions only for specific actions
            if view.action in ['review', 'update_notes']:
                return True
        
        return False


class IsSuperuserOrReadOnly(permissions.BasePermission):
    """
    Allow superusers full access, others read-only.
    Used for viewing system-wide data.
    """
    def has_permission(self, request, view):
        # Read permissions are allowed to authenticated users
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        
        # Write permissions only for superusers
        return request.user.is_superuser


class IsCaregiverWithAccess(permissions.BasePermission):
    """
    Allow caregivers to access patient data based on authorization.
    """
    def has_permission(self, request, view):
        # Always allow admins and providers
        if request.user.is_staff or request.user.role in ['admin', 'provider']:
            return True
        
        # For caregivers, check if they have authorization
        if request.user.role == 'caregiver':
            # For list actions, rely on get_queryset filtering
            if view.action == 'list':
                return True
            
            # For detail actions, check authorization
            return True  # Specific checks happen in has_object_permission
        
        return False
    
    def has_object_permission(self, request, view, obj):
        # Always allow admins and providers
        if request.user.is_staff or request.user.role in ['admin', 'provider']:
            return True
        
        # For caregivers, check if they're authorized for this patient
        if request.user.role == 'caregiver':
            # Check if object has patient relationship
            patient = None
            if hasattr(obj, 'patient'):
                patient = obj.patient
            elif hasattr(obj, 'user') and hasattr(obj.user, 'patient_profile'):
                patient = obj.user.patient_profile
            
            if patient:
                # Check if caregiver is authorized
                from .models import PatientAuthorizedCaregiver
                
                auth = PatientAuthorizedCaregiver.objects.filter(
                    patient=patient,
                    caregiver=request.user
                ).first()
                
                if auth:
                    # Check access level for write operations
                    if request.method not in permissions.SAFE_METHODS:
                        if 'medication' in str(view.basename).lower():
                            return auth.access_level in ['MEDICATIONS', 'FULL']
                        elif 'appointment' in str(view.basename).lower():
                            return auth.access_level in ['SCHEDULE', 'FULL']
                        else:
                            return auth.access_level == 'FULL'
                    return True
        
        return False


class IsPharmcoWithConsent(permissions.BasePermission):
    """
    Allow pharmaceutical companies to access data only for consented patients.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff or request.user.role == 'admin':
            return True
        
        # For pharmaceutical companies
        if request.user.role == 'pharmco':
            # Only allow read access
            if request.method in permissions.SAFE_METHODS:
                return True
        
        return False
    
    def has_object_permission(self, request, view, obj):
        # Always allow admins
        if request.user.is_staff or request.user.role == 'admin':
            return True
        
        # For pharmaceutical companies, check consent
        if request.user.role == 'pharmco':
            # Only allow read access
            if request.method not in permissions.SAFE_METHODS:
                return False
            
            # Check if patient has consented to medication monitoring
            patient_profile = None
            if hasattr(obj, 'patient'):
                patient_profile = obj.patient
            elif hasattr(obj, 'user') and hasattr(obj.user, 'patient_profile'):
                patient_profile = obj.user.patient_profile
            
            if patient_profile:
                return patient_profile.medication_adherence_monitoring_consent
        
        return False


class IsResearcherWithConsent(permissions.BasePermission):
    """
    Allow researchers to access anonymized data for consented patients.
    """
    def has_permission(self, request, view):
        # Always allow admins
        if request.user.is_staff or request.user.role == 'admin':
            return True
        
        # For researchers
        if request.user.role == 'researcher' and hasattr(request.user, 'researcher_profile'):
            # Must be verified
            if not request.user.researcher_profile.is_verified:
                return False
            
            # Only allow read access
            if request.method in permissions.SAFE_METHODS:
                return True
        
        return False
    
    def has_object_permission(self, request, view, obj):
        # Always allow admins
        if request.user.is_staff or request.user.role == 'admin':
            return True
        
        # For researchers, check consent and verification
        if request.user.role == 'researcher' and hasattr(request.user, 'researcher_profile'):
            # Must be verified
            if not request.user.researcher_profile.is_verified:
                return False
            
            # Only allow read access
            if request.method not in permissions.SAFE_METHODS:
                return False
            
            # Check if patient has consented to research
            patient_profile = None
            if hasattr(obj, 'patient'):
                patient_profile = obj.patient
            elif hasattr(obj, 'user') and hasattr(obj.user, 'patient_profile'):
                patient_profile = obj.user.patient_profile
            
            if patient_profile:
                return patient_profile.research_participation_consent
        
        return False


class IsPatientOrAuthorized(permissions.BasePermission):
    """
    Allow patients to access their own data, or authorized users.
    """
    def has_object_permission(self, request, view, obj):
        # Always allow admins
        if request.user.is_staff or request.user.role == 'admin':
            return True
        
        # Check if user is the patient
        if hasattr(obj, 'user'):
            if obj.user == request.user:
                return True
        elif hasattr(obj, 'patient') and hasattr(obj.patient, 'user'):
            if obj.patient.user == request.user:
                return True
        
        # Check if user is an authorized caregiver
        if request.user.role == 'caregiver':
            patient = None
            if hasattr(obj, 'patient'):
                patient = obj.patient
            elif hasattr(obj, 'user') and hasattr(obj.user, 'patient_profile'):
                patient = obj.user.patient_profile
            
            if patient:
                from .models import PatientAuthorizedCaregiver
                return PatientAuthorizedCaregiver.objects.filter(
                    patient=patient,
                    caregiver=request.user
                ).exists()
        
        # Check if user is a provider
        if request.user.role == 'provider':
            return True
        
        return False
