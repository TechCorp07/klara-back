from rest_framework import permissions
from django.conf import settings

class IsAdminUser(permissions.BasePermission):
    """
    Permission to only allow admin users to access the audit system.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'admin')


class IsSuperuser(permissions.BasePermission):
    """
    Permission to only allow superusers to access sensitive audit operations.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)


class IsComplianceOfficer(permissions.BasePermission):
    """
    Permission to allow compliance officers to access audit reports.
    This includes both dedicated compliance officers and administrators.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
            
        # Admins always have access
        if request.user.role == 'admin' or request.user.is_superuser:
            return True
            
        # Check for compliance officer role
        if request.user.role == 'compliance':
            # If we have a compliance profile, check permissions
            if hasattr(request.user, 'compliance_profile'):
                # For audit logs, check specific permission
                if getattr(view, 'audit_permission_type', None) == 'audit_logs':
                    return request.user.compliance_profile.can_view_audit_logs
                
                # For PHI logs, check specific permission
                if getattr(view, 'audit_permission_type', None) == 'phi_access':
                    return request.user.compliance_profile.can_view_phi
                    
                # For consent logs, check specific permission
                if getattr(view, 'audit_permission_type', None) == 'consent_logs':
                    return request.user.compliance_profile.can_view_consent_logs
                
                # Default access for compliance officers
                return True
            return True  # Allow access if compliance profile doesn't exist
            
        return False


class CanAccessPHILogs(permissions.BasePermission):
    """
    Permission to allow access to PHI access logs.
    
    Allowed roles:
    - Administrators (full access)
    - Compliance officers with PHI access permission
    - Providers (limited to their own access logs)
    - Patients (limited to their own logs)
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Check user role
        if request.user.role == 'admin' or request.user.is_superuser:
            return True
            
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            return request.user.compliance_profile.can_view_phi
            
        if request.user.role in ['provider', 'patient']:
            return True
            
        phi_access_roles = getattr(settings, 'PHI_ACCESS_ROLES', ['admin', 'provider', 'compliance', 'caregiver'])
        return request.user.role in phi_access_roles
        
    def has_object_permission(self, request, view, obj):
        """
        Object level permissions for PHI logs.
        
        For non-admin and non-compliance users, restrict to:
        - Provider can see their own access logs
        - Patient can see logs related to their data
        """
        # Admins always have access
        if request.user.role == 'admin' or request.user.is_superuser:
            return True
            
        # Compliance officers with PHI access have full access
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            return request.user.compliance_profile.can_view_phi
            
        # Providers can see their own access logs
        if request.user.role == 'provider' and obj.user and obj.user.id == request.user.id:
            return True
            
        # Patients can see logs related to their PHI
        if request.user.role == 'patient' and obj.patient and obj.patient.id == request.user.id:
            return True
            
        # Caregivers can see logs related to patients they are authorized for
        if (request.user.role == 'caregiver' and obj.patient and 
            hasattr(obj.patient, 'patient_profile') and 
            obj.patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists()):
            return True
            
        return False


class CanManageSecurityEvents(permissions.BasePermission):
    """
    Permission to allow managing security events.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
            
        # Only admin and compliance can manage security events
        return request.user.role in ['admin', 'compliance']
        
    def has_object_permission(self, request, view, obj):
        # Only allow write operations for admins 
        if request.method not in permissions.SAFE_METHODS:
            return request.user.role == 'admin' or request.user.is_superuser
            
        # Compliance officers can view security events
        if request.user.role == 'compliance':
            return True
            
        return request.user.role == 'admin' or request.user.is_superuser
