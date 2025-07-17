from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Allow owners to edit, others to read if public.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any safe methods
        if request.method in permissions.SAFE_METHODS:
            # Check if public or user has access
            if hasattr(obj, 'is_public') and obj.is_public:
                return True
            return obj.owner == request.user or request.user.is_staff or request.user.role == 'admin'
            
        # Write permissions are only allowed to the owner
        return obj.owner == request.user or request.user.is_staff or request.user.role == 'admin'


class HasReportAccess(permissions.BasePermission):
    """
    Permission to check if user has access to reports.
    """
    def has_permission(self, request, view):
        # Admins always have access
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Compliance officers have access
        if request.user.role == 'compliance':
            return True
            
        # Providers have access
        if request.user.role == 'provider':
            return True
            
        # Researchers with verified status have access
        if request.user.role == 'researcher' and hasattr(request.user, 'researcher_profile'):
            return request.user.researcher_profile.is_verified
            
        # Patients can access their own reports
        if request.user.role == 'patient':
            return True
            
        # Others don't have access by default
        return False
    
    def has_object_permission(self, request, view, obj):
        # Admins always have access
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Compliance officers have access
        if request.user.role == 'compliance':
            return True
            
        # Creator has access
        if obj.created_by == request.user:
            return True
            
        # Check configuration access if it's a report
        if hasattr(obj, 'configuration'):
            config = obj.configuration
            # Public configurations are accessible
            if config.is_public:
                return True
                
            # Check if user role is in allowed roles
            if request.user.role in config.allowed_roles:
                return True
                
        # Others don't have access
        return False


class HasDashboardAccess(permissions.BasePermission):
    """
    Permission to check if user has access to dashboards.
    """
    def has_permission(self, request, view):
        # Everyone authenticated has access to dashboards endpoint
        return True
    
    def has_object_permission(self, request, view, obj):
        # Admins always have access
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Owner has access
        if obj.owner == request.user:
            return True
            
        # Public dashboards are accessible
        if obj.is_public:
            return True
            
        # Check if user is in shared_with
        if request.user in obj.shared_with.all():
            return True
            
        # Others don't have access
        return False


class CanAccessAnalytics(permissions.BasePermission):
    """
    Permission to check if user can access analytics.
    """
    def has_permission(self, request, view):
        # Admins always have access
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Compliance officers have access
        if request.user.role == 'compliance':
            return True
            
        # Providers have access
        if request.user.role == 'provider':
            return True
            
        # Researchers with verified status have access
        if request.user.role == 'researcher' and hasattr(request.user, 'researcher_profile'):
            return request.user.researcher_profile.is_verified
            
        # Pharmaceutical companies have access to certain analytics
        if request.user.role == 'pharmco':
            # Specific analytics endpoints can be restricted in the view
            return True
            
        # Patients can access limited analytics
        if request.user.role == 'patient':
            # Specific limited analytics for patients
            if view.action in ['adherence_metrics', 'vitals_trends']:
                return True
            return False
            
        # Others don't have access by default
        return False


class IsApprovedUser(permissions.BasePermission):
    """
    Allows access only to approved users.
    """
    message = "Your account is pending administrator approval."
    
    def has_permission(self, request, view):
        # Admins and staff are always approved
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Check if the user is approved
        return request.user.is_approved


class IsComplianceOfficerOrAdmin(permissions.BasePermission):
    """
    Allows access only to compliance officers and admins.
    """
    message = "Only compliance officers and administrators can access this resource."
    
    def has_permission(self, request, view):
        # Admins always have access
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Compliance officers have access
        if request.user.role == 'compliance':
            return True
            
        # Others don't have access
        return False
