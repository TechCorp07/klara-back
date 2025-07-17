# security/permissions.py
from rest_framework import permissions
from django.conf import settings


class IsSecurityAdminUser(permissions.BasePermission):
    """
    Permission class that only allows access to admin users and superusers.
    Security module requires the highest level of access control.
    """
    
    def has_permission(self, request, view):
        """Check if user has security admin permissions."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Only allow superusers and admin role users
        if request.user.is_superuser:
            return True
        
        if hasattr(request.user, 'role') and request.user.role == 'admin':
            return True
        
        # Additional check for dedicated security role if implemented
        if hasattr(request.user, 'role') and request.user.role == 'security':
            return True
        
        return False
    
    def has_object_permission(self, request, view, obj):
        """Object-level permissions for security objects."""
        # Same requirements as has_permission
        return self.has_permission(request, view)


class IsSecuritySuperUser(permissions.BasePermission):
    """
    Permission class that only allows superusers access.
    For the most sensitive security operations.
    """
    
    def has_permission(self, request, view):
        """Only superusers can access."""
        return bool(
            request.user and 
            request.user.is_authenticated and 
            request.user.is_superuser
        )


class CanViewSecurityReports(permissions.BasePermission):
    """
    Permission for viewing security reports.
    Allows compliance officers to view reports without full security access.
    """
    
    def has_permission(self, request, view):
        """Check if user can view security reports."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Allow superusers and admins
        if request.user.is_superuser or getattr(request.user, 'role', None) == 'admin':
            return True
        
        # Allow compliance officers to view reports
        if getattr(request.user, 'role', None) == 'compliance':
            # Only allow read operations for compliance officers
            return request.method in permissions.SAFE_METHODS
        
        return False


class CanManageSecurityIncidents(permissions.BasePermission):
    """
    Permission for managing security incidents.
    Allows incident response team members limited access.
    """
    
    def has_permission(self, request, view):
        """Check if user can manage security incidents."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Allow superusers and admins full access
        if request.user.is_superuser or getattr(request.user, 'role', None) == 'admin':
            return True
        
        # Allow security role users
        if getattr(request.user, 'role', None) == 'security':
            return True
        
        # Allow compliance officers read-only access
        if getattr(request.user, 'role', None) == 'compliance':
            return request.method in permissions.SAFE_METHODS
        
        return False


class CanAccessNetworkMonitoring(permissions.BasePermission):
    """
    Permission for accessing network monitoring data.
    Network monitoring data is particularly sensitive.
    """
    
    def has_permission(self, request, view):
        """Check if user can access network monitoring data."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Only allow superusers and admin users
        allowed_roles = ['admin', 'security']
        
        if request.user.is_superuser:
            return True
        
        if hasattr(request.user, 'role') and request.user.role in allowed_roles:
            return True
        
        return False


class CanConfigureSecurity(permissions.BasePermission):
    """
    Permission for configuring security settings.
    Only the most privileged users should be able to change security configurations.
    """
    
    def has_permission(self, request, view):
        """Check if user can configure security settings."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Only superusers can modify security configurations
        if request.user.is_superuser:
            return True
        
        # Admin users can view configurations but not modify
        if (hasattr(request.user, 'role') and 
            request.user.role == 'admin' and 
            request.method in permissions.SAFE_METHODS):
            return True
        
        return False


class CanRunVulnerabilityScans(permissions.BasePermission):
    """
    Permission for running vulnerability scans.
    Vulnerability scans can impact system performance and should be controlled.
    """
    
    def has_permission(self, request, view):
        """Check if user can run vulnerability scans."""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Allow superusers and admin users
        if request.user.is_superuser or getattr(request.user, 'role', None) == 'admin':
            return True
        
        # Allow security role users
        if getattr(request.user, 'role', None) == 'security':
            return True
        
        return False