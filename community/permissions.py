# permissions.py
from rest_framework import permissions
from users.models import User  # Assuming your user model is here

class IsCommunityMemberOrPublic(permissions.BasePermission):
    """
    Allow access to community content based on privacy settings.
    Users can see public groups or private groups where they're members.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff or getattr(request.user, 'role', None) == 'admin':
            return True
        
        # Identify the group from obj
        if hasattr(obj, 'group'):
            group = obj.group
        elif hasattr(obj, 'post') and hasattr(obj.post, 'group'):
            group = obj.post.group
        else:
            return False
        
        # Public group
        if not group.is_private:
            return True
        
        # Private group => must be an approved member
        return group.memberships.filter(
            user=request.user, 
            status='approved'
        ).exists()


class IsPostAuthorOrReadOnly(permissions.BasePermission):
    """
    Read access to anyone who can see the post.
    Write access only to the author or group moderators/admins/experts.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        # Author can edit
        if obj.author == request.user:
            return True
        # Moderator/admin/expert can edit
        return obj.group.memberships.filter(
            user=request.user,
            role__in=['admin', 'moderator', 'expert'],
            status='approved'
        ).exists()


class IsModerationPermitted(permissions.BasePermission):
    """
    Allow moderation actions only for group moderators, experts, and admins.
    """
    def has_permission(self, request, view):
        group_id = request.data.get('group') or view.kwargs.get('group_id')
        if not group_id:
            return False
        if request.user.is_staff or getattr(request.user, 'role', None) == 'admin':
            return True
        
        from community.models import CommunityMembership
        return CommunityMembership.objects.filter(
            user=request.user,
            group_id=group_id,
            role__in=['admin', 'moderator', 'expert'],
            status='approved'
        ).exists()
    
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff or getattr(request.user, 'role', None) == 'admin':
            return True
        
        if hasattr(obj, 'group'):
            group = obj.group
        elif hasattr(obj, 'post') and hasattr(obj.post, 'group'):
            group = obj.post.group
        else:
            return False
        
        return group.memberships.filter(
            user=request.user,
            role__in=['admin', 'moderator', 'expert'],
            status='approved'
        ).exists()


class HasPatientDataAccess(permissions.BasePermission):
    """
    Permission class for healthcare data access in the community.
    """
    def has_permission(self, request, view):
        patient_id = request.query_params.get('patient_id')
        
        # Admins/providers always have access
        user_role = getattr(request.user, 'role', None)
        if request.user.is_staff or user_role in ['admin', 'provider']:
            return True
        
        # Patients can access their own data
        if user_role == 'patient' and hasattr(request.user, 'patient_profile'):
            if not patient_id or str(request.user.patient_profile.id) == patient_id:
                return True
        
        # Caregivers with specific permissions
        if user_role == 'caregiver' and hasattr(request.user, 'caregiver_profile'):
            if patient_id:
                from users.models import PatientProfile
                try:
                    patient = PatientProfile.objects.get(id=patient_id)
                    if patient.authorized_caregivers.filter(id=request.user.id).exists():
                        # FULL => all actions; otherwise read-only
                        if request.user.caregiver_profile.access_level == 'FULL':
                            return True
                        elif request.method in permissions.SAFE_METHODS:
                            return True
                except PatientProfile.DoesNotExist:
                    return False
        
        return False
