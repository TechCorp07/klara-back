from rest_framework import permissions
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

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


class IsConversationParticipant(permissions.BasePermission):
    """
    Allow actions only to users who are participants in the conversation.
    """
    def has_permission(self, request, view):
        # List and create permissions are handled at the view level
        return True
        
    def has_object_permission(self, request, view, obj):
        # Admin can access all conversations
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # For conversations, check if user is a participant
        if hasattr(obj, 'participants'):
            return obj.participants.filter(id=request.user.id).exists()
            
        # For messages, check if user is a participant in the conversation
        if hasattr(obj, 'conversation') and hasattr(obj.conversation, 'participants'):
            return obj.conversation.participants.filter(id=request.user.id).exists()
            
        # Default deny
        return False


class CanAccessNotification(permissions.BasePermission):
    """
    Allow access only to the user who owns the notification or admins.
    """
    def has_object_permission(self, request, view, obj):
        # Admin can access all notifications
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Users can only access their own notifications
        return obj.user == request.user


class CanViewConversationBetweenRoles(permissions.BasePermission):
    """
    Permissions based on role relationships.
    For example, providers can only message patients they are treating.
    """
    def has_object_permission(self, request, view, obj):
        # Admin can access all conversations
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Different role rules
        user_role = request.user.role
        
        # If it's a direct patient-provider conversation
        if user_role == 'provider':
            # Providers can see conversations with their patients
            patient_participants = obj.participants.filter(role='patient')
            
            for patient in patient_participants:
                # Check if provider is treating this patient
                if hasattr(patient, 'medical_records') and patient.medical_records.filter(primary_physician=request.user).exists():
                    return True
                    
                # Also check appointments
                if hasattr(patient, 'patient_appointments') and patient.patient_appointments.filter(provider=request.user).exists():
                    return True
            
            # If no direct patient relationships, access denied
            return False
            
        # Patients can only access their conversations
        elif user_role == 'patient':
            return obj.participants.filter(id=request.user.id).exists()
            
        # Caregivers can see conversations for patients they are authorized for
        elif user_role == 'caregiver' and hasattr(request.user, 'caregiver_profile'):
            # Check if any participant is a patient this caregiver is authorized for
            patient_participants = obj.participants.filter(role='patient')
            
            for patient in patient_participants:
                if hasattr(patient, 'patient_profile') and patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists():
                    return True
            
            return False
            
        # Default to standard participant check
        return obj.participants.filter(id=request.user.id).exists()
