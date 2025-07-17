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
        # Allow unapproved users to access login and registration
        if view.action in ['create', 'login', 'verify_2fa']:
            return True
            
        # Admins and staff are always approved
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # For all other actions, check if the user is approved
        return request.user.is_approved


class IsPatientProviderOrAdmin(permissions.BasePermission):
    """
    Allow access to patients, providers, or admins.
    """
    def has_permission(self, request, view):
        # Require authentication
        if not request.user.is_authenticated:
            return False
            
        # Allow admins and staff
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Allow patients and providers
        return request.user.role in ['patient', 'provider']


class IsProviderOrAdmin(permissions.BasePermission):
    """
    Allow access only to providers or admins.
    """
    message = "Only healthcare providers can perform this action."
    
    def has_permission(self, request, view):
        # Require authentication
        if not request.user.is_authenticated:
            return False
            
        # Allow admins and staff
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Allow providers
        return request.user.role == 'provider'


class IsAppointmentParticipant(permissions.BasePermission):
    """
    Allow access only to users who are participants in the appointment.
    """
    def has_object_permission(self, request, view, obj):
        # Allow admins and staff
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Allow if user is the patient or provider for the appointment
        if hasattr(obj, 'patient') and hasattr(obj, 'provider'):
            return request.user == obj.patient or request.user == obj.provider
            
        # For consultations, check the appointment
        if hasattr(obj, 'appointment'):
            appointment = obj.appointment
            return request.user == appointment.patient or request.user == appointment.provider
            
        # For prescriptions, check directly
        if hasattr(obj, 'patient') and hasattr(obj, 'provider'):
            return request.user == obj.patient or request.user == obj.provider
            
        return False


class CanViewPrescription(permissions.BasePermission):
    """
    Permission to view prescription details.
    - Patients can view their own prescriptions
    - Providers can view prescriptions they created
    - Pharmacies can view active/pending prescriptions
    """
    def has_object_permission(self, request, view, obj):
        # Admin can view all
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Patient can view their own
        if request.user.role == 'patient':
            return obj.patient == request.user
            
        # Provider can view ones they created
        if request.user.role == 'provider':
            return obj.provider == request.user
            
        # Pharmacy can view active/pending prescriptions
        if request.user.role == 'pharmco':
            return obj.status in ['pending', 'active']
            
        return False


class CanStartConsultation(permissions.BasePermission):
    """
    Permission to start a consultation.
    - Only providers can start consultations
    - Provider must be assigned to the appointment
    """
    def has_object_permission(self, request, view, obj):
        # Must be provider
        if request.user.role != 'provider':
            return False
            
        # Must be the provider for this consultation
        return obj.appointment.provider == request.user


class CanJoinConsultation(permissions.BasePermission):
    """
    Permission to join a consultation.
    - Only participants can join
    - Consultation must be ready or in progress
    """
    def has_object_permission(self, request, view, obj):
        # Must be participant
        is_participant = (
            obj.appointment.patient == request.user or 
            obj.appointment.provider == request.user
        )
        
        if not is_participant:
            return False
            
        # Consultation must be in proper state
        valid_status = obj.status in ['ready', 'in_progress']
        
        return valid_status


class CanManageProviderAvailability(permissions.BasePermission):
    """
    Permission to manage provider availability.
    - Providers can manage their own availability
    - Admins can manage all availabilities
    """
    def has_permission(self, request, view):
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        if request.user.role == 'provider':
            return True
            
        return False
        
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Providers can only manage their own availability
        if request.user.role == 'provider':
            return obj.provider == request.user
            
        return False


class CanManageWaitingRoom(permissions.BasePermission):
    """
    Permission to manage waiting room.
    - Providers can manage their own waiting rooms
    - Admins can manage all waiting rooms
    """
    def has_permission(self, request, view):
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        if request.user.role == 'provider':
            return True
            
        return False
        
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Providers can only manage their own waiting rooms
        if request.user.role == 'provider':
            return obj.provider == request.user
            
        return False


class CanPrescribe(permissions.BasePermission):
    """
    Permission to create and manage prescriptions.
    - Only providers can prescribe
    - Only active prescriptions for provider's patients
    """
    def has_permission(self, request, view):
        # Only providers and admins can create prescriptions
        return request.user.is_authenticated and (
            request.user.is_staff or 
            request.user.role == 'admin' or
            request.user.role == 'provider'
        )
    
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # Provider can only manage their own prescriptions
        if request.user.role == 'provider':
            return obj.provider == request.user
            
        return False


class IsPatientWithTelemedicineAccess(permissions.BasePermission):
    """
    Permission for patients who have consented to telemedicine.
    Checks if the patient has the necessary consent flags for telemedicine.
    """
    message = "You must provide consent for telemedicine services before proceeding."
    
    def has_permission(self, request, view):
        # Admins always have access
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        # For providers, check their telemedicine capabilities
        if request.user.role == 'provider':
            return hasattr(request.user, 'provider_profile') and getattr(request.user.provider_profile, 'telemedicine_available', False)
            
        # For patients, check telemedicine consent
        if request.user.role == 'patient':
            # Check if the patient has consented to telemedicine
            # This would need to be implemented based on your consent tracking system
            from healthcare.models import HealthDataConsent
            
            try:
                consent = HealthDataConsent.objects.filter(
                    patient=request.user,
                    consent_type='telemedicine',
                    consented=True
                ).exists()
                
                return consent
            except:
                # If consent system not available, default to permission check
                return request.user.is_authenticated
                
        return False


class CanViewHealthData(permissions.BasePermission):
    """
    Permission to view patient health data.
    Ensures HIPAA compliance for PHI access.
    """
    def has_permission(self, request, view):
        # Always require authentication
        if not request.user.is_authenticated:
            return False
            
        # Admin and compliance officers with PHI access can view
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            return request.user.compliance_profile.can_view_phi
            
        # Providers and patients have role-based access checked at object level
        return request.user.role in ['patient', 'provider', 'caregiver']
    
    def has_object_permission(self, request, view, obj):
        # Get the patient from the object
        patient = None
        
        if hasattr(obj, 'patient'):
            patient = obj.patient
        elif hasattr(obj, 'appointment') and hasattr(obj.appointment, 'patient'):
            patient = obj.appointment.patient
            
        if not patient:
            return False
            
        # Admin and compliance officers with PHI access can view
        if request.user.is_staff or request.user.role == 'admin':
            return True
            
        if request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile'):
            return request.user.compliance_profile.can_view_phi
            
        # Patients can view their own data
        if request.user.role == 'patient':
            return request.user == patient
            
        # Providers can view data for their patients
        if request.user.role == 'provider':
            # If there's a direct provider field, check that
            if hasattr(obj, 'provider'):
                return obj.provider == request.user
                
            # For appointments and consultations
            if hasattr(obj, 'appointment') and hasattr(obj.appointment, 'provider'):
                return obj.appointment.provider == request.user
                
            # Check if provider is primary for this patient
            if hasattr(patient, 'medical_records'):
                return patient.medical_records.filter(primary_physician=request.user).exists()
                
        # Caregivers can view data for patients they're authorized for
        if request.user.role == 'caregiver' and hasattr(request.user, 'caregiver_profile'):
            if hasattr(patient, 'patient_profile'):
                return patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists()
                
        return False
