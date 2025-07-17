# Create medication/permissions.py
from rest_framework import permissions
from django.shortcuts import get_object_or_404

class IsMedicationOwnerOrProvider(permissions.BasePermission):
    """
    Permission to check if user is the medication owner or prescriber.
    """
    
    def has_object_permission(self, request, view, obj):
        # Patient can access their own medications
        if request.user == obj.patient:
            return True
            
        # Prescriber can access medications they prescribed
        if request.user == obj.prescriber:
            return True
            
        # Authorized caregivers can access
        if (request.user.role == 'caregiver' and 
            hasattr(request.user, 'caregiver_profile') and
            request.user.caregiver_profile.access_level in ['MEDICATIONS', 'FULL']):
            # Check if caregiver is authorized for this patient
            return obj.patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists()
            
        # Pharmaceutical companies with consent can view aggregated data
        if (request.user.role == 'pharmco' and
            obj.patient.patient_profile.protocol_adherence_monitoring and
            obj.for_rare_condition):
            return True
            
        return False

class CanManageMedicationReminders(permissions.BasePermission):
    """
    Permission for managing medication reminders.
    """
    
    def has_object_permission(self, request, view, obj):
        # Patient can manage their own reminders
        if request.user == obj.patient:
            return True
            
        # Prescriber can manage reminders for their medications
        if request.user == obj.medication.prescriber:
            return True
            
        # Authorized caregivers with medication access
        if (request.user.role == 'caregiver' and 
            hasattr(request.user, 'caregiver_profile') and
            request.user.caregiver_profile.access_level in ['MEDICATIONS', 'FULL']):
            return obj.patient.patient_profile.authorized_caregivers.filter(id=request.user.id).exists()
            
        return False