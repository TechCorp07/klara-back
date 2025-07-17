# Add to audit/services/integration_service.py

import logging
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model

from ..models import AuditEvent, PHIAccessLog, SecurityAuditLog

User = get_user_model()
logger = logging.getLogger(__name__)

class HealthcareAuditIntegration:
    """
    Service for integrating audit functionality with healthcare-specific components.
    """
    
    @staticmethod
    def log_medical_record_access(user, medical_record, access_type='view', reason=None):
        """
        Log access to a medical record.
        
        Args:
            user: User accessing the record
            medical_record: Medical record being accessed
            access_type: Type of access (view, modify, export)
            reason: Reason for accessing the record
        
        Returns:
            PHIAccessLog: The created access log
        """
        from healthcare.models import MedicalRecord
        
        if not isinstance(medical_record, MedicalRecord):
            logger.error(f"log_medical_record_access called with invalid medical_record: {medical_record}")
            return None
        
        try:
            # Map access type string to PHIAccessLog.AccessType
            access_type_map = {
                'view': PHIAccessLog.AccessType.VIEW,
                'modify': PHIAccessLog.AccessType.MODIFY,
                'export': PHIAccessLog.AccessType.EXPORT,
                'share': PHIAccessLog.AccessType.SHARE,
                'print': PHIAccessLog.AccessType.PRINT,
            }
            
            mapped_access_type = access_type_map.get(access_type.lower(), PHIAccessLog.AccessType.VIEW)
            
            # Create PHI access log
            access_log = PHIAccessLog.objects.create(
                user=user,
                patient=medical_record.patient,
                access_type=mapped_access_type,
                reason=reason or "Medical record access",
                record_type='medical_record',
                record_id=str(medical_record.id),
                additional_data={
                    'record_number': medical_record.medical_record_number,
                    'primary_physician_id': str(medical_record.primary_physician.id) if medical_record.primary_physician else None,
                }
            )
            
            # Also log general audit event
            AuditEvent.objects.create(
                user=user,
                event_type=AuditEvent.EventType.ACCESS,
                resource_type='medical_record',
                resource_id=str(medical_record.id),
                description=f"{mapped_access_type} access to medical record for {medical_record.patient}"
            )
            
            return access_log
            
        except Exception as e:
            logger.error(f"Error logging medical record access: {str(e)}")
            return None
    
    @staticmethod
    def log_telemedicine_consultation(user, consultation, action_type='start', reason=None):
        """
        Log telemedicine consultation activity.
        
        Args:
            user: User performing the action
            consultation: Telemedicine consultation
            action_type: Type of action (start, join, end)
            reason: Reason for the action
        
        Returns:
            PHIAccessLog: The created access log
        """
        from telemedicine.models import Consultation
        
        if not isinstance(consultation, Consultation):
            logger.error(f"log_telemedicine_consultation called with invalid consultation: {consultation}")
            return None
        
        try:
            # Ensure we have an appointment and patient
            if not consultation.appointment or not consultation.appointment.patient:
                logger.error(f"Consultation {consultation.id} has no associated appointment or patient")
                return None
            
            # Determine event type and access type
            if action_type == 'start':
                event_type = AuditEvent.EventType.CREATE
                access_type = PHIAccessLog.AccessType.MODIFY
                description = f"Started telemedicine consultation for {consultation.appointment.patient}"
            elif action_type == 'join':
                event_type = AuditEvent.EventType.ACCESS
                access_type = PHIAccessLog.AccessType.VIEW
                description = f"Joined telemedicine consultation for {consultation.appointment.patient}"
            elif action_type == 'end':
                event_type = AuditEvent.EventType.UPDATE
                access_type = PHIAccessLog.AccessType.MODIFY
                description = f"Ended telemedicine consultation for {consultation.appointment.patient}"
            else:
                event_type = AuditEvent.EventType.ACCESS
                access_type = PHIAccessLog.AccessType.VIEW
                description = f"Accessed telemedicine consultation for {consultation.appointment.patient}"
            
            # Create PHI access log
            access_log = PHIAccessLog.objects.create(
                user=user,
                patient=consultation.appointment.patient,
                access_type=access_type,
                reason=reason or f"Telemedicine consultation {action_type}",
                record_type='telemedicine_consultation',
                record_id=str(consultation.id),
                additional_data={
                    'appointment_id': str(consultation.appointment.id),
                    'action': action_type,
                    'platform': consultation.platform,
                    'status': consultation.status,
                }
            )
            
            # Also log general audit event
            AuditEvent.objects.create(
                user=user,
                event_type=event_type,
                resource_type='telemedicine_consultation',
                resource_id=str(consultation.id),
                description=description
            )
            
            return access_log
            
        except Exception as e:
            logger.error(f"Error logging telemedicine consultation: {str(e)}")
            return None
    
    @staticmethod
    def log_medication_access(user, medication, access_type='view', reason=None):
        """
        Log access to medication records.
        
        Args:
            user: User accessing the medication
            medication: Medication being accessed
            access_type: Type of access (view, modify, export)
            reason: Reason for accessing the medication
        
        Returns:
            PHIAccessLog: The created access log
        """
        from healthcare.models import Medication
        
        if not isinstance(medication, Medication):
            logger.error(f"log_medication_access called with invalid medication: {medication}")
            return None
        
        try:
            # Map access type string to PHIAccessLog.AccessType
            access_type_map = {
                'view': PHIAccessLog.AccessType.VIEW,
                'modify': PHIAccessLog.AccessType.MODIFY,
                'export': PHIAccessLog.AccessType.EXPORT,
                'share': PHIAccessLog.AccessType.SHARE,
                'print': PHIAccessLog.AccessType.PRINT,
            }
            
            mapped_access_type = access_type_map.get(access_type.lower(), PHIAccessLog.AccessType.VIEW)
            
            # Get patient from medical record
            patient = medication.medical_record.patient if medication.medical_record else None
            
            if not patient:
                logger.error(f"Medication {medication.id} has no associated patient")
                return None
            
            # Create PHI access log
            access_log = PHIAccessLog.objects.create(
                user=user,
                patient=patient,
                access_type=mapped_access_type,
                reason=reason or "Medication record access",
                record_type='medication',
                record_id=str(medication.id),
                additional_data={
                    'medication_name': medication.name,
                    'is_controlled_substance': getattr(medication, 'is_controlled_substance', False),
                    'medical_record_id': str(medication.medical_record.id) if medication.medical_record else None,
                }
            )
            
            # Also log general audit event
            AuditEvent.objects.create(
                user=user,
                event_type=AuditEvent.EventType.ACCESS,
                resource_type='medication',
                resource_id=str(medication.id),
                description=f"{mapped_access_type} access to medication for {patient}"
            )
            
            # Flag special access to controlled substances
            if getattr(medication, 'is_controlled_substance', False):
                record_special_substance_access(user, patient, medication)
            
            return access_log
            
        except Exception as e:
            logger.error(f"Error logging medication access: {str(e)}")
            return None


def record_special_substance_access(user, patient, medication):
    """
    Record special access to controlled substances for additional monitoring.
    
    Args:
        user: User accessing the controlled substance
        patient: Patient the medication is for
        medication: The medication being accessed
    """
    try:
        # Check if user has a role/permission that allows controlled substance access
        has_permission = user.is_staff or user.role in ['admin', 'provider', 'pharmacist']
        
        if not has_permission:
            # Log a security event for unauthorized controlled substance access
            SecurityAuditLog.objects.create(
                user=user,
                event_type=SecurityAuditLog.EventType.PERMISSION_VIOLATION,
                description=f"Unauthorized access to controlled substance {medication.name} for patient {patient}",
                severity=SecurityAuditLog.Severity.MEDIUM,
                additional_data={
                    'medication_id': str(medication.id),
                    'medication_name': medication.name,
                    'patient_id': str(patient.id),
                    'user_role': user.role
                }
            )
    
    except Exception as e:
        logger.error(f"Error recording special substance access: {str(e)}")
