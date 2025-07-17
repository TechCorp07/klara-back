import logging
from django.utils import timezone
from django.db import transaction
from django.conf import settings
from django.contrib.auth import get_user_model

from ..models import PHIAccessLog, AuditEvent

User = get_user_model()
logger = logging.getLogger(__name__)

class HealthcareIntegrationException(Exception):
    """Exception for healthcare integration errors."""
    pass


def log_medical_record_access(user, patient_id, medical_record_id, access_type, reason=None):
    """
    Log access to a medical record for HIPAA compliance.
    
    Args:
        user: User accessing the record
        patient_id: ID of the patient
        medical_record_id: ID of the medical record
        access_type: Type of access (view, modify, export, etc.)
        reason: Reason for accessing the record
    
    Returns:
        PHIAccessLog: Created log entry
    """
    try:
        # Get patient info
        try:
            patient = User.objects.get(id=patient_id)
        except User.DoesNotExist:
            patient = None
            logger.warning(f"Patient with ID {patient_id} not found for PHI access log")
        
        # Create the PHI access log
        access_log = PHIAccessLog.objects.create(
            user=user,
            patient=patient,
            access_type=access_type,
            reason=reason or "Not specified",
            record_type='medical_record',
            record_id=str(medical_record_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'healthcare_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='medical_record',
            resource_id=str(medical_record_id),
            description=f"{access_type.title()} access to medical record for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging medical record access: {str(e)}")
        raise HealthcareIntegrationException(f"Error logging medical record access: {str(e)}")


def log_condition_access(user, patient_id, condition_id, access_type, reason=None):
    """
    Log access to a patient condition for HIPAA compliance.
    
    Args:
        user: User accessing the condition
        patient_id: ID of the patient
        condition_id: ID of the condition
        access_type: Type of access (view, modify, etc.)
        reason: Reason for accessing the condition
    
    Returns:
        PHIAccessLog: Created log entry
    """
    try:
        # Get patient info
        try:
            patient = User.objects.get(id=patient_id)
        except User.DoesNotExist:
            patient = None
            logger.warning(f"Patient with ID {patient_id} not found for PHI access log")
        
        # Create the PHI access log
        access_log = PHIAccessLog.objects.create(
            user=user,
            patient=patient,
            access_type=access_type,
            reason=reason or "Not specified",
            record_type='condition',
            record_id=str(condition_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'healthcare_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='condition',
            resource_id=str(condition_id),
            description=f"{access_type.title()} access to condition for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging condition access: {str(e)}")
        raise HealthcareIntegrationException(f"Error logging condition access: {str(e)}")


def log_medication_access(user, patient_id, medication_id, access_type, reason=None):
    """
    Log access to a patient medication for HIPAA compliance.
    
    Args:
        user: User accessing the medication
        patient_id: ID of the patient
        medication_id: ID of the medication
        access_type: Type of access (view, modify, etc.)
        reason: Reason for accessing the medication
    
    Returns:
        PHIAccessLog: Created log entry
    """
    try:
        # Get patient info
        try:
            patient = User.objects.get(id=patient_id)
        except User.DoesNotExist:
            patient = None
            logger.warning(f"Patient with ID {patient_id} not found for PHI access log")
        
        # Create the PHI access log
        access_log = PHIAccessLog.objects.create(
            user=user,
            patient=patient,
            access_type=access_type,
            reason=reason or "Not specified",
            record_type='medication',
            record_id=str(medication_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'healthcare_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='medication',
            resource_id=str(medication_id),
            description=f"{access_type.title()} access to medication for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging medication access: {str(e)}")
        raise HealthcareIntegrationException(f"Error logging medication access: {str(e)}")


def log_lab_result_access(user, patient_id, lab_result_id, access_type, reason=None):
    """
    Log access to a lab result for HIPAA compliance.
    
    Args:
        user: User accessing the lab result
        patient_id: ID of the patient
        lab_result_id: ID of the lab result
        access_type: Type of access (view, modify, etc.)
        reason: Reason for accessing the lab result
    
    Returns:
        PHIAccessLog: Created log entry
    """
    try:
        # Get patient info
        try:
            patient = User.objects.get(id=patient_id)
        except User.DoesNotExist:
            patient = None
            logger.warning(f"Patient with ID {patient_id} not found for PHI access log")
        
        # Create the PHI access log
        access_log = PHIAccessLog.objects.create(
            user=user,
            patient=patient,
            access_type=access_type,
            reason=reason or "Not specified",
            record_type='lab_result',
            record_id=str(lab_result_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'healthcare_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='lab_result',
            resource_id=str(lab_result_id),
            description=f"{access_type.title()} access to lab result for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging lab result access: {str(e)}")
        raise HealthcareIntegrationException(f"Error logging lab result access: {str(e)}")


def log_bulk_export(user, patient_ids, record_type, reason=None):
    """
    Log a bulk export of patient data for HIPAA compliance.
    
    Args:
        user: User performing the export
        patient_ids: List of patient IDs included in the export
        record_type: Type of records being exported
        reason: Reason for the export
    
    Returns:
        list: List of created PHIAccessLog entries
    """
    try:
        logs = []
        
        # Start a transaction for all log entries
        with transaction.atomic():
            # Create a general audit event for the bulk export
            AuditEvent.objects.create(
                user=user,
                event_type=AuditEvent.EventType.EXPORT,
                resource_type=record_type,
                resource_id='bulk',
                description=f"Bulk export of {record_type} data for {len(patient_ids)} patients"
            )
            
            # Create individual PHI access logs for each patient
            for patient_id in patient_ids:
                try:
                    patient = User.objects.get(id=patient_id)
                except User.DoesNotExist:
                    patient = None
                    logger.warning(f"Patient with ID {patient_id} not found for PHI access log")
                
                log = PHIAccessLog.objects.create(
                    user=user,
                    patient=patient,
                    access_type=PHIAccessLog.AccessType.EXPORT,
                    reason=reason or "Bulk export",
                    record_type=record_type,
                    record_id='bulk_export',
                    additional_data={
                        'timestamp': timezone.now().isoformat(),
                        'access_context': 'bulk_export',
                        'patient_id': patient_id,
                        'export_batch_size': len(patient_ids)
                    }
                )
                logs.append(log)
        
        return logs
    
    except Exception as e:
        logger.error(f"Error logging bulk export: {str(e)}")
        raise HealthcareIntegrationException(f"Error logging bulk export: {str(e)}")
