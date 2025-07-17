import logging
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import get_user_model

from ..models import PHIAccessLog, AuditEvent

User = get_user_model()
logger = logging.getLogger(__name__)

class MedicationIntegrationException(Exception):
    """Exception for medication integration errors."""
    pass


def log_prescription_access(user, patient_id, prescription_id, access_type, reason=None):
    """
    Log access to a prescription for HIPAA compliance.
    
    Args:
        user: User accessing the prescription
        patient_id: ID of the patient
        prescription_id: ID of the prescription
        access_type: Type of access (view, modify, export, etc.)
        reason: Reason for accessing the prescription
    
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
            record_type='prescription',
            record_id=str(prescription_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='prescription',
            resource_id=str(prescription_id),
            description=f"{access_type.title()} access to prescription for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging prescription access: {str(e)}")
        raise MedicationIntegrationException(f"Error logging prescription access: {str(e)}")


def log_medication_adherence_access(user, patient_id, medication_id, access_type, reason=None):
    """
    Log access to medication adherence data for HIPAA compliance.
    
    Args:
        user: User accessing the adherence data
        patient_id: ID of the patient
        medication_id: ID of the medication
        access_type: Type of access (view, modify, export, etc.)
        reason: Reason for accessing the adherence data
    
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
            record_type='medication_adherence',
            record_id=str(medication_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='medication_adherence',
            resource_id=str(medication_id),
            description=f"{access_type.title()} access to medication adherence data for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging medication adherence access: {str(e)}")
        raise MedicationIntegrationException(f"Error logging medication adherence access: {str(e)}")


def log_medication_reminder_access(user, patient_id, reminder_id, access_type, reason=None):
    """
    Log access to a medication reminder for HIPAA compliance.
    
    Args:
        user: User accessing the reminder
        patient_id: ID of the patient
        reminder_id: ID of the reminder
        access_type: Type of access (view, modify, export, etc.)
        reason: Reason for accessing the reminder
    
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
            record_type='medication_reminder',
            record_id=str(reminder_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='medication_reminder',
            resource_id=str(reminder_id),
            description=f"{access_type.title()} access to medication reminder for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging medication reminder access: {str(e)}")
        raise MedicationIntegrationException(f"Error logging medication reminder access: {str(e)}")


def log_medication_side_effect_access(user, patient_id, side_effect_id, access_type, reason=None):
    """
    Log access to medication side effect data for HIPAA compliance.
    
    Args:
        user: User accessing the side effect data
        patient_id: ID of the patient
        side_effect_id: ID of the side effect record
        access_type: Type of access (view, modify, export, etc.)
        reason: Reason for accessing the side effect data
    
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
            record_type='medication_side_effect',
            record_id=str(side_effect_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='medication_side_effect',
            resource_id=str(side_effect_id),
            description=f"{access_type.title()} access to medication side effect data for patient {patient_id}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging medication side effect access: {str(e)}")
        raise MedicationIntegrationException(f"Error logging medication side effect access: {str(e)}")


def log_pharmacist_prescription_review(user, patient_id, prescription_id, review_status, reason=None):
    """
    Log a pharmacist's review of a prescription for HIPAA compliance.
    
    Args:
        user: Pharmacist reviewing the prescription
        patient_id: ID of the patient
        prescription_id: ID of the prescription
        review_status: Result of the review (approved, denied, etc.)
        reason: Reason for the review decision
    
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
            access_type=PHIAccessLog.AccessType.MODIFY,
            reason=reason or f"Prescription review: {review_status}",
            record_type='prescription_review',
            record_id=str(prescription_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id,
                'review_status': review_status
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.UPDATE,
            resource_type='prescription',
            resource_id=str(prescription_id),
            description=f"Pharmacist reviewed prescription for patient {patient_id}: {review_status}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging prescription review: {str(e)}")
        raise MedicationIntegrationException(f"Error logging prescription review: {str(e)}")


def log_e_prescription_transmission(user, patient_id, prescription_id, pharmacy_id, status, reason=None):
    """
    Log the electronic transmission of a prescription for HIPAA compliance.
    
    Args:
        user: User sending the prescription
        patient_id: ID of the patient
        prescription_id: ID of the prescription
        pharmacy_id: ID of the pharmacy
        status: Transmission status (sent, failed, etc.)
        reason: Reason for transmission
    
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
            access_type=PHIAccessLog.AccessType.SHARE,
            reason=reason or f"E-prescription transmission to pharmacy",
            record_type='e_prescription',
            record_id=str(prescription_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id,
                'pharmacy_id': pharmacy_id,
                'transmission_status': status
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.SHARE,
            resource_type='prescription',
            resource_id=str(prescription_id),
            description=f"E-prescription for patient {patient_id} transmitted to pharmacy {pharmacy_id}: {status}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging e-prescription transmission: {str(e)}")
        raise MedicationIntegrationException(f"Error logging e-prescription transmission: {str(e)}")


def log_medication_data_export(user, patient_ids, medication_ids, reason=None):
    """
    Log a bulk export of medication data for HIPAA compliance.
    
    Args:
        user: User performing the export
        patient_ids: List of patient IDs included in the export
        medication_ids: List of medication IDs included in the export
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
                resource_type='medication',
                resource_id='bulk',
                description=f"Bulk export of medication data for {len(patient_ids)} patients, {len(medication_ids)} medications"
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
                    reason=reason or "Bulk medication data export",
                    record_type='medication_export',
                    record_id='bulk_export',
                    additional_data={
                        'timestamp': timezone.now().isoformat(),
                        'access_context': 'bulk_export',
                        'patient_id': patient_id,
                        'medication_count': len(medication_ids),
                        'export_batch_size': len(patient_ids)
                    }
                )
                logs.append(log)
        
        return logs
    
    except Exception as e:
        logger.error(f"Error logging medication data export: {str(e)}")
        raise MedicationIntegrationException(f"Error logging medication data export: {str(e)}")


def log_drug_interaction_check(user, patient_id, medication_ids, interaction_found, reason=None):
    """
    Log a drug interaction check for HIPAA compliance.
    
    Args:
        user: User performing the interaction check
        patient_id: ID of the patient
        medication_ids: List of medication IDs checked for interactions
        interaction_found: Whether an interaction was found
        reason: Reason for the interaction check
    
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
            access_type=PHIAccessLog.AccessType.VIEW,
            reason=reason or "Drug interaction check",
            record_type='drug_interaction',
            record_id=f"interaction_check_{timezone.now().strftime('%Y%m%d%H%M%S')}",
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id,
                'medication_ids': medication_ids,
                'interaction_found': interaction_found
            }
        )
        
        # Also log general audit event
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='drug_interaction',
            resource_id=f"interaction_check_{timezone.now().strftime('%Y%m%d%H%M%S')}",
            description=f"Drug interaction check for patient {patient_id}: {'Interaction found' if interaction_found else 'No interaction found'}"
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging drug interaction check: {str(e)}")
        raise MedicationIntegrationException(f"Error logging drug interaction check: {str(e)}")


def log_orphan_drug_access(user, patient_id, medication_id, access_type, reason=None):
    """
    Log access to orphan drug information for HIPAA compliance.
    Orphan drugs require special logging due to their rare disease designation.
    
    Args:
        user: User accessing the orphan drug data
        patient_id: ID of the patient
        medication_id: ID of the orphan drug medication
        access_type: Type of access (view, modify, export, etc.)
        reason: Reason for accessing the orphan drug data
    
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
        
        # Create the PHI access log with special orphan drug designation
        access_log = PHIAccessLog.objects.create(
            user=user,
            patient=patient,
            access_type=access_type,
            reason=reason or "Orphan drug access",
            record_type='orphan_drug',
            record_id=str(medication_id),
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id,
                'medication_type': 'orphan_drug',
                'special_category': True
            }
        )
        
        # Also log general audit event with emphasis on orphan drug status
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='orphan_drug',
            resource_id=str(medication_id),
            description=f"{access_type.title()} access to orphan drug for patient {patient_id}"
        )
        
        # Log a separate security audit event for orphan drugs since they're more sensitive
        from ..models import SecurityAuditLog
        
        SecurityAuditLog.objects.create(
            user=user,
            event_type=SecurityAuditLog.EventType.PERMISSION_VIOLATION if not reason else 'special_access',
            description=f"Orphan drug access for patient {patient_id}: {reason or 'No reason provided'}",
            severity=SecurityAuditLog.Severity.MEDIUM,
            additional_data={
                'timestamp': timezone.now().isoformat(),
                'access_context': 'medication_api',
                'patient_id': patient_id,
                'medication_id': medication_id,
                'orphan_drug': True
            }
        )
        
        return access_log
    
    except Exception as e:
        logger.error(f"Error logging orphan drug access: {str(e)}")
        raise MedicationIntegrationException(f"Error logging orphan drug access: {str(e)}")
