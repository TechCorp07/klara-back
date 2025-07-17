import logging
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

def log_phi_access(user, patient, access_type, reason, record_type, record_id, 
                   additional_data=None, ip_address=None, user_agent=None):
    """
    Centralized function to log PHI access and create associated audit event.
    
    Args:
        user: User accessing the PHI
        patient: Patient whose PHI is being accessed
        access_type: Type of access (PHIAccessLog.AccessType)
        reason: Reason for accessing the PHI
        record_type: Type of record being accessed
        record_id: ID of the record being accessed
        additional_data: Additional data to log
        ip_address: IP address of the user
        user_agent: User agent of the client
        
    Returns:
        PHIAccessLog: The created access log
    """
    from .models import PHIAccessLog, AuditEvent
    
    # Default values
    if additional_data is None:
        additional_data = {}
        
    # Ensure we have a valid reason
    if not reason:
        reason = "No reason provided"
        
    # Map PHIAccessLog.AccessType to AuditEvent.EventType
    access_to_event_type = {
        PHIAccessLog.AccessType.VIEW: AuditEvent.EventType.READ,
        PHIAccessLog.AccessType.MODIFY: AuditEvent.EventType.UPDATE,
        PHIAccessLog.AccessType.EXPORT: AuditEvent.EventType.EXPORT,
        PHIAccessLog.AccessType.SHARE: AuditEvent.EventType.SHARE,
        PHIAccessLog.AccessType.PRINT: AuditEvent.EventType.ACCESS,
    }
    
    # Determine event type for audit event
    event_type = access_to_event_type.get(access_type, AuditEvent.EventType.ACCESS)
    
    # Create PHI access log
    access_log = PHIAccessLog.objects.create(
        user=user,
        patient=patient,
        access_type=access_type,
        reason=reason,
        record_type=record_type,
        record_id=str(record_id),
        ip_address=ip_address,
        user_agent=user_agent,
        additional_data=additional_data
    )
    
    # Create audit event
    patient_desc = patient.username if patient else "Unknown patient"
    AuditEvent.objects.create(
        user=user,
        event_type=event_type,
        resource_type=record_type,
        resource_id=str(record_id),
        description=f"{access_type} access to {record_type} for {patient_desc}",
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return access_log

def log_security_resolution(security_log, resolved_by):
    """
    Log resolution of a security incident.
    
    Args:
        security_log: The SecurityAuditLog that was resolved
        resolved_by: User who resolved the incident
    """
    from .models import AuditEvent
    
    AuditEvent.objects.create(
        user=resolved_by,
        event_type=AuditEvent.EventType.UPDATE,
        resource_type='security_alert',
        resource_id=str(security_log.id),
        description=f"Resolved security alert: {security_log.get_event_type_display()}",
        additional_data={
            'severity': security_log.severity,
            'original_timestamp': security_log.timestamp.isoformat() if security_log.timestamp else None,
            'resolution_notes': security_log.resolution_notes
        }
    )

def get_patient(patient_id):
    """
    Get a patient User object by ID with proper error handling.
    
    Args:
        patient_id: ID of the patient
        
    Returns:
        User: Patient user or None if not found
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    try:
        return User.objects.get(id=patient_id)
    except (User.DoesNotExist, ValueError):
        logger.warning(f"Patient with ID {patient_id} not found")
        return None

def get_setting(name, default=None):
    """
    Get a setting with a default value if not found.
    
    Args:
        name: Name of the setting
        default: Default value if setting not found
        
    Returns:
        Setting value or default
    """
    return getattr(settings, name, default)

def anonymize_ip(ip_address):
    """
    Anonymize an IP address by removing the last octet or part.
    
    Args:
        ip_address: IP address to anonymize
        
    Returns:
        str: Anonymized IP address
    """
    if not ip_address:
        return None
        
    # Check if IPv4 or IPv6
    if ':' in ip_address:
        # IPv6 - remove last 64 bits
        parts = ip_address.rsplit(':', 4)
        if len(parts) > 1:
            return f"{parts[0]}:0:0:0:0"
        return ip_address
    else:
        # IPv4 - remove last octet
        parts = ip_address.rsplit('.', 1)
        if len(parts) > 1:
            return f"{parts[0]}.0"
        return ip_address

def sanitize_request_data(request_data):
    """
    Sanitize sensitive data from request.
    
    Args:
        request_data: Dictionary of request data
        
    Returns:
        dict: Sanitized data with sensitive fields masked
    """
    if not request_data:
        return {}
        
    # List of sensitive fields to mask
    sensitive_fields = [
        'password', 'token', 'authorization', 'auth', 'key', 'secret', 'credential',
        'credit_card', 'card_number', 'cvv', 'ssn', 'social_security', 'dob', 
        'date_of_birth', 'address', 'zip_code', 'postal_code'
    ]
        
    sanitized = {}
    
    # Copy and sanitize data
    if isinstance(request_data, dict):
        for key, value in request_data.items():
            # Check if key is sensitive
            is_sensitive = any(field in key.lower() for field in sensitive_fields)
            
            if is_sensitive:
                sanitized[key] = '********'
            elif isinstance(value, dict):
                # Recursively sanitize nested dictionaries
                sanitized[key] = sanitize_request_data(value)
            elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
                # Sanitize list of dictionaries
                sanitized[key] = [sanitize_request_data(item) for item in value]
            else:
                sanitized[key] = value
    else:
        # Return as-is if not a dictionary
        return request_data
            
    return sanitized

def parse_date(date_str, default=None):
    """
    Parse date string with multiple format support.
    
    Args:
        date_str: Date string to parse
        default: Default value if parsing fails
        
    Returns:
        datetime: Parsed datetime or default
    """
    from datetime import datetime
    
    if not date_str:
        return default
        
    # Try multiple formats
    formats = [
        '%Y-%m-%d',           # ISO format
        '%Y-%m-%dT%H:%M:%S',  # ISO with time
        '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO with time and microseconds
        '%m/%d/%Y',           # US format
        '%d/%m/%Y',           # European format
        '%b %d, %Y',          # Month name format
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
            
    logger.warning(f"Could not parse date: {date_str}")
    return default
