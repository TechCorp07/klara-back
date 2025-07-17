"""
Enhanced audit logging for HIPAA compliance and security monitoring.
Provides comprehensive logging for PHI access, security events, and system activities.
"""
import logging
import json
import os
from datetime import datetime
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http import HttpRequest
from ipware import get_client_ip

# Configure loggers
audit_logger = logging.getLogger('audit')
security_logger = logging.getLogger('security')
hipaa_logger = logging.getLogger('hipaa_audit')
klararety_logger = logging.getLogger('klararety')

User = get_user_model()

class AuditLogger:
    """
    Enhanced audit logging for HIPAA compliance and security monitoring.
    Provides methods for logging different types of events with appropriate context.
    """
    
    @staticmethod
    def log_phi_access(user, resource_type, resource_id, action, request=None, details=None, success=True):
        """
        Log PHI access events for HIPAA compliance.
        
        Args:
            user: User accessing the PHI
            resource_type: Type of resource being accessed (e.g., 'Patient', 'MedicalRecord')
            resource_id: ID of the resource being accessed
            action: Action being performed (e.g., 'view', 'update', 'delete')
            request: HTTP request object (optional)
            details: Additional details about the access (optional)
            success: Whether the access was successful (default: True)
        """
        # Get client IP if request is provided
        ip_address = None
        user_agent = None
        if request and isinstance(request, HttpRequest):
            ip_address, _ = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Build log entry
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'phi_access',
            'user_id': getattr(user, 'id', None),
            'username': getattr(user, 'username', 'system'),
            'user_role': getattr(user, 'role', None),
            'resource_type': resource_type,
            'resource_id': resource_id,
            'action': action,
            'success': success,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details or {}
        }
        
        # Log to both audit and HIPAA audit logs
        audit_logger.info(json.dumps(log_entry))
        hipaa_logger.info(json.dumps(log_entry))
        
        # Return the log entry for potential further processing
        return log_entry
    
    @staticmethod
    def log_security_event(event_type, severity, details, user=None, request=None, related_resource=None):
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event (e.g., 'login_failure', 'permission_denied')
            severity: Severity level ('low', 'medium', 'high', 'critical')
            details: Details about the security event
            user: User associated with the event (optional)
            request: HTTP request object (optional)
            related_resource: Related resource information (optional)
        """
        # Get client IP if request is provided
        ip_address = None
        user_agent = None
        if request and isinstance(request, HttpRequest):
            ip_address, _ = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Build log entry
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'user_id': getattr(user, 'id', None) if user else None,
            'username': getattr(user, 'username', 'system') if user else None,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details,
            'related_resource': related_resource
        }
        
        # Log to security log
        if severity == 'critical':
            security_logger.critical(json.dumps(log_entry))
        elif severity == 'high':
            security_logger.error(json.dumps(log_entry))
        elif severity == 'medium':
            security_logger.warning(json.dumps(log_entry))
        else:
            security_logger.info(json.dumps(log_entry))
        
        # Also log to audit log for comprehensive audit trail
        audit_logger.info(json.dumps(log_entry))
        
        # Return the log entry for potential further processing
        return log_entry
    
    @staticmethod
    def log_system_event(event_type, component, details, success=True):
        """
        Log system-level events.
        
        Args:
            event_type: Type of system event (e.g., 'startup', 'shutdown', 'backup')
            component: System component (e.g., 'database', 'api', 'scheduler')
            details: Details about the system event
            success: Whether the event was successful (default: True)
        """
        # Build log entry
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'event_type': event_type,
            'component': component,
            'success': success,
            'details': details
        }
        
        # Log to klararety log
        if success:
            klararety_logger.info(json.dumps(log_entry))
        else:
            klararety_logger.error(json.dumps(log_entry))
        
        # Also log to audit log for comprehensive audit trail
        audit_logger.info(json.dumps(log_entry))
        
        # Return the log entry for potential further processing
        return log_entry
    
    @staticmethod
    def log_user_activity(user, activity_type, details, request=None, related_resource=None):
        """
        Log user activity events.
        
        Args:
            user: User performing the activity
            activity_type: Type of activity (e.g., 'login', 'logout', 'profile_update')
            details: Details about the activity
            request: HTTP request object (optional)
            related_resource: Related resource information (optional)
        """
        # Get client IP if request is provided
        ip_address = None
        user_agent = None
        if request and isinstance(request, HttpRequest):
            ip_address, _ = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Build log entry
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'user_activity',
            'activity_type': activity_type,
            'user_id': getattr(user, 'id', None),
            'username': getattr(user, 'username', 'system'),
            'user_role': getattr(user, 'role', None),
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details,
            'related_resource': related_resource
        }
        
        # Log to audit log
        audit_logger.info(json.dumps(log_entry))
        
        # Also log to klararety log for general application logging
        klararety_logger.info(json.dumps(log_entry))
        
        # Return the log entry for potential further processing
        return log_entry
    
    @staticmethod
    def log_emergency_access(user, resource_type, resource_id, reason, request=None, details=None):
        """
        Log emergency access to PHI (break-glass procedure).
        
        Args:
            user: User accessing the PHI
            resource_type: Type of resource being accessed (e.g., 'Patient', 'MedicalRecord')
            resource_id: ID of the resource being accessed
            reason: Reason for emergency access
            request: HTTP request object (optional)
            details: Additional details about the access (optional)
        """
        # Get client IP if request is provided
        ip_address = None
        user_agent = None
        if request and isinstance(request, HttpRequest):
            ip_address, _ = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Build log entry
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'emergency_access',
            'user_id': getattr(user, 'id', None),
            'username': getattr(user, 'username', 'system'),
            'user_role': getattr(user, 'role', None),
            'resource_type': resource_type,
            'resource_id': resource_id,
            'reason': reason,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details or {}
        }
        
        # Log to all relevant logs with high visibility
        audit_logger.warning(json.dumps(log_entry))
        hipaa_logger.warning(json.dumps(log_entry))
        security_logger.warning(json.dumps(log_entry))
        
        # Return the log entry for potential further processing
        return log_entry
    
    @staticmethod
    def log_consent_change(user, consent_type, consented, request=None, details=None):
        """
        Log patient consent changes for HIPAA compliance.
        
        Args:
            user: User whose consent is being changed
            consent_type: Type of consent (e.g., 'data_sharing', 'research')
            consented: Boolean indicating whether consent was given or revoked
            request: HTTP request object (optional)
            details: Additional details about the consent change (optional)
        """
        # Get client IP if request is provided
        ip_address = None
        user_agent = None
        if request and isinstance(request, HttpRequest):
            ip_address, _ = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Build log entry
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'event_type': 'consent_change',
            'user_id': getattr(user, 'id', None),
            'username': getattr(user, 'username', 'system'),
            'consent_type': consent_type,
            'consented': consented,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details or {}
        }
        
        # Log to both audit and HIPAA audit logs
        audit_logger.info(json.dumps(log_entry))
        hipaa_logger.info(json.dumps(log_entry))
        
        # Return the log entry for potential further processing
        return log_entry
    
    @staticmethod
    def export_audit_logs(log_type, start_date=None, end_date=None, filters=None, output_format='json'):
        """
        Export audit logs for compliance reporting.
        
        Args:
            log_type: Type of log to export ('audit', 'security', 'hipaa', 'klararety')
            start_date: Start date for log entries (optional)
            end_date: End date for log entries (optional)
            filters: Additional filters to apply (optional)
            output_format: Output format ('json', 'csv')
            
        Returns:
            str: Path to the exported log file
        """
        # Determine log file path based on log type
        log_file_map = {
            'audit': getattr(settings, 'AUDIT_LOG_FILE', 'logs/audit.log'),
            'security': getattr(settings, 'SECURITY_LOG_FILE', 'logs/security.log'),
            'hipaa': getattr(settings, 'HIPAA_AUDIT_LOG_FILE', 'logs/hipaa_audit.log'),
            'klararety': getattr(settings, 'KLARARETY_LOG_FILE', 'logs/klararety.log')
        }
        
        log_file = log_file_map.get(log_type)
        if not log_file or not os.path.exists(log_file):
            raise ValueError(f"Log file for {log_type} not found")
        
        # Create export directory if it doesn't exist
        export_dir = os.path.join(settings.BASE_DIR, 'log_exports')
        os.makedirs(export_dir, exist_ok=True)
        
        # Generate export filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_file = os.path.join(export_dir, f"{log_type}_export_{timestamp}.{output_format}")
        
        # Process and filter log entries
        filtered_entries = []
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    
                    # Apply date filters if provided
                    if start_date or end_date:
                        entry_date = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                        
                        if start_date and entry_date < start_date:
                            continue
                        if end_date and entry_date > end_date:
                            continue
                    
                    # Apply additional filters if provided
                    if filters:
                        skip = False
                        for key, value in filters.items():
                            if entry.get(key) != value:
                                skip = True
                                break
                        if skip:
                            continue
                    
                    filtered_entries.append(entry)
                except (json.JSONDecodeError, ValueError):
                    # Skip invalid log entries
                    continue
        
        # Write filtered entries to export file
        if output_format == 'json':
            with open(export_file, 'w') as f:
                json.dump(filtered_entries, f, indent=2)
        elif output_format == 'csv':
            import csv
            
            # Determine CSV headers from the first entry
            if filtered_entries:
                headers = filtered_entries[0].keys()
                
                with open(export_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(filtered_entries)
        
        return export_file
