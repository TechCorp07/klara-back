import json
import logging
import re
from functools import wraps
from django.utils import timezone
from django.urls import resolve
from django.conf import settings
from .models import AuditEvent, PHIAccessLog, SecurityAuditLog
from .services.security_alerts import SecurityAlertService

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """
    Middleware to log audit events for all API requests.
    
    This middleware tracks all API requests and logs appropriate audit events
    based on the request type and content. It also handles special cases for
    PHI access and security-related events.
    """
    
    def __init__(self, get_response):
        """Initialize middleware with configuration."""
        self.get_response = get_response
        
        # Compile regexes for performance
        self.skip_paths = getattr(settings, 'AUDIT_SKIP_PATHS', [
            r'^/admin/',
            r'^/static/',
            r'^/media/',
            r'^/favicon\.ico$',
            r'^/robots\.txt$',
            r'^/api/docs/',
            r'^/api/schema/'
        ])
        self.skip_re = [re.compile(pattern) for pattern in self.skip_paths]
        
        # Define paths that contain PHI
        self.phi_paths = getattr(settings, 'AUDIT_PHI_PATHS', [
            r'^/api/healthcare/',
            r'^/api/medication/',
            r'^/api/telemedicine/',
            r'^/api/patients/'
        ])
        self.phi_re = [re.compile(pattern) for pattern in self.phi_paths]
        
    def __call__(self, request):
        """Process request and log audit events."""
        # Process request
        response = self.get_response(request)
        
        # Skip audit for excluded paths
        path = request.path
        if any(regex.match(path) for regex in self.skip_re):
            return response
        
        # Log audit event for API requests
        if path.startswith('/api/'):
            self._log_api_request(request, response)
            
            # Log PHI access for PHI-containing paths
            if any(regex.match(path) for regex in self.phi_re):
                self._log_phi_access(request, response)
        
        return response
    
    def _log_api_request(self, request, response):
        """Log API request as audit event."""
        # Skip OPTIONS requests
        if request.method == 'OPTIONS':
            return
        
        # Get resource information
        resource_type, resource_id = self._get_resource_info(request)
        
        # Determine event type
        event_type = self._get_event_type(request.method)
        
        # Get request body for specific event types
        body_data = {}
        if event_type in [AuditEvent.EventType.CREATE, AuditEvent.EventType.UPDATE]:
            # Safely parse request body
            body_data = self._get_sanitized_request_body(request)
                
        # Create audit event
        AuditEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            description=f"{request.method} {request.path}",
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'status_code': response.status_code,
                'request_body': body_data,
                'query_params': dict(request.GET),
                'headers': self._get_sanitized_headers(request)
            }
        )
        
        # Log security events for authentication failures
        if resource_type == 'auth' and response.status_code in [401, 403]:
            self._log_security_event(request, response)
    
    def _log_phi_access(self, request, response):
        """Log PHI access event."""
        # Skip if we couldn't identify a patient
        patient_id = self._get_patient_id(request)
        if not patient_id:
            return
            
        # Get patient user if possible
        patient = None
        if patient_id:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                patient = User.objects.get(id=patient_id)
            except (User.DoesNotExist, ValueError):
                pass
                
        # Determine access type based on method
        access_type = self._get_phi_access_type(request.method)
        
        # Determine record type and ID
        record_type, record_id = self._get_resource_info(request)
        
        # Get access reason from request headers or parameters
        reason = (
            request.META.get('HTTP_X_ACCESS_REASON', '') or
            request.GET.get('access_reason', '') or
            'No reason provided'
        )
        
        # Create PHI access log
        PHIAccessLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            patient=patient,
            access_type=access_type,
            reason=reason,
            record_type=record_type,
            record_id=record_id,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'status_code': response.status_code,
                'query_params': dict(request.GET),
                'url': request.path,
                'method': request.method
            }
        )
        
        # Check for missing access reason and log security event if necessary
        if not reason or reason == 'No reason provided':
            SecurityAlertService.create_security_alert(
                event_type=SecurityAuditLog.EventType.PERMISSION_VIOLATION,
                description=f"PHI access without reason: {request.method} {request.path}",
                severity=SecurityAuditLog.Severity.MEDIUM,
                user=request.user if request.user.is_authenticated else None,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                additional_data={
                    'patient_id': str(patient_id) if patient_id else None,
                    'record_type': record_type,
                    'record_id': record_id
                }
            )
    
    def _log_security_event(self, request, response):
        """Log security-related event."""
        # Determine security event type
        if 'login' in request.path.lower():
            event_type = SecurityAuditLog.EventType.LOGIN_FAILED
            severity = SecurityAuditLog.Severity.MEDIUM
        elif response.status_code == 403:
            event_type = SecurityAuditLog.EventType.PERMISSION_VIOLATION
            severity = SecurityAuditLog.Severity.MEDIUM
        else:
            event_type = SecurityAuditLog.EventType.SUSPICIOUS_ACCESS
            severity = SecurityAuditLog.Severity.LOW
            
        # Create security audit log
        SecurityAuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            event_type=event_type,
            description=f"Security event: {request.method} {request.path} (status: {response.status_code})",
            severity=severity,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'status_code': response.status_code,
                'query_params': dict(request.GET),
                'url': request.path,
                'method': request.method,
                'username': getattr(request.user, 'username', None)
            }
        )
    
    def _get_event_type(self, method):
        """Get event type based on HTTP method."""
        if method == 'GET':
            return AuditEvent.EventType.READ
        elif method == 'POST':
            return AuditEvent.EventType.CREATE
        elif method in ['PUT', 'PATCH']:
            return AuditEvent.EventType.UPDATE
        elif method == 'DELETE':
            return AuditEvent.EventType.DELETE
        return AuditEvent.EventType.ACCESS
    
    def _get_phi_access_type(self, method):
        """Get PHI access type based on HTTP method."""
        if method == 'GET':
            return PHIAccessLog.AccessType.VIEW
        elif method == 'POST':
            return PHIAccessLog.AccessType.MODIFY
        elif method in ['PUT', 'PATCH']:
            return PHIAccessLog.AccessType.MODIFY
        elif method == 'DELETE':
            return PHIAccessLog.AccessType.MODIFY
        return PHIAccessLog.AccessType.VIEW
    
    def _get_resource_info(self, request):
        """Get resource type and ID from path."""
        parts = request.path.strip('/').split('/')
        
        if len(parts) >= 2 and parts[0] == 'api':
            resource_type = parts[1]
            
            # Look for ID in path
            resource_id = ''
            if len(parts) >= 3:
                if parts[2].isdigit() or self._is_uuid(parts[2]):
                    resource_id = parts[2]
                elif len(parts) >= 4 and (parts[3].isdigit() or self._is_uuid(parts[3])):
                    resource_id = parts[3]
                    
            return resource_type, resource_id
        
        return 'unknown', ''
    
    def _get_patient_id(self, request):
        """Extract patient ID from request."""
        # Try to get from URL path
        parts = request.path.strip('/').split('/')
        
        # Check if path contains 'patients/{id}'
        for i, part in enumerate(parts):
            if part == 'patients' and i + 1 < len(parts):
                if parts[i+1].isdigit() or self._is_uuid(parts[i+1]):
                    return parts[i+1]
        
        # Try to get from query parameters
        patient_id = request.GET.get('patient_id') or request.GET.get('patient')
        if patient_id:
            return patient_id
            
        # Try to get from request body - safely handle already read body
        try:
            body_data = self._get_sanitized_request_body(request)
            if body_data and isinstance(body_data, dict):
                patient_id = body_data.get('patient_id') or body_data.get('patient')
                if patient_id:
                    return str(patient_id)
        except Exception as e:
            logger.debug(f"Error extracting patient ID from request body: {str(e)}")
                
        return None
    
    def _get_sanitized_request_body(self, request):
        """Safely get request body data."""
        try:
            # If it's a POST request, try to get from POST data first
            if request.method == 'POST' and request.content_type == 'application/x-www-form-urlencoded':
                body_data = dict(request.POST)
                
                # Remove sensitive data
                for sensitive_field in ['password', 'token', 'secret']:
                    if sensitive_field in body_data:
                        body_data[sensitive_field] = '********'
                return body_data
            
            # For JSON data, try to parse the body
            if hasattr(request, 'body') and request.body:
                try:
                    body_data = json.loads(request.body.decode('utf-8'))
                    if isinstance(body_data, dict):
                        # Remove sensitive data
                        for sensitive_field in ['password', 'token', 'secret']:
                            if sensitive_field in body_data:
                                body_data[sensitive_field] = '********'
                    return body_data
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return {'error': 'Could not decode request body'}
            
            return {}
        except Exception as e:
            logger.debug(f"Error parsing request body: {str(e)}")
            return {'error': 'Error accessing request body'}
    
    def _get_sanitized_headers(self, request):
        """Get sanitized request headers."""
        headers = {}
        for key, value in request.META.items():
            if key.startswith('HTTP_') and key not in ['HTTP_AUTHORIZATION', 'HTTP_COOKIE']:
                header_name = key[5:].lower().replace('_', '-')
                headers[header_name] = value
        return headers
    
    def _is_uuid(self, value):
        """Check if a string appears to be a UUID."""
        if not value:
            return False
        
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(value))
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class HealthcareAuditMiddleware:
    """
    Extended middleware specifically for healthcare endpoints.
    Enhances the core AuditMiddleware with healthcare-specific context.
    """
    
    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response
        
    def __call__(self, request):
        """Process request and log healthcare-specific audit events."""
        # Process request
        response = self.get_response(request)
        
        # Only process healthcare-related endpoints
        if not request.path.startswith('/api/healthcare/') and not request.path.startswith('/api/telemedicine/'):
            return response
            
        # Skip for unauthenticated users
        if not request.user.is_authenticated:
            return response
            
        try:
            self._log_healthcare_access(request, response)
        except Exception as e:
            # Don't let errors in extended logging block the response
            logger.error(f"Error in HealthcareAuditMiddleware: {str(e)}")
            
        return response
    
    def _log_healthcare_access(self, request, response):
        """Log healthcare-specific access with detailed context."""
        try:
            # Import models only when needed
            from healthcare.models import MedicalRecord
            from audit.models import PHIAccessLog
            
            # Determine healthcare resource type and ID
            resource_type, resource_id = self._extract_healthcare_resource(request)
            
            # Determine patient ID - check query params, body, and path
            patient_id = self._extract_patient_id(request)
            
            # If no patient ID found, try to infer from resource
            if not patient_id and resource_type == 'medical-records' and resource_id:
                try:
                    medical_record = MedicalRecord.objects.get(id=resource_id)
                    patient_id = str(medical_record.patient.id)
                except MedicalRecord.DoesNotExist:
                    pass
            
            # Skip if we couldn't identify a patient
            if not patient_id:
                return response
                
            # Get patient user if possible
            from django.contrib.auth import get_user_model
            User = get_user_model()
            patient = None
            try:
                patient = User.objects.get(id=patient_id)
            except User.DoesNotExist:
                pass
                
            # Get access reason with fallbacks
            reason = self._get_access_reason(request)
            
            # Determine access type based on context
            access_type, record_type = self._determine_access_details(request)
            
            # Create PHI access log
            PHIAccessLog.objects.create(
                user=request.user,
                patient=patient,
                access_type=access_type,
                reason=reason,
                record_type=record_type or resource_type,
                record_id=resource_id or '',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                additional_data={
                    'path': request.path,
                    'method': request.method,
                    'status_code': response.status_code,
                    'content_type': response.get('Content-Type', ''),
                    'response_size': len(response.content) if hasattr(response, 'content') else 0,
                }
            )
            
            # Also log general audit event
            from audit.models import AuditEvent
            AuditEvent.objects.create(
                user=request.user,
                event_type=AuditEvent.EventType.ACCESS if access_type == PHIAccessLog.AccessType.VIEW else AuditEvent.EventType.UPDATE,
                resource_type=record_type or resource_type,
                resource_id=resource_id or '',
                description=f"Healthcare {access_type} access to {record_type or resource_type} for patient {patient_id}"
            )
            
        except Exception as e:
            logger.error(f"Error in healthcare access logging: {str(e)}")
    
    def _extract_healthcare_resource(self, request):
        """Extract resource type and ID from healthcare requests."""
        parts = request.path.strip('/').split('/')
        
        if len(parts) < 3:
            return 'healthcare', ''
            
        resource_type = parts[2]  # e.g., 'medical-records'
        resource_id = parts[3] if len(parts) > 3 and self._is_valid_id(parts[3]) else ''
        
        return resource_type, resource_id
    
    def _extract_patient_id(self, request):
        """Extract patient ID from request with multiple strategies."""
        # Check query parameters
        patient_id = request.GET.get('patient_id') or request.GET.get('patient')
        if patient_id:
            return patient_id
            
        # Check path components
        parts = request.path.strip('/').split('/')
        for i, part in enumerate(parts):
            if part in ['patients', 'patient'] and i + 1 < len(parts):
                if self._is_valid_id(parts[i+1]):
                    return parts[i+1]
        
        # Check request body for patient_id
        if hasattr(request, 'data') and isinstance(request.data, dict):
            body_patient = request.data.get('patient_id') or request.data.get('patient')
            if body_patient:
                return str(body_patient)
                
        # Check POST data
        post_patient = request.POST.get('patient_id') or request.POST.get('patient')
        if post_patient:
            return post_patient
            
        return None
    
    def _get_access_reason(self, request):
        """Get the reason for accessing healthcare data with fallbacks."""
        reason = (
            request.META.get('HTTP_X_ACCESS_REASON', '') or
            request.GET.get('access_reason', '') or
            request.POST.get('access_reason', '')
        )
        
        # If no specific reason provided, use a context-based default
        if not reason:
            if 'telemedicine' in request.path:
                reason = 'Telemedicine consultation'
            elif 'medical-records' in request.path:
                reason = 'Medical record access'
            elif 'medication' in request.path:
                reason = 'Medication management'
            elif 'lab-results' in request.path:
                reason = 'Lab results review'
            else:
                reason = 'Healthcare data access'
                
        return reason
    
    def _determine_access_details(self, request):
        """Determine access type and record type based on request context."""
        from audit.models import PHIAccessLog
        
        if 'telemedicine' in request.path:
            access_type = PHIAccessLog.AccessType.VIEW if request.method == 'GET' else PHIAccessLog.AccessType.MODIFY
            record_type = 'telemedicine'
        elif 'lab-results' in request.path or 'vital-signs' in request.path:
            access_type = PHIAccessLog.AccessType.VIEW if request.method == 'GET' else PHIAccessLog.AccessType.MODIFY
            record_type = 'clinical_data'
        elif 'medication' in request.path:
            access_type = PHIAccessLog.AccessType.VIEW if request.method == 'GET' else PHIAccessLog.AccessType.MODIFY
            record_type = 'medication'
        else:
            access_type = PHIAccessLog.AccessType.VIEW if request.method == 'GET' else PHIAccessLog.AccessType.MODIFY
            record_type = None  # Use the extracted resource type
            
        # Check for export actions
        if 'export' in request.path or request.GET.get('export'):
            access_type = PHIAccessLog.AccessType.EXPORT
            
        # Check for share actions
        if 'share' in request.path or request.GET.get('share'):
            access_type = PHIAccessLog.AccessType.SHARE
            
        return access_type, record_type
    
    def _is_valid_id(self, value):
        """Check if a value is a valid ID (numeric or UUID)."""
        if not value:
            return False
            
        # Check if numeric
        if value.isdigit():
            return True
            
        # Check if UUID
        import re
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(value))
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
