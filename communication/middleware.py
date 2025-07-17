import re
import logging
from django.utils import timezone
from django.urls import resolve
from audit.models import PHIAccessLog

logger = logging.getLogger(__name__)

class MessageAccessMiddleware:
    """
    Middleware to track access to messages and conversations for HIPAA compliance.
    Logs access to PHI (Protected Health Information) in message content.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Skip middleware for admin/staff or non-authenticated users
        if not request.user.is_authenticated or request.user.is_staff:
            return self.get_response(request)
            
        # Skip for non-communication URLs
        if not request.path.startswith('/api/communication/'):
            return self.get_response(request)
            
        # Process the request
        response = self.get_response(request)
        
        # Log PHI access for specific endpoints
        self._log_phi_access_if_needed(request, response)
            
        # Return the response
        return response
    
    def _log_phi_access_if_needed(self, request, response):
        """Log PHI access for specific endpoints that may contain health data."""
        try:
            # Skip for failed requests
            if response.status_code >= 400:
                return
                
            # Only process GET requests
            if request.method != 'GET':
                return
                
            # Extract endpoint information
            resolved = resolve(request.path)
            
            # Track access to conversations and messages which may contain PHI
            if (resolved.url_name == 'conversation-detail' or 
                resolved.url_name == 'conversation-messages' or
                resolved.url_name == 'message-detail'):
                
                # Extract the ID from the URL path
                resource_id = None
                match = re.search(r'/(\d+)', request.path)
                if match:
                    resource_id = match.group(1)
                
                # Determine if this is a conversation or message access
                if 'messages' in request.path:
                    resource_type = 'message'
                else:
                    resource_type = 'conversation'
                
                # Log the access
                self._create_phi_access_log(
                    request=request,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    reason='Viewing message content'
                )
        
        except Exception as e:
            logger.error(f"Error in MessageAccessMiddleware: {str(e)}")
    
    def _create_phi_access_log(self, request, resource_id, resource_type, reason):
        """Create a PHI access log entry."""
        try:
            # Get the client IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR', '')
            
            # Create the log entry
            PHIAccessLog.objects.create(
                user=request.user,
                access_time=timezone.now(),
                resource_type=resource_type,
                resource_id=resource_id,
                reason=reason,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_path=request.path
            )
            
        except Exception as e:
            logger.error(f"Error creating PHI access log: {str(e)}")
