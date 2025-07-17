import logging
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from ..models import SecurityAuditLog

logger = logging.getLogger(__name__)

class EmergencyAccessView(APIView):
    """
    View to handle emergency access to PHI ("break-glass" procedure).
    
    In emergency situations where normal access controls would delay critical care,
    this endpoint allows authorized providers to bypass standard PHI access controls.
    All such accesses are heavily audited for HIPAA compliance.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        """
        Activate emergency access procedure for a user.
        
        Required parameters:
        - reason: Text explanation of the emergency situation
        
        Optional parameters:
        - patient_id: Specific patient ID for the emergency (if known)
        - duration_minutes: How long emergency access is needed (default: 30)
        
        Returns:
        - Emergency access token
        - Expiration time
        """
        # Verify emergency access is enabled
        if not getattr(settings, 'EMERGENCY_ACCESS_ENABLED', True):
            return Response(
                {'error': 'Emergency access is not enabled on this system'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get required parameters
        reason = request.data.get('reason')
        if not reason:
            return Response(
                {'error': 'Emergency reason is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Get optional parameters
        patient_id = request.data.get('patient_id')
        duration_minutes = int(request.data.get('duration_minutes', 30))
        
        # Limit maximum duration
        max_duration = getattr(settings, 'EMERGENCY_ACCESS_MAX_DURATION_MINUTES', 60)
        if duration_minutes > max_duration:
            duration_minutes = max_duration
            
        # Create a security audit log for the emergency access
        security_log = SecurityAuditLog.objects.create(
            user=request.user,
            event_type='emergency_access',
            description=f"Emergency access activated: {reason}",
            severity='high',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'reason': reason,
                'patient_id': patient_id,
                'duration_minutes': duration_minutes,
                'expiration': (timezone.now() + timedelta(minutes=duration_minutes)).isoformat()
            }
        )
        
        # Generate an emergency access token
        import uuid
        import hashlib
        
        token_base = f"{uuid.uuid4()}-{request.user.id}-{timezone.now().timestamp()}"
        token = hashlib.sha256(token_base.encode()).hexdigest()
        
        # Set expiration time
        expiration = timezone.now() + timedelta(minutes=duration_minutes)
        
        # Store token in session
        request.session['emergency_access_token'] = token
        request.session['emergency_access_expiry'] = expiration.isoformat()
        request.session['emergency_access_reason'] = reason
        
        # Send notification to compliance officers and administrators
        self._send_emergency_access_notification(
            request.user, reason, patient_id, duration_minutes, security_log
        )
        
        # Return token and expiration
        return Response({
            'token': token,
            'expiration': expiration.isoformat(),
            'duration_minutes': duration_minutes,
            'patient_id': patient_id,
            'message': 'Emergency access granted. This access will be thoroughly audited.'
        })
    
    def delete(self, request, *args, **kwargs):
        """
        Deactivate emergency access before the default expiration.
        
        This is good practice to minimize the duration of enhanced access.
        """
        # Check if emergency access is active
        if 'emergency_access_token' not in request.session:
            return Response(
                {'message': 'No active emergency access to deactivate'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Get token and reason from session
        token = request.session.get('emergency_access_token')
        reason = request.session.get('emergency_access_reason', 'Unknown reason')
        
        # Clean up session
        for key in ['emergency_access_token', 'emergency_access_expiry', 'emergency_access_reason']:
            if key in request.session:
                del request.session[key]
                
        # Log the deactivation
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='emergency_access_end',
            description=f"Emergency access deactivated: {reason}",
            severity='medium',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'reason': reason,
                'deactivation_time': timezone.now().isoformat(),
                'deactivation_type': 'user_initiated'
            }
        )
        
        return Response({
            'message': 'Emergency access deactivated successfully',
            'deactivation_time': timezone.now().isoformat()
        })
    
    def get(self, request, *args, **kwargs):
        """
        Check if emergency access is active and get its status.
        """
        # Check if emergency access is active
        if 'emergency_access_token' not in request.session:
            return Response({
                'active': False,
                'message': 'No emergency access is currently active'
            })
            
        # Get token and expiration from session
        token = request.session.get('emergency_access_token')
        expiry_str = request.session.get('emergency_access_expiry')
        reason = request.session.get('emergency_access_reason', 'Unknown reason')
        
        # Parse expiration time
        try:
            expiry = timezone.datetime.fromisoformat(expiry_str)
        except (ValueError, TypeError):
            # If expiry can't be parsed, deactivate emergency access
            for key in ['emergency_access_token', 'emergency_access_expiry', 'emergency_access_reason']:
                if key in request.session:
                    del request.session[key]
                    
            return Response({
                'active': False,
                'message': 'Emergency access status could not be determined and was deactivated'
            })
            
        # Check if expired
        if expiry < timezone.now():
            # Clean up session
            for key in ['emergency_access_token', 'emergency_access_expiry', 'emergency_access_reason']:
                if key in request.session:
                    del request.session[key]
                    
            # Log the automatic expiration
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='emergency_access_end',
                description=f"Emergency access expired: {reason}",
                severity='medium',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                additional_data={
                    'reason': reason,
                    'deactivation_time': timezone.now().isoformat(),
                    'deactivation_type': 'automatic_expiration',
                    'original_expiry': expiry_str
                }
            )
            
            return Response({
                'active': False,
                'message': 'Emergency access has expired',
                'expiry': expiry.isoformat()
            })
            
        # Calculate remaining time
        remaining_seconds = (expiry - timezone.now()).total_seconds()
        remaining_minutes = int(remaining_seconds / 60)
        
        return Response({
            'active': True,
            'token': token,
            'expiry': expiry.isoformat(),
            'reason': reason,
            'remaining_minutes': remaining_minutes,
            'remaining_seconds': int(remaining_seconds)
        })
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
    
    def _send_emergency_access_notification(self, user, reason, patient_id, duration_minutes, security_log):
        """
        Send notification about emergency access to compliance officers and administrators.
        
        Args:
            user: User who activated emergency access
            reason: Reason for emergency access
            patient_id: Patient ID if specified
            duration_minutes: Duration of emergency access
            security_log: SecurityAuditLog entry created for this access
        """
        # Get notification recipients
        notification_emails = getattr(settings, 'EMERGENCY_ACCESS_NOTIFICATION_EMAILS', [])
        
        if not notification_emails:
            # Fall back to compliance officers and admin emails
            notification_emails = getattr(settings, 'COMPLIANCE_OFFICER_EMAILS', [])
            admin_emails = getattr(settings, 'ADMINS', [])
            if admin_emails:
                # The ADMINS setting is a list of (name, email) tuples
                admin_emails = [email for name, email in admin_emails]
            notification_emails.extend(admin_emails)
        
        if not notification_emails:
            logger.warning("No recipients configured for emergency access notifications")
            return
        
        # Prepare notification
        subject = f"ALERT: Emergency PHI Access Activated by {user.username}"
        
        message = f"""
        Emergency PHI access has been activated by {user.get_full_name() or user.username}.
        
        User: {user.username} ({user.get_role_display() if hasattr(user, 'get_role_display') else 'User'})
        Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
        Duration: {duration_minutes} minutes
        Reason: {reason}
        """
        
        if patient_id:
            message += f"\nPatient ID: {patient_id}"
            
        message += f"""
        
        This emergency access bypasses normal PHI access controls and will be thoroughly audited.
        Security Log ID: {security_log.id}
        
        If this access appears suspicious or unnecessary, please investigate immediately.
        """
        
        # Create HTML version
        html_message = f"""
        <html>
        <body>
            <h2>Emergency PHI Access Alert</h2>
            <p>Emergency PHI access has been activated by {user.get_full_name() or user.username}.</p>
            
            <ul>
                <li><strong>User:</strong> {user.username} ({user.get_role_display() if hasattr(user, 'get_role_display') else 'User'})</li>
                <li><strong>Time:</strong> {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                <li><strong>Duration:</strong> {duration_minutes} minutes</li>
                <li><strong>Reason:</strong> {reason}</li>
                {f'<li><strong>Patient ID:</strong> {patient_id}</li>' if patient_id else ''}
                <li><strong>Security Log ID:</strong> {security_log.id}</li>
            </ul>
            
            <p style="color: red; font-weight: bold;">
                This emergency access bypasses normal PHI access controls and will be thoroughly audited.
            </p>
            
            <p>If this access appears suspicious or unnecessary, please investigate immediately.</p>
        </body>
        </html>
        """
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=notification_emails,
                html_message=html_message
            )
            logger.info(f"Emergency access notification sent to {len(notification_emails)} recipients")
        except Exception as e:
            logger.error(f"Failed to send emergency access notification: {str(e)}")


class EmergencyAccessMiddleware:
    """
    Middleware to handle emergency access mode.
    
    This checks for active emergency tokens and logs all PHI access during
    emergency mode for complete audit trails.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Process request - check for emergency access
        if self._has_active_emergency_access(request):
            # Set emergency access flag for audit logging
            request.emergency_access = True
            
        # Process response
        response = self.get_response(request)
        
        # If we're in emergency access mode, log this access
        if hasattr(request, 'emergency_access') and request.emergency_access:
            self._log_emergency_access(request, response)
            
        return response
    
    def _has_active_emergency_access(self, request):
        """
        Check if request has active emergency access.
        
        Args:
            request: The request object
            
        Returns:
            bool: True if emergency access is active
        """
        # Check session for emergency access token
        if not hasattr(request, 'session'):
            return False
            
        token = request.session.get('emergency_access_token')
        expiry_str = request.session.get('emergency_access_expiry')
        
        if not token or not expiry_str:
            return False
            
        # Check if token is expired
        try:
            expiry = timezone.datetime.fromisoformat(expiry_str)
            if expiry < timezone.now():
                # Clean up expired token
                for key in ['emergency_access_token', 'emergency_access_expiry', 'emergency_access_reason']:
                    if key in request.session:
                        del request.session[key]
                return False
        except (ValueError, TypeError):
            # Invalid expiry format
            return False
            
        return True
    
    def _log_emergency_access(self, request, response):
        """
        Log data access during emergency mode.
        
        Args:
            request: The request object
            response: The response object
        """
        # Only log API requests that might contain PHI
        if not request.path.startswith('/api/'):
            return
            
        # Skip certain API paths
        skip_paths = [
            '/api/auth/',
            '/api/emergency/',
            '/api/docs/',
            '/api/schema/'
        ]
        
        if any(request.path.startswith(path) for path in skip_paths):
            return
            
        # Get reason from session
        reason = request.session.get('emergency_access_reason', 'Unknown reason')
        
        # Log the emergency access
        from ..models import AuditEvent
        
        AuditEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            event_type=AuditEvent.EventType.ACCESS,
            resource_type='emergency_access',
            resource_id=request.path,
            description=f"Emergency access during {reason}: {request.method} {request.path}",
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'method': request.method,
                'path': request.path,
                'query_params': dict(request.GET),
                'emergency_reason': reason,
                'response_status': response.status_code
            }
        )
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
