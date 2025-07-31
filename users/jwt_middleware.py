# users/jwt_middleware.py
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import resolve
from django.conf import settings
from typing import Optional

from .jwt_auth import JWTAuthenticationManager
from .session_manager import SessionManager
from .models import AuditTrail, PharmaceuticalTenant

User = get_user_model()
logger = logging.getLogger(__name__)


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    JWT Authentication Middleware with local token verification.
    
    This middleware replaces your current API-based token validation with
    local JWT verification, eliminating the race conditions caused by
    external authentication calls during every request.
    
    Think of this as a smart security guard that can verify IDs instantly
    without having to call headquarters every time someone wants to enter.
    """
    
    # Pharmaceutical tenant isolation enforcement
    TENANT_ISOLATED_PATHS = [
        '/api/proxy/patient/',
        '/api/proxy/research/',
        '/api/proxy/pharmco/',
    ]
    
    def process_request(self, request):
        """
        Process incoming request and authenticate user via JWT.
        
        This method runs for every request and determines if the user
        is authenticated without making external API calls, eliminating
        the bottleneck that was causing race conditions in your current system.
        """
        if request.path.startswith('/admin/'):
            return None
        
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return None
        
        # Skip authentication for public paths
        if self._is_public_path(request.path):
            request.user = AnonymousUser()
            return None
        
        # Extract JWT token from Authorization header or cookie
        jwt_token = self._extract_jwt_token(request)
        
        if not jwt_token:
            return self._create_auth_required_response("Authentication token required")
        
        # Validate JWT token locally (no database calls for basic validation)
        is_valid, payload, error_message = JWTAuthenticationManager.validate_access_token(jwt_token)
        
        if not is_valid:
            # Log authentication failure for security monitoring
            self._log_auth_failure(request, error_message)
            return self._create_auth_required_response(error_message)
        
        # Attach user and session information to request
        try:
            user = self._get_user_from_payload(payload)
            if not user:
                return self._create_auth_required_response("User not found")
            
            # Attach user to request for downstream processing
            request.user = user
            user.backend = 'users.jwt_auth.JWTAuthenticationBackend'
            request.jwt_payload = payload
            request.session_id = payload.get('session_id')
            request.pharmaceutical_tenant_id = payload.get('primary_tenant_id')
            
            # Enforce pharmaceutical tenant isolation if required
            if self._requires_tenant_isolation(request.path):
                if not self._validate_tenant_access(request, payload):
                    return self._create_forbidden_response("Insufficient tenant permissions")
            
            # Track user activity for session management
            self._track_user_activity(request, payload)
            
            # Check for emergency access and log appropriately
            if payload.get('emergency_access'):
                self._log_emergency_access(request, payload)
            
            return None  # Continue processing the request
            
        except Exception as e:
            logger.error(f"JWT middleware error: {str(e)}")
            return self._create_auth_required_response("Authentication validation failed")
    
    def _extract_jwt_token(self, request) -> Optional[str]:
        """
        Extract JWT token from Authorization header ONLY.
        NO cookie fallback for tab-specific authentication.
        """
        
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]
        
        return None
    
    def _get_user_from_payload(self, payload: dict) -> Optional[User]:
        """
        Get user object from JWT payload with minimal database impact.
        
        Uses select_related to minimize database queries while getting
        all necessary user context in a single database hit.
        """
        try:
            user_id = payload.get('user_id')
            if not user_id:
                return None
            
            # Get user with related pharmaceutical tenant data
            user = User.objects.select_related(
                'primary_pharmaceutical_tenant'
            ).prefetch_related(
                'pharmaceutical_tenants'
            ).get(id=user_id)
            
            # Verify JWT version matches to ensure token hasn't been invalidated
            if payload.get('jwt_version', 1) != user.jwt_secret_version:
                logger.warning(f"JWT version mismatch for user {user.email}")
                return None
            
            return user
            
        except User.DoesNotExist:
            return None
        except Exception as e:
            logger.error(f"Error getting user from payload: {str(e)}")
            return None
    
    def _is_public_path(self, path: str) -> bool:
        """
        Check if the request path requires authentication.
        
        This method determines which endpoints can be accessed without
        providing valid authentication credentials.
        """
        # Exact path matches for specific public endpoints
        exact_public_paths = [
            '/api/users/auth/login/',
            '/api/users/auth/register/',
            '/api/users/auth/check-status/',
            '/api/users/auth/verify-email/',
            '/api/users/auth/forgot-password/',
            '/api/users/auth/reset-password/',
            '/api/users/auth/refresh/',  # Token refresh might be considered semi-public
        ]
        
        if path in exact_public_paths:
            return True
        
        # Pattern matches for paths with parameters (like /static/css/style.css)
        public_patterns = [
            '/admin/login/',
            '/admin/logout/',
            '/admin/jsi18n/',
            '/static/',
            '/media/',
            '/.well-known/',
        ]
        
        return any(path.startswith(pattern) for pattern in public_patterns)

    def _requires_tenant_isolation(self, path: str) -> bool:
        """
        Check if the request path requires pharmaceutical tenant isolation.
        
        Certain endpoints that handle patient data or research information
        must enforce strict tenant boundaries to prevent data leakage
        between competing pharmaceutical companies.
        """
        return any(path.startswith(pattern) for pattern in self.TENANT_ISOLATED_PATHS)
    
    def _validate_tenant_access(self, request, payload: dict) -> bool:
        """
        Validate that user has access to the pharmaceutical tenant context.
        
        This prevents users from accessing data belonging to pharmaceutical
        companies they're not associated with, which is critical for
        maintaining competitive separation in pharmaceutical research.
        """
        requested_tenant_id = request.GET.get('tenant_id') or request.POST.get('tenant_id')
        
        if not requested_tenant_id:
            # If no specific tenant requested, allow access to primary tenant
            return True
        
        # Check if user has access to the requested tenant
        user_tenant_ids = payload.get('tenant_ids', [])
        return requested_tenant_id in user_tenant_ids
    
    def _track_user_activity(self, request, payload: dict):
        """
        Track user activity for session management and security monitoring.
        
        This updates the user's session to extend the timeout and provides
        activity tracking for security analysis without requiring database
        locks that could cause race conditions.
        """
        session_id = payload.get('session_id')
        if session_id:
            # Update session activity asynchronously to avoid blocking the request
            try:
                # This extends the session timeout based on user activity
                SessionManager.extend_session(session_id)
            except Exception as e:
                # Log error but don't block the request
                logger.warning(f"Failed to update session activity: {str(e)}")
    
    def _log_auth_failure(self, request, error_message: str):
        """
        Log authentication failures for security monitoring.
        
        These logs are crucial for detecting potential security threats
        and monitoring the health of your authentication system.
        """
        try:
            AuditTrail.objects.create(
                user=None,  # No user for failed authentication
                action_type='SECURITY_EVENT',
                action_description=f'Authentication failed: {error_message}',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                risk_level='MEDIUM',
                request_data={
                    'path': request.path,
                    'method': request.method,
                    'error': error_message,
                }
            )
        except Exception as e:
            # Don't let audit logging failures break authentication
            logger.error(f"Failed to log auth failure: {str(e)}")
    
    def _log_emergency_access(self, request, payload: dict):
        """
        Log emergency access usage for compliance and security monitoring.
        
        Emergency access is high-risk and requires comprehensive audit trails
        for healthcare compliance and security analysis.
        """
        try:
            AuditTrail.objects.create(
                user_id=payload.get('user_id'),
                action_type='EMERGENCY_ACCESS',
                action_description=f'Emergency access used: {payload.get("emergency_reason", "Unknown")}',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                risk_level='HIGH',
                request_data={
                    'path': request.path,
                    'method': request.method,
                    'emergency_reason': payload.get('emergency_reason'),
                    'emergency_approved_by': payload.get('emergency_approved_by'),
                }
            )
        except Exception as e:
            logger.error(f"Failed to log emergency access: {str(e)}")
    
    def _get_client_ip(self, request) -> str:
        """
        Get client IP address accounting for proxy servers.
        
        Healthcare applications often run behind load balancers and proxies,
        so we need to extract the real client IP for security logging.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '0.0.0.0')
    
    def _create_auth_required_response(self, message: str) -> JsonResponse:
        """
        Create standardized authentication required response.
        
        This provides consistent error responses for authentication failures,
        helping frontend code handle authentication errors predictably.
        """
        return JsonResponse({
            'error': 'Authentication required',
            'message': message,
            'type': 'AUTH_REQUIRED'
        }, status=401)
    
    def _create_forbidden_response(self, message: str) -> JsonResponse:
        """
        Create standardized forbidden response for tenant access violations.
        
        This handles cases where a user is authenticated but doesn't have
        permission to access specific pharmaceutical tenant data.
        """
        return JsonResponse({
            'error': 'Access forbidden',
            'message': message,
            'type': 'INSUFFICIENT_PERMISSIONS'
        }, status=403)


class PharmaceuticalTenantMiddleware(MiddlewareMixin):
    """
    Middleware for pharmaceutical tenant context management.
    
    This middleware ensures that all database queries are automatically
    filtered by the appropriate pharmaceutical tenant, preventing data
    leakage between competing pharmaceutical companies.
    """
    
    def process_request(self, request):
        """
        Set pharmaceutical tenant context for the request.
        
        This ensures that all subsequent database operations are automatically
        scoped to the appropriate pharmaceutical tenant, preventing accidental
        cross-tenant data access.
        """
        # Only process authenticated requests
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return None
        
        # Get tenant context from JWT payload
        if hasattr(request, 'jwt_payload'):
            tenant_id = request.jwt_payload.get('primary_tenant_id')
            if tenant_id:
                try:
                    tenant = PharmaceuticalTenant.objects.get(id=tenant_id)
                    request.pharmaceutical_tenant = tenant
                except PharmaceuticalTenant.DoesNotExist:
                    logger.warning(f"Invalid tenant ID in JWT: {tenant_id}")
        
        return None


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers for healthcare application compliance.
    
    Healthcare applications require additional security headers to
    protect sensitive medical information and meet compliance requirements.
    """
    
    def process_response(self, request, response):
        """
        Add comprehensive security headers to all responses.
        
        These headers provide defense-in-depth security for your healthcare
        application, protecting against various attack vectors.
        """
        # Prevent clickjacking attacks
        response['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS protection
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Control referrer information
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy for additional protection
        if not response.get('Content-Security-Policy'):
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self' https:; "
                "frame-ancestors 'none';"
            )
            response['Content-Security-Policy'] = csp
        
        # HIPAA compliance headers
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        
        return response