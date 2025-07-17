"""
Security middleware and settings for Klararety platform.
Implements security middleware and Django settings for enhanced security.
"""
from django.conf import settings
from django.http import HttpResponseRedirect
import re
import logging

logger = logging.getLogger('security')

class SecurityMiddleware:
    """
    Middleware for enforcing security policies.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Enforce HTTPS
        if not request.is_secure() and not settings.DEBUG:
            url = request.build_absolute_uri(request.get_full_path())
            secure_url = url.replace('http://', 'https://')
            return HttpResponseRedirect(secure_url)
            
        response = self.get_response(request)
        return response


class ContentSecurityPolicyMiddleware:
    """
    Middleware for implementing Content Security Policy.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add CSP header
        csp_parts = [
            "default-src 'self'",  # everything else inherits from this
            "script-src 'self' 'unsafe-inline'",  # allow minimal inline JS
            "style-src 'self' 'unsafe-inline' fonts.googleapis.com",  # Google fonts CSS
            "img-src 'self' data: cdn.redoc.ly",  # local images + ReDoc logo/data URIs
            "font-src 'self' fonts.gstatic.com",  # Google font files
            "worker-src 'self' blob:",
            "connect-src 'self'",  # AJAX / WebSocket endpoints
            "frame-ancestors 'none'",  # prevent click‑jacking
            "form-action 'self'",  # only allow forms to post back to us
            "base-uri 'self'",  # disallow <base href> manipulation
            "object-src 'none'",  # block <object>, <embed>, <applet>
        ]
        
        response['Content-Security-Policy'] = '; '.join(csp_parts)
        return response


class XSSProtectionMiddleware:
    """
    Middleware for protecting against XSS attacks.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.xss_pattern = re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL)
        
    def __call__(self, request):
        # Check for potential XSS in GET parameters
        for key, value in request.GET.items():
            if isinstance(value, str) and self.xss_pattern.search(value):
                logger.warning(f"Potential XSS attack detected in GET parameter: {key}")
                return self.get_response(request)
                
        # Check for potential XSS in POST parameters
        for key, value in request.POST.items():
            if isinstance(value, str) and self.xss_pattern.search(value):
                logger.warning(f"Potential XSS attack detected in POST parameter: {key}")
                return self.get_response(request)
                
        response = self.get_response(request)
        
        # Add XSS protection header
        response['X-XSS-Protection'] = '1; mode=block'
        return response


# Django settings for enhanced security
SECURITY_SETTINGS = {    
    # CSRF protection
    'CSRF_FAILURE_VIEW': 'django.views.csrf.csrf_failure',
    
    # Rate limiting
    'AXES_ENABLED': True,
    'AXES_FAILURE_LIMIT': 5,
    'AXES_COOLOFF_TIME': 1,  # 1 hour
    'AXES_LOCK_OUT_AT_FAILURE': True,
    'AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP': True,
    
    # File upload settings
    'DATA_UPLOAD_MAX_MEMORY_SIZE': 10485760,  # 10 MB
    'FILE_UPLOAD_MAX_MEMORY_SIZE': 10485760,  # 10 MB
    'FILE_UPLOAD_PERMISSIONS': 0o644,
    'FILE_UPLOAD_DIRECTORY_PERMISSIONS': 0o755,
}
