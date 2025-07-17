# middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject
from django.conf import settings
import re

def get_accessibility_settings(request):
    """
    Get or create accessibility settings for the current user.
    """
    if not hasattr(request, '_cached_accessibility') and hasattr(request, 'user') and request.user.is_authenticated:
        from community.models import CommunityAccessibilitySetting
        request._cached_accessibility, _ = CommunityAccessibilitySetting.objects.get_or_create(
            user=request.user
        )
    return getattr(request, '_cached_accessibility', None)


class AccessibilityMiddleware(MiddlewareMixin):
    """
    Middleware to attach accessibility settings to the request.
    """
    def process_request(self, request):
        request.accessibility = SimpleLazyObject(lambda: get_accessibility_settings(request))


class PHIProtectionMiddleware(MiddlewareMixin):
    """
    Middleware to scan outgoing content for potential PHI.
    Adds a warning header when PHI patterns are detected.
    """
    PHI_PATTERNS = [
        r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',  # SSN
        r'\b\d{9}\b',                         # 9-digit identifiers
        r'\b[A-Z]{2}\d{6}\b',                 # Medical record patterns
        r'\b(patient|record|chart)\s*(id|number|#)?\s*:?\s*\w+\b',  # Patient ID references
        r'\b\d{1,2}/\d{1,2}/\d{2,4}\b',        # Dates
        r'\b\d{3}-\d{3}-\d{4}\b',             # Phone numbers
    ]
    
    def process_response(self, request, response):
        """
        Check response for PHI patterns and add warning header if found.
        """
        # Skip for non-authenticated users or admin users
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return response
            
        content_type = response.get('Content-Type', '')
        if 'text/html' in content_type or 'application/json' in content_type:
            potential_phi = False
            response_content = response.content.decode('utf-8', errors='replace')
            
            for pattern in self.PHI_PATTERNS:
                if re.search(pattern, response_content):
                    potential_phi = True
                    break
                    
            if potential_phi:
                response['X-PHI-Warning'] = 'Potential PHI detected in response'
                
                # Optionally log the potential PHI detection
                if hasattr(settings, 'PHI_WARNING_LOGGER'):
                    import logging
                    logger = logging.getLogger(settings.PHI_WARNING_LOGGER)
                    logger.warning(
                        "Potential PHI detected in response to %s by user %s", 
                        request.path, 
                        request.user.username
                    )
        return response


class ContentTransformMiddleware(MiddlewareMixin):
    """
    Middleware to transform content based on user accessibility settings.
    """
    def process_response(self, request, response):
        if not hasattr(request, 'user') or not request.user.is_authenticated or not hasattr(request, 'accessibility'):
            return response
            
        content_type = response.get('Content-Type', '')
        if 'text/html' not in content_type:
            return response
        
        accessibility = request.accessibility
        if not accessibility:
            return response
        
        content = response.content.decode('utf-8', errors='replace')
        
        # High contrast mode
        if accessibility.high_contrast:
            content = self._add_high_contrast_class(content)
            
        # Large text mode
        if accessibility.large_text:
            content = self._add_large_text_class(content)
            
        # Screen reader optimizations
        if accessibility.screen_reader_optimized:
            content = self._enhance_for_screen_readers(content)
        
        response.content = content.encode('utf-8', errors='replace')
        return response
        
    def _add_high_contrast_class(self, content):
        return content.replace('<body', '<body class="high-contrast"')
        
    def _add_large_text_class(self, content):
        if 'class="high-contrast"' in content:
            return content.replace('class="high-contrast"', 'class="high-contrast large-text"')
        else:
            return content.replace('<body', '<body class="large-text"')
            
    def _enhance_for_screen_readers(self, content):
        import re
        return re.sub(
            r'<i class="icon-([^"]+)"([^>]*)></i>',
            r'<i class="icon-\1"\2><span class="sr-only">\1</span></i>',
            content
        )
