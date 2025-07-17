# middleware.py in healthcare app

from django.http import JsonResponse
from django.urls import resolve
from django.conf import settings

class ApprovalMiddleware:
    """
    Middleware to check if users are approved before accessing healthcare APIs.
    This provides a double layer of security with the permission classes.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Skip middleware for admin/staff or non-authenticated users
        # (DRF permission classes will handle those)
        if not request.user.is_authenticated or request.user.is_staff:
            return self.get_response(request)
            
        # Skip for non-healthcare URLs
        if not request.path.startswith('/api/healthcare/'):
            return self.get_response(request)
            
        # Skip for registration/login endpoints
        resolved = resolve(request.path)
        exempt_views = ['login', 'logout', 'create']
        if resolved.url_name in exempt_views:
            return self.get_response(request)
            
        # Check if user is approved
        if not hasattr(request.user, 'is_approved') or not request.user.is_approved:
            return JsonResponse({
                'detail': 'Your account is pending administrator approval.'
            }, status=403)
            
        # User is approved, proceed with the request
        return self.get_response(request)
