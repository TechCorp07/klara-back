# users/authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """
    Custom DRF authentication class that works with JWT middleware.
    
    This class integrates the JWT middleware with DRF's authentication system,
    ensuring that users authenticated via JWT are properly recognized by DRF's
    permission classes.
    """
    
    def authenticate(self, request):
        """
        Authenticate the request using JWT token validation from middleware.
        
        Returns None if authentication fails, or (user, token) tuple if successful.
        """
        # ⭐ FIX: Access user from underlying Django request to avoid recursion
        # Don't use request.user as it triggers DRF authentication again
        
        # Check if JWT middleware has set the user on the underlying Django request
        django_request = request._request  # Get the underlying Django request
        
        if (hasattr(django_request, 'user') and 
            django_request.user and 
            not isinstance(django_request.user, AnonymousUser) and
            hasattr(request, 'jwt_payload') and 
            request.jwt_payload):
            
            # Return user and token for DRF
            return (django_request.user, request.jwt_payload.get('jti'))  # Use JWT ID as token
        
        # No JWT authentication found
        return None
    
    def authenticate_header(self, request):
        """
        Return the authentication header for 401 responses.
        """
        return 'Bearer'


class JWTSessionAuthentication(BaseAuthentication):
    """
    Alternative authentication class that creates a session-like experience with JWT.
    """
    
    def authenticate(self, request):
        """
        Authenticate using JWT and create session-like behavior.
        """
        # ⭐ FIX: Access user from underlying Django request to avoid recursion
        django_request = request._request  # Get the underlying Django request
        
        # Check if middleware has set the user from JWT
        if (hasattr(django_request, 'user') and 
            django_request.user and 
            not isinstance(django_request.user, AnonymousUser) and
            hasattr(request, 'jwt_payload')):
            
            # Mark user as authenticated
            django_request.user.backend = 'users.jwt_auth.JWTAuthenticationBackend'
            
            return (django_request.user, request.jwt_payload.get('jti'))
        
        return None
    
    def authenticate_header(self, request):
        return 'Bearer'


class SimpleJWTAuthentication(BaseAuthentication):
    """
    Simplified JWT authentication that only checks for JWT payload presence.
    """
    
    def authenticate(self, request):
        """
        Simple authentication check based on JWT payload existence.
        """
        # If JWT middleware successfully processed a token, there will be a jwt_payload
        if hasattr(request, 'jwt_payload') and request.jwt_payload:
            # Get user from the JWT payload
            user_id = request.jwt_payload.get('user_id')
            if user_id:
                try:
                    user = User.objects.get(id=user_id)
                    # Set backend for DRF compatibility
                    user.backend = 'users.jwt_auth.JWTAuthenticationBackend'
                    return (user, request.jwt_payload.get('jti'))
                except User.DoesNotExist:
                    return None
        
        return None
    
    def authenticate_header(self, request):
        return 'Bearer'