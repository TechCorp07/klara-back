"""
SMART on FHIR integration for Klararety platform.
Implements OAuth2 authorization for FHIR API access using a database-backed token store.
"""
from django.conf import settings
from django.http import JsonResponse
from django.urls import reverse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import uuid
import logging

# Import your new models
from smart_auth.models import SMARTAuthRequest, SMARTToken

logger = logging.getLogger('fhir')


@api_view(['GET'])
@permission_classes([AllowAny])
def smart_configuration(request):
    """
    SMART on FHIR configuration endpoint.
    Returns the SMART configuration for the FHIR server.
    """
    base_url = request.build_absolute_uri('/').rstrip('/')
    config = {
        "authorization_endpoint": f"{base_url}/api/smart/authorize",
        "token_endpoint": f"{base_url}/api/smart/token",
        "capabilities": [
            "launch-standalone",
            "client-public",
            "client-confidential-symmetric",
            "context-standalone-patient",
            "permission-patient",
            "permission-user",
            "permission-offline"
        ],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "management_endpoint": f"{base_url}/api/smart/manage",
        "introspection_endpoint": f"{base_url}/api/smart/introspect",
        "revocation_endpoint": f"{base_url}/api/smart/revoke",
        "scopes_supported": [
            "openid",
            "profile",
            "fhirUser",
            "launch",
            "launch/patient",
            "patient/*.read",
            "patient/*.write",
            "patient/Patient.read",
            "patient/Observation.read",
            "patient/Condition.read",
            "patient/MedicationStatement.read",
            "patient/Communication.read",
            "patient/Encounter.read",
            "user/*.read",
            "user/*.write",
            "user/Patient.read",
            "user/Observation.read",
            "user/Condition.read",
            "user/MedicationStatement.read",
            "user/Communication.read",
            "user/Encounter.read",
            "system/*.read",
            "system/*.write"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "context_relations_supported": ["patient", "encounter", "practitioner"]
    }
    return JsonResponse(config)


@api_view(['GET'])
@permission_classes([AllowAny])
def authorize(request):
    """
    SMART on FHIR authorization endpoint.
    Initiates the authorization process by creating an auth request in the database.
    """
    response_type = request.GET.get('response_type')
    client_id = request.GET.get('client_id')
    redirect_uri = request.GET.get('redirect_uri')
    scope = request.GET.get('scope')
    state = request.GET.get('state')
    aud = request.GET.get('aud')
    code_challenge = request.GET.get('code_challenge')
    code_challenge_method = request.GET.get('code_challenge_method', 'plain')
    
    # Validate parameters
    if not all([response_type, client_id, redirect_uri, scope, state]):
        return JsonResponse({
            "error": "invalid_request",
            "error_description": "Missing required parameters"
        }, status=400)
    
    if response_type != 'code':
        return JsonResponse({
            "error": "unsupported_response_type",
            "error_description": "Only 'code' response type is supported"
        }, status=400)

    # Create a SMARTAuthRequest in DB
    auth_request = SMARTAuthRequest.objects.create(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        aud=aud
    )
    
    # For a real app, you'd show a login/consent screen. 
    # We'll simulate "auto-approval" by returning the redirect with code + state:
    redirect_url = f"{redirect_uri}?code={auth_request.auth_code}&state={state}"
    
    return JsonResponse({
        "redirect_url": redirect_url,
        "message": "Authorization successful. In production, present a consent screen here."
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def token(request):
    """
    SMART on FHIR token endpoint.
    Exchanges an authorization code for an access token or refreshes an existing token.
    """
    grant_type = request.POST.get('grant_type')
    code = request.POST.get('code')
    redirect_uri = request.POST.get('redirect_uri')
    client_id = request.POST.get('client_id')
    code_verifier = request.POST.get('code_verifier')
    refresh_token_value = request.POST.get('refresh_token')
    
    if grant_type == 'authorization_code':
        if not all([code, redirect_uri, client_id]):
            return JsonResponse({
                "error": "invalid_request",
                "error_description": "Missing required parameters for authorization_code grant"
            }, status=400)

        # Lookup the auth request in DB
        try:
            auth_request = SMARTAuthRequest.objects.get(pk=code)
        except SMARTAuthRequest.DoesNotExist:
            return JsonResponse({
                "error": "invalid_grant",
                "error_description": "Invalid authorization code"
            }, status=400)
        
        # Validate client and redirect URI
        if auth_request.client_id != client_id or auth_request.redirect_uri != redirect_uri:
            return JsonResponse({
                "error": "invalid_grant",
                "error_description": "Client ID or redirect URI mismatch"
            }, status=400)
        
        # (Optional) Validate PKCE code_challenge with code_verifier if provided
        # For example, if code_challenge_method == 'S256', confirm code_verifier. 
        # ...
        
        # Generate new tokens
        new_access_token = SMARTToken.objects.create(
            client_id=client_id,
            scope=auth_request.scope,
            # Optionally set expires_in or user reference
        )
        
        # Once used, remove the auth request or mark it used
        auth_request.delete()

        return JsonResponse({
            "access_token": str(new_access_token.access_token),
            "token_type": "Bearer",
            "expires_in": new_access_token.expires_in,
            "refresh_token": str(new_access_token.refresh_token),
            "scope": new_access_token.scope,
            # If you have patient context, add it here:
            "patient": "example-patient-id",
            "encounter": "example-encounter-id"
        })
    
    elif grant_type == 'refresh_token':
        if not all([refresh_token_value, client_id]):
            return JsonResponse({
                "error": "invalid_request",
                "error_description": "Missing required parameters for refresh_token grant"
            }, status=400)
        
        # Validate refresh token in DB
        try:
            old_token = SMARTToken.objects.get(refresh_token=refresh_token_value, client_id=client_id)
        except SMARTToken.DoesNotExist:
            return JsonResponse({
                "error": "invalid_grant",
                "error_description": "Invalid refresh token"
            }, status=400)
        
        scope = old_token.scope
        # (Optional) You could delete the old token or keep track of multiple versions
        old_token.delete()
        
        # Create a new token
        new_token = SMARTToken.objects.create(client_id=client_id, scope=scope)
        
        return JsonResponse({
            "access_token": str(new_token.access_token),
            "token_type": "Bearer",
            "expires_in": new_token.expires_in,
            "refresh_token": str(new_token.refresh_token),
            "scope": new_token.scope
        })
    
    else:
        return JsonResponse({
            "error": "unsupported_grant_type",
            "error_description": "Unsupported grant type"
        }, status=400)


@api_view(['POST'])
@permission_classes([AllowAny])
def introspect(request):
    """
    SMART on FHIR token introspection endpoint.
    Validates an access token and returns its metadata.
    """
    token = request.POST.get('token')
    if not token:
        return JsonResponse({
            "error": "invalid_request",
            "error_description": "Missing token parameter"
        }, status=400)
    
    try:
        token_obj = SMARTToken.objects.get(pk=token)
        # You might calculate actual expiration from created_at + expires_in 
        return JsonResponse({
            "active": True,
            "scope": token_obj.scope,
            "client_id": token_obj.client_id,
            "exp": token_obj.expires_in
        })
    except SMARTToken.DoesNotExist:
        return JsonResponse({"active": False})


@api_view(['POST'])
@permission_classes([AllowAny])
def revoke(request):
    """
    SMART on FHIR token revocation endpoint.
    Revokes an access token or refresh token.
    """
    token = request.POST.get('token')
    token_type_hint = request.POST.get('token_type_hint')  # 'access_token' or 'refresh_token', optional
    
    if not token:
        return JsonResponse({
            "error": "invalid_request",
            "error_description": "Missing token parameter"
        }, status=400)
    
    if token_type_hint == 'refresh_token':
        # Revoke by refresh token
        SMARTToken.objects.filter(refresh_token=token).delete()
    else:
        # Default to revoking by access token
        SMARTToken.objects.filter(pk=token).delete()
    
    return JsonResponse({"success": True})


@api_view(['GET'])
@permission_classes([AllowAny])
def well_known_smart_configuration(request):
    """
    Returns the same SMART configuration from a well-known endpoint.
    """
    return smart_configuration(request)
