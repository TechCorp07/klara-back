"""
Models for SMART on FHIR authorization requests and tokens.
Database-backed approach to storing authorization codes and tokens.
"""
import uuid
from django.db import models

class SMARTAuthRequest(models.Model):
    """
    Stores the authorization code and associated parameters for a SMART on FHIR auth flow.
    Used during the 'authorization_code' exchange before the token is issued.
    """
    auth_code = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client_id = models.CharField(max_length=255)
    redirect_uri = models.URLField()
    scope = models.TextField()
    state = models.CharField(max_length=255)
    code_challenge = models.CharField(max_length=255, blank=True, null=True)
    code_challenge_method = models.CharField(max_length=50, blank=True, null=True)
    aud = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SMARTAuthRequest {self.auth_code} for client {self.client_id}"


class SMARTToken(models.Model):
    """
    Stores access tokens and refresh tokens for SMART on FHIR.
    """
    access_token = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client_id = models.CharField(max_length=255)
    scope = models.TextField()
    refresh_token = models.UUIDField(default=uuid.uuid4, editable=False)
    expires_in = models.IntegerField(default=3600)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SMARTToken {self.access_token} for client {self.client_id}"
