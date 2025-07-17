"""
URL configuration for SMART on FHIR integration.
Defines API endpoints for SMART on FHIR authorization.
"""
from django.urls import path
from fhir.smart import (
    smart_configuration,
    authorize,
    token,
    introspect,
    revoke,
    well_known_smart_configuration,
)

urlpatterns = [
    path('smart-configuration', smart_configuration, name='smart_configuration'),
    path('authorize', authorize, name='authorize'),
    path('token', token, name='token'),
    path('introspect', introspect, name='introspect'),
    path('revoke', revoke, name='revoke'),
    path('.well-known/smart-configuration', well_known_smart_configuration, name='well_known_smart_configuration'),
]
