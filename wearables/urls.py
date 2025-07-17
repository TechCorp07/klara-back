from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    WearableIntegrationViewSet, WearableMeasurementViewSet,
    WearableConnectViewSet, DataSyncViewSet, LegacyWithingsViewSet
)

router = DefaultRouter()
router.register(r'integrations', WearableIntegrationViewSet, basename='wearable-integration')
router.register(r'measurements', WearableMeasurementViewSet, basename='wearable-measurement')

urlpatterns = [
    path('', include(router.urls)),
    
    # Connection endpoints
    path('connect/', WearableConnectViewSet.as_view({'get': 'connect'}), name='wearable-connect'),
    path('callback/', WearableConnectViewSet.as_view({'post': 'callback'}), name='wearable-callback'),
    
    # Data sync endpoints
    path('sync/', DataSyncViewSet.as_view({'post': 'fetch_data'}), name='wearable-sync'),
    
    # Legacy Withings endpoints (for backward compatibility)
    path('withings/profile/', LegacyWithingsViewSet.as_view({'get': 'profile'}), name='withings-profile'),
    path('withings/connect/', LegacyWithingsViewSet.as_view({'get': 'connect'}), name='withings-connect'),
    path('withings/callback/', LegacyWithingsViewSet.as_view({'post': 'callback'}), name='withings-callback'),
    path('withings/fetch-data/', LegacyWithingsViewSet.as_view({'get': 'fetch_data'}), name='withings-fetch-data'),
    
    # Callback endpoints for various services
    path('callback/fitbit/', WearableConnectViewSet.as_view({'post': 'callback'}), name='fitbit-callback'),
    path('callback/google_fit/', WearableConnectViewSet.as_view({'post': 'callback'}), name='google-fit-callback'),
    
    # Mobile app endpoints for health data sync
    path('mobile/apple_health/', include([
        path('sync/', DataSyncViewSet.as_view({'post': 'apple_health_sync'}), name='apple-health-sync'),
        path('config/', DataSyncViewSet.as_view({'get': 'apple_health_config'}), name='apple-health-config'),
    ])),
    path('mobile/samsung_health/', include([
        path('sync/', DataSyncViewSet.as_view({'post': 'samsung_health_sync'}), name='samsung-health-sync'),
        path('config/', DataSyncViewSet.as_view({'get': 'samsung_health_config'}), name='samsung-health-config'),
    ])),
]
