# wearables/services/__init__.py
from . import withings_service
from . import apple_health_service
from . import google_fit_service
from . import samsung_health_service
from . import fitbit_service
from .notification_service import send_watch_notification, WearableNotificationService
from .adherence_monitoring import AdherenceMonitoringService

# Export the main functions for external use
__all__ = [
    'send_watch_notification',
    'WearableNotificationService', 
    'AdherenceMonitoringService',
    'withings_service',
    'apple_health_service',
    'google_fit_service',
    'samsung_health_service',
    'fitbit_service'
]
