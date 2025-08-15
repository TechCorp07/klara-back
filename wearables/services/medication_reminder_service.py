# wearables/services/medication_reminder_service.py
from datetime import datetime, timedelta
from django.utils import timezone
from .notification_service import WearableNotificationService
import logging
from wearables.models import WearableIntegration

logger = logging.getLogger(__name__)

class MedicationReminderService:
    @classmethod
    def schedule_apple_watch_reminder(cls, user, medication, scheduled_time):
        """Schedule medication reminder for Apple Watch."""
        try:
            integration = WearableIntegration.objects.filter(
                user=user,
                integration_type='apple_health',
                status='connected'
            ).first()
            
            if not integration:
                return False
            
            reminder_data = {
                'medication_id': medication.id,
                'medication_name': medication.name,
                'dosage': medication.dosage,
                'scheduled_time': scheduled_time.isoformat(),
                'is_critical': medication.is_critical
            }
            
            return WearableNotificationService.send_watch_notification(
                device_id=integration.platform_user_id,
                title=f"Take {medication.name}",
                message=f"Time for your {medication.dosage} dose",
                **reminder_data
            )
            
        except Exception as e:
            logger.error(f"Failed to schedule Apple Watch reminder: {str(e)}")
            return False
