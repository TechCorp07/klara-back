# wearables/services/notification_service.py
import json
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from typing import Dict, Any, Optional, List
from ..models import WearableIntegration, NotificationDelivery

logger = logging.getLogger(__name__)

class WearableNotificationService:
    """
    Service for sending notifications to various wearable devices.
    Critical for medication adherence in rare disease patients.
    """
    
    @classmethod
    def send_watch_notification(cls, device_id: str, title: str, message: str, **kwargs) -> bool:
        """
        Main entry point for sending smartwatch notifications.
        Automatically routes to the correct platform based on device.
        """
        try:
            # Get device integration
            integration = WearableIntegration.objects.filter(
                platform_user_id=device_id,
                status=WearableIntegration.ConnectionStatus.CONNECTED
            ).first()
            
            if not integration:
                logger.warning(f"No active integration found for device {device_id}")
                return False
            
            # Route to appropriate platform
            if integration.integration_type == WearableIntegration.IntegrationType.APPLE_HEALTH:
                return cls._send_apple_watch_notification(integration, title, message, **kwargs)
            elif integration.integration_type == WearableIntegration.IntegrationType.SAMSUNG_HEALTH:
                return cls._send_samsung_watch_notification(integration, title, message, **kwargs)
            elif integration.integration_type == WearableIntegration.IntegrationType.FITBIT:
                return cls._send_fitbit_notification(integration, title, message, **kwargs)
            elif integration.integration_type == WearableIntegration.IntegrationType.GARMIN:
                return cls._send_garmin_notification(integration, title, message, **kwargs)
            else:
                # Generic notification for other platforms
                return cls._send_generic_notification(integration, title, message, **kwargs)
                
        except Exception as e:
            logger.error(f"Error sending watch notification: {str(e)}")
            return False
    
    @classmethod
    def _send_apple_watch_notification(cls, integration: WearableIntegration, title: str, message: str, **kwargs) -> bool:
        """Send notification to Apple Watch via iOS app and HealthKit."""
        try:
            # For Apple Watch, we send through the iOS companion app
            # The app will then trigger the watch notification
            
            notification_data = {
                'title': title,
                'message': message,
                'category': 'medication_reminder',
                'sound': 'medication_alert.wav',
                'badge': 1,
                'priority': 'high',
                'medication_id': kwargs.get('medication_id'),
                'scheduled_time': kwargs.get('scheduled_time'),
                'is_critical': kwargs.get('is_critical', False),
                'actions': [
                    {'id': 'taken', 'title': 'Mark as Taken'},
                    {'id': 'skip', 'title': 'Skip'},
                    {'id': 'snooze', 'title': 'Remind in 15 min'}
                ]
            }
            
            # Send via Apple Push Notification Service (APNs)
            success = cls._send_apns_notification(integration, notification_data)
            
            # Also send via HealthKit if available
            if success:
                cls._send_healthkit_reminder(integration, notification_data)
            
            # Log delivery attempt
            cls._log_notification_delivery(
                integration=integration,
                notification_type='apple_watch',
                title=title,
                message=message,
                success=success,
                metadata=notification_data
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending Apple Watch notification: {str(e)}")
            return False
    
    @classmethod
    def _send_samsung_watch_notification(cls, integration: WearableIntegration, title: str, message: str, **kwargs) -> bool:
        """Send notification to Samsung Galaxy Watch."""
        try:
            notification_data = {
                'title': title,
                'message': message,
                'category': 'health_reminder',
                'vibration_pattern': 'medication_alert',
                'priority': 'high',
                'medication_id': kwargs.get('medication_id'),
                'is_critical': kwargs.get('is_critical', False),
                'actions': [
                    {'action': 'taken', 'label': 'Taken'},
                    {'action': 'skip', 'label': 'Skip'},
                    {'action': 'snooze', 'label': 'Snooze 15min'}
                ]
            }
            
            # Send via Samsung Health SDK or FCM
            success = cls._send_samsung_health_notification(integration, notification_data)
            
            cls._log_notification_delivery(
                integration=integration,
                notification_type='samsung_watch',
                title=title,
                message=message,
                success=success,
                metadata=notification_data
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending Samsung Watch notification: {str(e)}")
            return False
    
    @classmethod
    def _send_apns_notification(cls, integration: WearableIntegration, data: Dict[str, Any]) -> bool:
        """Send notification via Apple Push Notification Service."""
        try:
            # This would integrate with your APNs setup
            apns_payload = {
                'aps': {
                    'alert': {
                        'title': data['title'],
                        'body': data['message']
                    },
                    'sound': data.get('sound', 'default'),
                    'badge': data.get('badge', 1),
                    'category': data['category'],
                    'thread-id': 'medication-reminders'
                },
                'custom_data': {
                    'medication_id': data.get('medication_id'),
                    'is_critical': data.get('is_critical', False),
                    'actions': data.get('actions', [])
                }
            }
            
            # Send to device token (stored in integration.platform_user_id for APNs)
            device_token = integration.platform_user_id
            
            # Use your APNs service here
            # For now, simulate success
            logger.info(f"Would send APNs notification to {device_token}: {apns_payload}")
            return True
            
        except Exception as e:
            logger.error(f"APNs notification failed: {str(e)}")
            return False
    
    @classmethod
    def _send_samsung_health_notification(cls, integration: WearableIntegration, data: Dict[str, Any]) -> bool:
        """Send notification via Samsung Health SDK."""
        try:
            # This would integrate with Samsung Health Partner API
            payload = {
                'notification': {
                    'title': data['title'],
                    'body': data['message'],
                    'priority': 'high',
                    'collapse_key': 'medication_reminder'
                },
                'data': {
                    'type': 'medication_reminder',
                    'medication_id': str(data.get('medication_id', '')),
                    'is_critical': str(data.get('is_critical', False)),
                    'actions': json.dumps(data.get('actions', []))
                },
                'to': integration.platform_user_id  # FCM token
            }
            
            # Send via FCM or Samsung Health API
            logger.info(f"Would send Samsung notification: {payload}")
            return True
            
        except Exception as e:
            logger.error(f"Samsung Health notification failed: {str(e)}")
            return False
    
    @classmethod
    def _send_generic_notification(cls, integration: WearableIntegration, title: str, message: str, **kwargs) -> bool:
        """Send generic notification for other platforms."""
        try:
            # For other platforms, send via mobile push notification
            # which should trigger watch notifications if available
            
            notification_data = {
                'title': title,
                'message': message,
                'platform': integration.integration_type,
                'medication_id': kwargs.get('medication_id'),
                'is_critical': kwargs.get('is_critical', False)
            }
            
            logger.info(f"Sending generic notification for {integration.integration_type}: {notification_data}")
            return True
            
        except Exception as e:
            logger.error(f"Generic notification failed: {str(e)}")
            return False
    
    @classmethod
    def _send_healthkit_reminder(cls, integration: WearableIntegration, data: Dict[str, Any]) -> bool:
        """Send medication reminder via HealthKit."""
        try:
            # This would create a HealthKit medication reminder
            # which can trigger Apple Watch notifications
            
            healthkit_data = {
                'type': 'medication_reminder',
                'medication_name': data.get('medication_name'),
                'dosage': data.get('dosage'),
                'scheduled_time': data.get('scheduled_time'),
                'reminder_id': data.get('medication_id')
            }
            
            # Store as HealthKit sample
            logger.info(f"Would create HealthKit reminder: {healthkit_data}")
            return True
            
        except Exception as e:
            logger.error(f"HealthKit reminder failed: {str(e)}")
            return False
    
    @classmethod
    def _log_notification_delivery(cls, integration: WearableIntegration, notification_type: str, 
                                 title: str, message: str, success: bool, metadata: Dict[str, Any]):
        """Log notification delivery for audit and debugging."""
        try:
            NotificationDelivery.objects.create(
                integration=integration,
                user=integration.user,
                notification_type=notification_type,
                title=title,
                message=message,
                success=success,
                metadata=metadata,
                sent_at=timezone.now()
            )
        except Exception as e:
            logger.error(f"Failed to log notification delivery: {str(e)}")
    
    @classmethod
    def get_notification_analytics(cls, patient_id: int, days: int = 30) -> Dict:
        """Get notification delivery analytics."""
        from ..models import NotificationDelivery
        from django.db.models import Count
        
        notifications = NotificationDelivery.objects.filter(
            user_id=patient_id,
            sent_at__gte=timezone.now() - timezone.timedelta(days=days)
        )
        
        return {
            'total_notifications': notifications.count(),
            'successful_deliveries': notifications.filter(success=True).count(),
            'delivery_rate': (notifications.filter(success=True).count() / notifications.count() * 100) if notifications.count() > 0 else 0,
            'notification_types': dict(notifications.values_list('notification_type').annotate(count=Count('id'))),
            'engagement_metrics': {
                'delivered_count': notifications.filter(delivered_at__isnull=False).count(),
                'read_count': notifications.filter(read_at__isnull=False).count(),
                'responded_count': notifications.filter(user_response__isnull=False).count()
            }
        }

    @classmethod
    def send_batch_notifications(cls, patient_ids: List[int], notification_data: Dict) -> Dict:
        """Send notifications to multiple patients."""
        results = {'successful': [], 'failed': []}
        
        for patient_id in patient_ids:
            try:
                devices = WearableIntegration.objects.filter(
                    user_id=patient_id,
                    status=WearableIntegration.ConnectionStatus.CONNECTED
                )
                
                for device in devices:
                    success = cls.send_watch_notification(
                        device_id=device.platform_user_id,
                        title=notification_data['title'],
                        message=notification_data['message'],
                        is_critical=notification_data.get('priority') == 'critical'
                    )
                    
                    if success:
                        results['successful'].append(patient_id)
                    else:
                        results['failed'].append(patient_id)
                        
            except Exception as e:
                results['failed'].append({'patient_id': patient_id, 'error': str(e)})
        
        return results

# Make the function available at module level for medication service
def send_watch_notification(device_id: str, title: str, message: str, **kwargs) -> bool:
    """Wrapper function for compatibility with medication service."""
    return WearableNotificationService.send_watch_notification(
        device_id=device_id,
        title=title,
        message=message,
        **kwargs
    )