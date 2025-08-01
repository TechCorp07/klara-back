import logging
from django.utils import timezone
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

class NotificationException(Exception):
    """Exception for notification errors."""
    pass

def create_notification(user, title, message, notification_type, related_object_id=None, related_object_type=None):
    """
    Create a notification for a user.
    """
    try:
        from ..models import Notification

        if related_object_id is None:
            related_object_id = 1
        if related_object_type is None:
            related_object_type = 'general'

        if isinstance(related_object_id, str) and related_object_id.isdigit():
            related_object_id = int(related_object_id)
        elif not isinstance(related_object_id, int):
            related_object_id = 1

        notification = Notification.objects.create(
            user=user,
            title=title,
            message=message,
            notification_type=notification_type,
            related_object_id=related_object_id,
            related_object_type=related_object_type
        )
        
        # Attempt to send email notification if enabled
        if getattr(settings, 'EMAIL_NOTIFICATIONS_ENABLED', False):
            try:
                send_email_notification(
                    user=user,
                    title=title,
                    message=message,
                    notification_type=notification_type
                )
            except Exception as e:
                # Log email failure but continue with in-app notification
                logger.warning(f"Email notification failed for user {user.id}: {str(e)}")
        
        return notification
        
    except Exception as e:
        logger.error(f"Failed to create notification: {str(e)}")
        raise NotificationException(f"Failed to create notification: {str(e)}")


def mark_notification_as_read(notification_id, user):
    """
    Mark a notification as read.
    
    Args:
        notification_id: ID of the notification to mark as read
        user: User marking the notification as read
    
    Returns:
        bool: True if successful
    
    Raises:
        NotificationException: If operation fails
    """
    try:
        from ..models import Notification
        
        notification = Notification.objects.get(id=notification_id, user=user)
        
        # Skip if already read
        if notification.read_at:
            return True
            
        notification.read_at = timezone.now()
        notification.save(update_fields=['read_at'])
        
        return True
        
    except Notification.DoesNotExist:
        raise NotificationException(f"Notification {notification_id} not found for user {user.id}")
    except Exception as e:
        logger.error(f"Failed to mark notification as read: {str(e)}")
        raise NotificationException(f"Failed to mark notification as read: {str(e)}")


def send_email_notification(user, title, message, notification_type):
    """
    Send an email notification to a user.
    
    Args:
        user: User to send email to
        title: Email subject
        message: Email message
        notification_type: Type of notification
    
    Returns:
        bool: True if successful
    
    Raises:
        NotificationException: If email sending fails
    """
    try:
        if not user.email:
            logger.warning(f"Cannot send email notification - no email for user {user.id}")
            return False
            
        # Prepare email context
        context = {
            'user_name': user.get_full_name() or user.username,
            'title': title,
            'message': message,
            'notification_type': notification_type,
            'portal_url': settings.FRONTEND_URL,
            'notification_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Render email content
        template_name = f'communication/emails/{notification_type.lower()}_notification.html'
        try:
            html_content = render_to_string(template_name, context)
        except:
            # Fallback to generic template if specific one doesn't exist
            html_content = render_to_string('communication/emails/generic_notification.html', context)
            
        text_content = strip_tags(html_content)
        
        # Create email
        subject = title
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = user.email
        
        # Send email
        email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        email.attach_alternative(html_content, "text/html")
        email.send()
        
        logger.info(f"Email notification sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email notification: {str(e)}")
        raise NotificationException(f"Failed to send email notification: {str(e)}")


def create_message_notification(message, conversation):
    """
    Create notification for a new message.
    
    Args:
        message: The Message object
        conversation: The Conversation object
    
    Returns:
        list: List of created notifications
    """
    try:
        # Create notifications for all participants except sender
        notifications = []
        for participant in conversation.participants.exclude(id=message.sender.id):
            notification = create_notification(
                user=participant,
                title='New Message',
                message=f'You have a new message from {message.sender.get_full_name() or message.sender.username}',
                notification_type='message',
                related_object_id=conversation.id,
                related_object_type='conversation'
            )
            notifications.append(notification)
            
        return notifications
        
    except Exception as e:
        logger.error(f"Failed to create message notification: {str(e)}")
        # Continue without notification if it fails
        return []


def send_bulk_notifications(users, title, message, notification_type, related_object_id=None, related_object_type=None):
    """
    Send notifications to multiple users.
    
    Args:
        users: QuerySet or list of users
        title: Notification title
        message: Notification message
        notification_type: Type of notification
        related_object_id: ID of the related object (optional)
        related_object_type: Type of the related object (optional)
    
    Returns:
        int: Number of notifications sent
    """
    from ..models import Notification
    
    notifications = []
    for user in users:
        try:
            notification = Notification(
                user=user,
                title=title,
                message=message,
                notification_type=notification_type,
                related_object_id=related_object_id,
                related_object_type=related_object_type
            )
            notifications.append(notification)
        except Exception as e:
            logger.error(f"Failed to create notification for user {user.id}: {str(e)}")
    
    # Bulk create all notifications
    created = Notification.objects.bulk_create(notifications)
    
    # Send emails if enabled
    if getattr(settings, 'EMAIL_NOTIFICATIONS_ENABLED', False):
        for user in users:
            try:
                send_email_notification(
                    user=user,
                    title=title,
                    message=message,
                    notification_type=notification_type
                )
            except Exception as e:
                logger.warning(f"Email notification failed for user {user.id}: {str(e)}")
    
    return len(created)


def send_critical_rare_disease_alert(self, user, medication_name, severity_level='HIGH'):
    """Send critical alerts for rare disease patients."""
    try:
        # Create notification
        notification = self.create_notification(
            user=user,
            title=f"CRITICAL: {medication_name} Alert",
            message=f"Immediate attention required for {medication_name}. Contact your provider.",
            notification_type='system',
            priority='CRITICAL'
        )
        
        # Send via all available channels for critical alerts
        channels_sent = []
        
        # Email
        if self.send_email_notification(user, notification):
            channels_sent.append('email')
        
        # SMS
        if user.phone_number and self.send_sms_notification(user, notification):
            channels_sent.append('sms')
        
        # Push notification
        if self.send_push_notification(user, notification):
            channels_sent.append('push')
        
        # Smartwatch (if available)
        if hasattr(user, 'patient_profile') and user.patient_profile.smartwatch_integration_active:
            from wearables.services.notification_service import WearableNotificationService
            WearableNotificationService.send_critical_alert(user, medication_name, severity_level)
            channels_sent.append('smartwatch')
        
        return len(channels_sent) > 0
        
    except Exception as e:
        logger.error(f"Failed to send critical alert: {str(e)}")
        return False


def notify_care_team_emergency(self, patient, emergency_type, details):
    """Notify entire care team of patient emergency."""
    care_team = self._get_care_team(patient)
    
    for team_member in care_team:
        self.send_emergency_notification(
            user=team_member,
            patient=patient,
            emergency_type=emergency_type,
            details=details
        )


def send_sms_notification(self, user, notification):
    """Send SMS notification via configured provider."""
    try:
        if not user.phone_number:
            return False
            
        from django.conf import settings
        
        if settings.SMS_PROVIDER == 'twilio':
            return self._send_twilio_sms(user.phone_number, notification.message)
        elif settings.SMS_PROVIDER == 'vonage':
            return self._send_vonage_sms(user.phone_number, notification.message)
        
        return False
        
    except Exception as e:
        logger.error(f"SMS notification failed: {str(e)}")
        return False


def _send_twilio_sms(self, phone_number, message):
    """Send SMS via Twilio."""
    try:
        from twilio.rest import Client
        from django.conf import settings
        
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        
        message = client.messages.create(
            body=message,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Twilio SMS failed: {str(e)}")
        return False


class NotificationService:
    """
    Service class for managing notifications.
    Provides a clean interface for notification operations.
    """
    
    def create_notification(self, user, title, message, notification_type, 
                          related_object_id=None, related_object_type=None):
        """Create a notification using the function."""
        return create_notification(
            user=user,
            title=title,
            message=message,
            notification_type=notification_type,
            related_object_id=related_object_id,
            related_object_type=related_object_type
        )
    
    def send_bulk_notifications(self, users, title, message, notification_type, 
                              related_object_id=None, related_object_type=None):
        """Send bulk notifications using the function."""
        return send_bulk_notifications(
            users=users,
            title=title,
            message=message,
            notification_type=notification_type,
            related_object_id=related_object_id,
            related_object_type=related_object_type
        )
    
    def mark_notification_as_read(self, notification_id, user):
        """Mark notification as read using the function."""
        return mark_notification_as_read(notification_id, user)
