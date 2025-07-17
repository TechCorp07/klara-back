from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
import logging

from .models import Conversation, Message, Notification

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Message)
def handle_new_message(sender, instance, created, **kwargs):
    """
    Handle post-save actions for new messages.
    - Send notifications to conversation participants
    - Update conversation timestamp
    """
    try:
        # Skip if this is not a new message or it's a system message
        if not created or not instance.sender:
            return
            
        # Update conversation's updated_at timestamp
        instance.conversation.updated_at = timezone.now()
        instance.conversation.save(update_fields=['updated_at'])
        
        # Create notifications for other participants
        for participant in instance.conversation.participants.exclude(id=instance.sender.id):
            try:
                Notification.objects.create(
                    user=participant,
                    title='New Message',
                    message=f'You have a new message from {instance.sender.get_full_name() or instance.sender.username}',
                    notification_type='message',
                    related_object_id=instance.conversation.id,
                    related_object_type='conversation'
                )
            except Exception as e:
                logger.error(f"Failed to create notification for user {participant.id}: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error in handle_new_message signal handler: {str(e)}")


@receiver(post_save, sender=Notification)
def handle_new_notification(sender, instance, created, **kwargs):
    """
    Handle post-save actions for new notifications.
    - Send external notifications (email, push) if enabled
    """
    try:
        # Skip if this is not a new notification
        if not created:
            return
            
        # Check if email notifications are enabled
        from django.conf import settings
        if not getattr(settings, 'EMAIL_NOTIFICATIONS_ENABLED', False):
            return
            
        # Send email notification asynchronously with Celery if available
        try:
            from communication.tasks import send_email_notification_task
            send_email_notification_task.delay(instance.id)
        except ImportError:
            # Fallback to synchronous email if Celery is not available
            try:
                from .services.notification_service import send_email_notification
                
                send_email_notification(
                    user=instance.user,
                    title=instance.title,
                    message=instance.message,
                    notification_type=instance.notification_type
                )
            except Exception as email_error:
                logger.error(f"Failed to send email notification: {str(email_error)}")
                
    except Exception as e:
        logger.error(f"Error in handle_new_notification signal handler: {str(e)}")


@receiver(pre_save, sender=Notification)
def handle_notification_read(sender, instance, **kwargs):
    """
    Handle when a notification is marked as read.
    """
    try:
        # Check if this is a read action
        if instance.pk and not instance.read_at and instance._state.adding is False:
            # Get the previous state
            try:
                old_instance = Notification.objects.get(pk=instance.pk)
                
                # If we're transitioning from unread to read
                if not old_instance.read_at and instance.read_at:
                    # Log the read event if needed
                    logger.debug(f"Notification {instance.pk} marked as read by user {instance.user.id}")
                    
            except Notification.DoesNotExist:
                pass
                
    except Exception as e:
        logger.error(f"Error in handle_notification_read signal handler: {str(e)}")
