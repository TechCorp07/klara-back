from celery import shared_task
from __future__ import absolute_import, unicode_literals
import logging
from django.utils import timezone
from datetime import timedelta
from django.db.models import F, Count, Q
from .services.notification_service import NotificationService

logger = logging.getLogger(__name__)


@shared_task
def send_email_notification_task(notification_id):
    """
    Task to send an email notification asynchronously.
    
    Args:
        notification_id: ID of the notification to send email for
    
    Returns:
        str: Status message
    """
    try:
        from .models import Notification
        from .services.notification_service import send_email_notification
        
        # Get the notification
        notification = Notification.objects.get(pk=notification_id)
        
        # Skip if already older than 1 hour (avoid duplicate delayed emails)
        if notification.created_at < timezone.now() - timedelta(hours=1):
            return f"Skipped sending email for notification {notification_id} - too old"
        
        # Send email
        send_email_notification(
            user=notification.user,
            title=notification.title,
            message=notification.message,
            notification_type=notification.notification_type
        )
        
        return f"Email sent for notification {notification_id}"
        
    except Exception as e:
        logger.error(f"Failed to send email notification: {str(e)}")
        return f"Failed to send email notification: {str(e)}"


@shared_task
def clean_old_notifications():
    """
    Task to clean up old notifications.
    Deletes read notifications older than 90 days and
    unread notifications older than 180 days.
    
    Returns:
        str: Status message with counts
    """
    try:
        from .models import Notification
        
        # Delete read notifications older than 90 days
        read_cutoff = timezone.now() - timedelta(days=90)
        read_deletion_count = Notification.objects.filter(
            read_at__lt=read_cutoff
        ).delete()[0]
        
        # Delete unread notifications older than 180 days
        unread_cutoff = timezone.now() - timedelta(days=180)
        unread_deletion_count = Notification.objects.filter(
            read_at__isnull=True,
            created_at__lt=unread_cutoff
        ).delete()[0]
        
        return f"Deleted {read_deletion_count} read and {unread_deletion_count} unread old notifications"
        
    except Exception as e:
        logger.error(f"Failed to clean old notifications: {str(e)}")
        return f"Failed to clean old notifications: {str(e)}"


@shared_task
def send_message_digest(interval='daily'):
    """
    Task to send a digest of unread messages to users.
    
    Args:
        interval: Frequency of digest ('daily' or 'weekly')
    
    Returns:
        str: Status message with counts
    """
    try:
        from django.contrib.auth import get_user_model
        from .models import Conversation, Message
        from .services.notification_service import send_email_notification
        
        User = get_user_model()
        
        # Determine time cutoff based on interval
        if interval == 'weekly':
            cutoff = timezone.now() - timedelta(days=7)
            digest_type = "Weekly"
        else:  # Default to daily
            cutoff = timezone.now() - timedelta(days=1)
            digest_type = "Daily"
        
        # Find users with unread messages since cutoff
        users_with_unread = User.objects.filter(
            conversations__messages__created_at__gt=cutoff
        ).exclude(
            conversations__messages__read_by=F('id')
        ).distinct()
        
        # For each user, send a digest
        sent_count = 0
        for user in users_with_unread:
            try:
                # Count unread messages by conversation
                conversations = Conversation.objects.filter(
                    participants=user,
                    messages__created_at__gt=cutoff
                ).exclude(
                    messages__read_by=user
                ).annotate(
                    unread_count=Count('messages', filter=~Q(messages__read_by=user))
                ).filter(
                    unread_count__gt=0
                )
                
                # Skip if no unread messages
                if not conversations.exists():
                    continue
                
                # Calculate total unread
                total_unread = sum(c.unread_count for c in conversations)
                
                # Get conversation summaries
                conversation_summaries = []
                for conversation in conversations[:5]:  # Limit to 5 conversations in digest
                    last_message = conversation.messages.order_by('-created_at').first()
                    
                    # Prepare a summary for this conversation
                    title = conversation.title
                    if not title:
                        # Generate a title based on participants
                        other_participants = conversation.participants.exclude(id=user.id)[:3]
                        names = [p.get_full_name() or p.username for p in other_participants]
                        title = ", ".join(names)
                        if conversation.participants.count() > 4:  # user + 3 others
                            title += f" and {conversation.participants.count() - 4} others"
                    
                    # Add the summary
                    conversation_summaries.append({
                        'title': title,
                        'unread_count': conversation.unread_count,
                        'last_message': last_message.content[:100] + '...' if last_message and len(last_message.content) > 100 else (last_message.content if last_message else ""),
                        'last_sender': last_message.sender.get_full_name() if last_message and last_message.sender else "System"
                    })
                
                # Prepare the digest message
                digest_title = f"{digest_type} Message Digest: {total_unread} unread messages"
                
                digest_content = f"You have {total_unread} unread messages from {conversations.count()} conversations:\n\n"
                
                for summary in conversation_summaries:
                    digest_content += f"• {summary['title']}: {summary['unread_count']} unread messages\n"
                    digest_content += f"  Last message from {summary['last_sender']}: \"{summary['last_message']}\"\n\n"
                
                digest_content += f"Log in to the Klararety Health Platform to view and respond to these messages."
                
                # Send the digest as an email
                send_email_notification(
                    user=user,
                    title=digest_title,
                    message=digest_content,
                    notification_type='digest'
                )
                
                sent_count += 1
                
            except Exception as user_error:
                logger.error(f"Error sending digest to user {user.id}: {str(user_error)}")
        
        return f"Sent {digest_type.lower()} message digest to {sent_count} users"
        
    except Exception as e:
        logger.error(f"Failed to send message digest: {str(e)}")
        return f"Failed to send message digest: {str(e)}"


@shared_task
def sync_conversations_with_healthcare_events():
    """
    Task to create or update conversations based on healthcare events.
    
    This task looks for healthcare events like appointments, condition updates,
    or medication changes and creates appropriate conversations between
    patients and providers if they don't already exist.
    
    Returns:
        str: Status message with counts
    """
    try:
        from django.contrib.auth import get_user_model
        from .models import Conversation, Message
        from .services.message_service import create_conversation, send_message
        from healthcare.models import MedicalRecord
        from telemedicine.models import Appointment
        
        User = get_user_model()
        
        # Get recent appointments without conversations
        recent_cutoff = timezone.now() - timedelta(days=7)
        recent_appointments = Appointment.objects.filter(
            created_at__gt=recent_cutoff,
            status__in=['confirmed', 'scheduled'],
        )
        
        conversations_created = 0
        messages_sent = 0
        
        for appointment in recent_appointments:
            try:
                patient = appointment.patient
                provider = appointment.provider
                
                # Skip if either user is missing
                if not patient or not provider:
                    continue
                
                # Check if a conversation already exists between these users
                existing_conversation = Conversation.objects.filter(
                    participants=patient
                ).filter(
                    participants=provider
                ).first()
                
                if not existing_conversation:
                    # Create a new conversation
                    conversation = create_conversation(
                        title=f"Care conversation: {patient.get_full_name()} & {provider.get_full_name()}",
                        participants=[patient, provider],
                        created_by=provider
                    )
                    
                    # Send an initial message
                    appointment_time = appointment.scheduled_time.strftime('%A, %B %d at %I:%M %p')
                    initial_message = f"Hello {patient.first_name},\n\nI'm Dr. {provider.last_name} and I'll be seeing you for your {appointment.get_appointment_type_display()} on {appointment_time}. Feel free to message me if you have any questions before your appointment."
                    
                    send_message(
                        conversation=conversation,
                        sender=provider,
                        content=initial_message
                    )
                    
                    conversations_created += 1
                    messages_sent += 1
                
            except Exception as appt_error:
                logger.error(f"Error processing appointment {appointment.id}: {str(appt_error)}")
        
        return f"Created {conversations_created} new conversations and sent {messages_sent} initial messages"
        
    except Exception as e:
        logger.error(f"Failed to sync conversations with healthcare events: {str(e)}")
        return f"Failed to sync conversations with healthcare events: {str(e)}"

@shared_task
def send_delayed_notification(user_id, title, message, notification_type, delay_minutes=0):
    """Send notification after specified delay."""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    try:
        user = User.objects.get(id=user_id)
        notification_service = NotificationService()
        
        notification_service.create_notification(
            user=user,
            title=title,
            message=message,
            notification_type=notification_type
        )
        
        return True
    except Exception as e:
        logger.error(f"Delayed notification failed: {str(e)}")
        return False
