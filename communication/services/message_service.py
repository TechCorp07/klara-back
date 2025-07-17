import logging
from django.utils import timezone
from django.db import transaction
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)

class MessageException(Exception):
    """Exception for message service errors."""
    pass


def create_conversation(title, participants, created_by):
    """
    Create a new conversation with participants.
    
    Args:
        title: Conversation title
        participants: List of participant User objects or IDs
        created_by: User creating the conversation
    
    Returns:
        Conversation: The created conversation object
    
    Raises:
        MessageException: If conversation creation fails
    """
    try:
        from ..models import Conversation
        
        with transaction.atomic():
            # Create conversation
            conversation = Conversation.objects.create(
                title=title
            )
            
            # Add creator as participant
            conversation.participants.add(created_by)
            
            # Add other participants
            for participant in participants:
                # Handle participant IDs or User objects
                if isinstance(participant, int):
                    try:
                        user = User.objects.get(id=participant)
                        conversation.participants.add(user)
                    except User.DoesNotExist:
                        logger.warning(f"User {participant} not found when creating conversation")
                else:
                    conversation.participants.add(participant)
            
            return conversation
            
    except Exception as e:
        logger.error(f"Failed to create conversation: {str(e)}")
        raise MessageException(f"Failed to create conversation: {str(e)}")


def add_participant_to_conversation(conversation, user):
    """
    Add a participant to an existing conversation.
    
    Args:
        conversation: Conversation object
        user: User to add
    
    Returns:
        bool: True if successful
    
    Raises:
        MessageException: If operation fails
    """
    try:
        # Check if user is already a participant
        if conversation.participants.filter(id=user.id).exists():
            return True
            
        # Add user to conversation
        conversation.participants.add(user)
        
        # Create a system message about the new participant
        from ..models import Message
        
        Message.objects.create(
            conversation=conversation,
            sender=None,  # System message
            content=f"{user.get_full_name() or user.username} was added to the conversation."
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to add participant to conversation: {str(e)}")
        raise MessageException(f"Failed to add participant to conversation: {str(e)}")


def remove_participant_from_conversation(conversation, user):
    """
    Remove a participant from a conversation.
    
    Args:
        conversation: Conversation object
        user: User to remove
    
    Returns:
        bool: True if successful
    
    Raises:
        MessageException: If operation fails
    """
    try:
        # Check if user is a participant
        if not conversation.participants.filter(id=user.id).exists():
            return True
            
        # Remove user from conversation
        conversation.participants.remove(user)
        
        # Create a system message about the removed participant
        from ..models import Message
        
        Message.objects.create(
            conversation=conversation,
            sender=None,  # System message
            content=f"{user.get_full_name() or user.username} was removed from the conversation."
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to remove participant from conversation: {str(e)}")
        raise MessageException(f"Failed to remove participant to conversation: {str(e)}")


def send_message(conversation, sender, content):
    """
    Send a message in a conversation.
    
    Args:
        conversation: Conversation object
        sender: User sending the message
        content: Message content
    
    Returns:
        Message: The created message object
    
    Raises:
        MessageException: If message sending fails
    """
    try:
        from ..models import Message, Conversation
        from .notification_service import create_message_notification
        
        # Verify sender is a participant
        if not conversation.participants.filter(id=sender.id).exists():
            raise MessageException("Sender is not a participant in this conversation")
            
        # Create message
        message = Message.objects.create(
            conversation=conversation,
            sender=sender,
            content=content
        )
        
        # Mark as read by sender
        message.read_by.add(sender)
        
        # Update conversation timestamp
        conversation.updated_at = timezone.now()
        conversation.save(update_fields=['updated_at'])
        
        # Create notifications for other participants
        create_message_notification(message, conversation)
        
        return message
        
    except Exception as e:
        logger.error(f"Failed to send message: {str(e)}")
        raise MessageException(f"Failed to send message: {str(e)}")


def mark_messages_as_read(conversation, user):
    """
    Mark all messages in a conversation as read by a user.
    
    Args:
        conversation: Conversation object
        user: User marking messages as read
    
    Returns:
        int: Number of messages marked as read
    
    Raises:
        MessageException: If operation fails
    """
    try:
        # Verify user is a participant
        if not conversation.participants.filter(id=user.id).exists():
            raise MessageException("User is not a participant in this conversation")
            
        # Get unread messages
        unread_messages = conversation.messages.exclude(read_by=user)
        
        # Mark messages as read
        count = 0
        for message in unread_messages:
            message.read_by.add(user)
            count += 1
            
        return count
        
    except Exception as e:
        logger.error(f"Failed to mark messages as read: {str(e)}")
        raise MessageException(f"Failed to mark messages as read: {str(e)}")


def get_unread_message_count(user):
    """
    Get count of unread messages for a user across all conversations.
    
    Args:
        user: User to check unread messages for
    
    Returns:
        int: Count of unread messages
    """
    try:
        from ..models import Message, Conversation
        
        # Get conversations the user is in
        conversations = Conversation.objects.filter(participants=user)
        
        # Count unread messages
        unread_count = 0
        for conversation in conversations:
            unread_count += conversation.messages.exclude(read_by=user).count()
            
        return unread_count
        
    except Exception as e:
        logger.error(f"Failed to get unread message count: {str(e)}")
        return 0


def get_conversation_preview(conversation, for_user=None):
    """
    Get a preview of a conversation including last message.
    
    Args:
        conversation: Conversation object
        for_user: Optional user context for unread count
    
    Returns:
        dict: Conversation preview data
    """
    try:
        # Get last message
        last_message = conversation.messages.order_by('-created_at').first()
        
        # Count unread messages for user
        unread_count = 0
        if for_user:
            unread_count = conversation.messages.exclude(read_by=for_user).count()
        
        # Create preview
        preview = {
            'id': conversation.id,
            'title': conversation.title,
            'participant_count': conversation.participants.count(),
            'updated_at': conversation.updated_at,
            'unread_count': unread_count
        }
        
        # Add last message if exists
        if last_message:
            preview['last_message'] = {
                'id': last_message.id,
                'sender_id': last_message.sender.id if last_message.sender else None,
                'sender_name': last_message.sender.get_full_name() if last_message.sender else 'System',
                'content': last_message.content[:100] + '...' if len(last_message.content) > 100 else last_message.content,
                'created_at': last_message.created_at
            }
        
        return preview
        
    except Exception as e:
        logger.error(f"Failed to get conversation preview: {str(e)}")
        return {
            'id': conversation.id,
            'title': conversation.title,
            'error': "Failed to load preview"
        }
