from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Conversation, Message, Notification

User = get_user_model()


class UserBasicSerializer(serializers.ModelSerializer):
    """Simplified user serializer for nested relationships."""
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'role', 'role_display', 'profile_image')
        read_only_fields = ('id', 'role_display')
        ref_name = "CommunicationUserBasic"


class ConversationSerializer(serializers.ModelSerializer):
    """Serializer for conversations."""
    participants = UserBasicSerializer(many=True, read_only=True)
    participant_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Conversation
        fields = ('id', 'participants', 'participant_ids', 'title', 'created_at', 'updated_at', 'last_message', 'unread_count')
        read_only_fields = ('created_at', 'updated_at')
    
    def get_last_message(self, obj):
        """Get the last message in the conversation."""
        last_message = obj.messages.order_by('-created_at').first()
        if last_message:
            return {
                'id': last_message.id,
                'content': last_message.content,
                'sender': {
                    'id': last_message.sender.id if last_message.sender else None,
                    'username': last_message.sender.username if last_message.sender else "System",
                    'first_name': last_message.sender.first_name if last_message.sender else "",
                    'last_name': last_message.sender.last_name if last_message.sender else ""
                } if last_message.sender else {
                    'id': None,
                    'username': "System",
                    'first_name': "",
                    'last_name': ""
                },
                'created_at': last_message.created_at
            }
        return None
    
    def get_unread_count(self, obj):
        """Get the number of unread messages for the current user."""
        # For list view, this is precomputed in the queryset
        if hasattr(obj, 'unread_count'):
            return obj.unread_count
            
        # For detail view, compute it
        user = self.context['request'].user
        return obj.messages.exclude(read_by=user).filter(sender__isnull=False).count()


class ConversationDetailSerializer(ConversationSerializer):
    """Detailed serializer for retrieving a single conversation."""
    recent_messages = serializers.SerializerMethodField()
    
    class Meta(ConversationSerializer.Meta):
        fields = ConversationSerializer.Meta.fields + ('recent_messages',)
    
    def get_recent_messages(self, obj):
        """Get recent messages for the conversation."""
        # Limit to 20 most recent messages
        recent_messages = obj.messages.order_by('-created_at')[:20]
        
        return [{
            'id': message.id,
            'content': message.content,
            'sender': {
                'id': message.sender.id if message.sender else None,
                'username': message.sender.username if message.sender else "System",
                'first_name': message.sender.first_name if message.sender else "",
                'last_name': message.sender.last_name if message.sender else ""
            } if message.sender else {
                'id': None,
                'username': "System",
                'first_name': "",
                'last_name': ""
            },
            'created_at': message.created_at,
            'is_read': self.context['request'].user in message.read_by.all()
        } for message in recent_messages]


class CreateConversationSerializer(serializers.ModelSerializer):
    """Serializer for creating a new conversation."""
    participant_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True
    )
    initial_message = serializers.CharField(required=False)
    
    class Meta:
        model = Conversation
        fields = ('title', 'participant_ids', 'initial_message')
    
    def validate_participant_ids(self, value):
        """Validate that all participants exist."""
        # Check that all participant IDs are valid users
        users = User.objects.filter(id__in=value)
        if len(users) != len(value):
            missing_ids = set(value) - set(user.id for user in users)
            raise serializers.ValidationError(f"Users with IDs {missing_ids} do not exist")
        return value


class MessageSerializer(serializers.ModelSerializer):
    """Serializer for messages."""
    sender = UserBasicSerializer(read_only=True)
    is_read = serializers.SerializerMethodField()
    read_by_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Message
        fields = ('id', 'conversation', 'sender', 'content', 'created_at', 'is_read', 'read_by_count')
        read_only_fields = ('sender', 'created_at', 'is_read', 'read_by_count')
    
    def get_is_read(self, obj):
        """Check if message is read by current user."""
        user = self.context['request'].user
        return user in obj.read_by.all()
    
    def get_read_by_count(self, obj):
        """Get count of users who have read the message."""
        return obj.read_by.count()


class CreateMessageSerializer(serializers.ModelSerializer):
    """Serializer for creating a new message."""
    class Meta:
        model = Message
        fields = ('conversation', 'content')
    
    def validate_conversation(self, value):
        """Validate that the user is a participant in the conversation."""
        user = self.context['request'].user
        if not value.participants.filter(id=user.id).exists():
            raise serializers.ValidationError("You are not a participant in this conversation")
        return value


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications."""
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    
    class Meta:
        model = Notification
        fields = ('id', 'title', 'message', 'notification_type', 'notification_type_display', 'related_object_id', 'related_object_type', 'read_at', 'created_at')
        read_only_fields = ('created_at',)


class MarkMessagesReadSerializer(serializers.Serializer):
    """Serializer for marking messages as read."""
    conversation_id = serializers.IntegerField(required=False)
    message_id = serializers.IntegerField(required=False)
    user_id = serializers.IntegerField(required=False)
    
    def validate(self, data):
        """Validate that at least one ID is provided."""
        if not any(field in data for field in ['conversation_id', 'message_id', 'user_id']):
            raise serializers.ValidationError("At least one of conversation_id, message_id, or user_id is required")
        return data


class ParticipantManagementSerializer(serializers.Serializer):
    """Serializer for managing conversation participants."""
    user_id = serializers.IntegerField(required=True)


class BulkMessageSerializer(serializers.Serializer):
    """Serializer for sending bulk messages."""
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True
    )
    content = serializers.CharField(required=True)
    title = serializers.CharField(required=False, allow_blank=True)
    create_individual_conversations = serializers.BooleanField(default=False)


class MessageSearchSerializer(serializers.Serializer):
    """Serializer for searching messages."""
    query = serializers.CharField(required=True)
    conversation_id = serializers.IntegerField(required=False)
    start_date = serializers.DateTimeField(required=False)
    end_date = serializers.DateTimeField(required=False)
    sender_id = serializers.IntegerField(required=False)

class BulkCriticalAlertSerializer(serializers.Serializer):
    """Serializer for sending bulk critical alerts."""
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True,
        help_text="List of user IDs to send alerts to"
    )
    title = serializers.CharField(
        max_length=255,
        required=True,
        help_text="Alert title"
    )
    message = serializers.CharField(
        required=True,
        help_text="Alert message content"
    )
    alert_type = serializers.ChoiceField(
        choices=[
            ('MEDICATION', 'Medication Alert'),
            ('APPOINTMENT', 'Appointment Alert'),
            ('SYSTEM', 'System Alert'),
            ('EMERGENCY', 'Emergency Alert'),
            ('GENERAL', 'General Alert')
        ],
        default='GENERAL',
        required=False,
        help_text="Type of alert being sent"
    )
    
    def validate_user_ids(self, value):
        """Validate that all user IDs exist."""
        existing_users = User.objects.filter(id__in=value)
        if len(existing_users) != len(value):
            missing_ids = set(value) - set(user.id for user in existing_users)
            raise serializers.ValidationError(f"Users with IDs {missing_ids} do not exist")
        return value

