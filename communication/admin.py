from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import Conversation, Message, Notification


class MessageInline(admin.TabularInline):
    """Inline admin for messages within a conversation."""
    model = Message
    extra = 0
    fields = ('sender', 'content', 'created_at', 'read_by_count')
    readonly_fields = ('sender', 'created_at', 'read_by_count')
    ordering = ('-created_at',)
    max_num = 10
    
    def read_by_count(self, obj):
        return obj.read_by.count()
    read_by_count.short_description = "Read By"


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    """Admin configuration for Conversation model."""
    list_display = ('id', 'title', 'participant_count', 'message_count', 'last_activity', 'created_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('title', 'participants__username', 'participants__first_name', 'participants__last_name', 'messages__content')
    date_hierarchy = 'updated_at'
    filter_horizontal = ('participants',)
    readonly_fields = ('created_at', 'updated_at', 'message_count', 'last_activity')
    inlines = [MessageInline]
    
    fieldsets = (
        ('Conversation Info', {
            'fields': ('title', 'participants', 'created_at', 'updated_at')
        }),
        ('Stats', {
            'fields': ('message_count', 'last_activity')
        }),
    )
    
    def participant_count(self, obj):
        """Display participant count with a link to filter messages by conversation."""
        count = obj.participants.count()
        url = reverse('admin:communication_message_changelist') + f'?conversation__id__exact={obj.id}'
        return format_html('<a href="{}">{} participants</a>', url, count)
    participant_count.short_description = "Participants"
    
    def message_count(self, obj):
        """Display message count with a link to filter messages by conversation."""
        count = obj.messages.count()
        url = reverse('admin:communication_message_changelist') + f'?conversation__id__exact={obj.id}'
        return format_html('<a href="{}">{} messages</a>', url, count)
    message_count.short_description = "Messages"
    
    def last_activity(self, obj):
        """Display the last activity time."""
        last_message = obj.messages.order_by('-created_at').first()
        if last_message:
            return last_message.created_at
        return obj.updated_at
    last_activity.short_description = "Last Activity"


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    """Admin configuration for Message model."""
    list_display = ('id', 'sender_name', 'conversation_link', 'content_preview', 'created_at', 'read_by_count')
    list_filter = ('created_at', 'sender', 'conversation')
    search_fields = ('content', 'sender__username', 'sender__first_name', 'sender__last_name')
    date_hierarchy = 'created_at'
    readonly_fields = ('created_at', 'read_by_count')
    filter_horizontal = ('read_by',)
    
    fieldsets = (
        ('Message Info', {
            'fields': ('conversation', 'sender', 'content', 'created_at')
        }),
        ('Read Status', {
            'fields': ('read_by', 'read_by_count')
        }),
    )
    
    def sender_name(self, obj):
        """Display sender name or 'System' for system messages."""
        if obj.sender:
            return obj.sender.get_full_name() or obj.sender.username
        return "System"
    sender_name.short_description = "Sender"
    
    def conversation_link(self, obj):
        """Display conversation with a link to the conversation admin."""
        url = reverse('admin:communication_conversation_change', args=[obj.conversation.id])
        title = obj.conversation.title or f"Conversation {obj.conversation.id}"
        return format_html('<a href="{}">{}</a>', url, title)
    conversation_link.short_description = "Conversation"
    
    def content_preview(self, obj):
        """Display a preview of the message content."""
        max_length = 50
        if len(obj.content) > max_length:
            return obj.content[:max_length] + "..."
        return obj.content
    content_preview.short_description = "Content"
    
    def read_by_count(self, obj):
        """Display the count of users who have read the message."""
        count = obj.read_by.count()
        if count == 0:
            return "0 users"
        return format_html("{} users", count)
    read_by_count.short_description = "Read By"


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    """Admin configuration for Notification model."""
    list_display = ('id', 'user_link', 'title', 'notification_type', 'created_at', 'is_read')
    list_filter = ('notification_type', 'created_at', 'read_at')
    search_fields = ('title', 'message', 'user__username', 'user__first_name', 'user__last_name')
    date_hierarchy = 'created_at'
    readonly_fields = ('created_at',)
    
    fieldsets = (
        ('Notification Info', {
            'fields': ('user', 'title', 'message', 'notification_type', 'created_at')
        }),
        ('Status', {
            'fields': ('read_at',)
        }),
        ('Related Object', {
            'fields': ('related_object_id', 'related_object_type'),
            'classes': ('collapse',),
        }),
    )
    
    def user_link(self, obj):
        """Display user with a link to the user admin."""
        url = reverse('admin:users_user_change', args=[obj.user.id])
        return format_html('<a href="{}">{}</a>', url, obj.user.get_full_name() or obj.user.username)
    user_link.short_description = "User"
    
    def is_read(self, obj):
        """Display if the notification has been read."""
        if obj.read_at:
            return format_html('<span style="color:green;">✓</span> Read')
        return format_html('<span style="color:red;">✗</span> Unread')
    is_read.short_description = "Read Status"
