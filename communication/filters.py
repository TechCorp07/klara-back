# communication/filters.py
from django_filters import rest_framework as filters
from .models import Conversation, Message, Notification

class ConversationFilterSet(filters.FilterSet):
    participant = filters.NumberFilter(field_name='participants__id')
    
    class Meta:
        model = Conversation
        fields = ['participants']
    
    def filter_participant(self, queryset, name, value):
        """Custom filter for participants to handle M2M relationship properly."""
        if value:
            return queryset.filter(participants__id=value)
        return queryset

class MessageFilterSet(filters.FilterSet):
    class Meta:
        model = Message
        fields = ['conversation', 'sender']

class NotificationFilterSet(filters.FilterSet):
    # Add date range filters if needed
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = Notification
        fields = ['notification_type', 'read_at']
