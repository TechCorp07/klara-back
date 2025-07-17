# serializers.py
from rest_framework import serializers
from community.models import (
    CommunityGroup,
    CommunityMembership,
    CommunityPost,
    CommunityComment,
    CommunityEvent,
    EventAttendee,
    CommunityResource,
    CommunityNotification,
    CommunityAccessibilitySetting
)

class CommunityGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityGroup
        fields = '__all__'
        read_only_fields = ['member_count', 'post_count', 'created_at', 'updated_at']


class CommunityMembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityMembership
        fields = '__all__'
        read_only_fields = ['joined_at', 'last_active_at']


class CommunityPostSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CommunityPost
        fields = '__all__'
        read_only_fields = [
            'created_at', 'updated_at', 'view_count', 'like_count',
            'comment_count', 'author_name'
        ]
    
    def get_author_name(self, obj):
        return obj.author.get_full_name() or obj.author.username


class CommunityCommentSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    replies = serializers.SerializerMethodField()
    
    class Meta:
        model = CommunityComment
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at', 'like_count', 'author_name', 'replies']
    
    def get_author_name(self, obj):
        return obj.author.get_full_name() or obj.author.username
    
    def get_replies(self, obj):
        # Return only immediate children if parent == None
        if obj.parent is None:
            replies_qs = obj.replies.filter(status='published').order_by('created_at')
            return CommunityCommentSerializer(replies_qs, many=True, context=self.context).data
        return []


class CommunityEventSerializer(serializers.ModelSerializer):
    creator_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CommunityEvent
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at', 'current_attendees', 'creator_name']
    
    def get_creator_name(self, obj):
        return obj.creator.get_full_name() or obj.creator.username


class EventAttendeeSerializer(serializers.ModelSerializer):
    user_name = serializers.SerializerMethodField()
    
    class Meta:
        model = EventAttendee
        fields = '__all__'
        read_only_fields = ['registered_at', 'updated_at', 'user_name']
    
    def get_user_name(self, obj):
        return obj.user.get_full_name() or obj.user.username


class CommunityResourceSerializer(serializers.ModelSerializer):
    creator_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CommunityResource
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at', 'view_count', 'download_count', 'creator_name']
    
    def get_creator_name(self, obj):
        return obj.creator.get_full_name() or obj.creator.username


class CommunityNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityNotification
        fields = '__all__'
        read_only_fields = ['created_at', 'read_at']


class CommunityAccessibilitySettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityAccessibilitySetting
        fields = '__all__'
        read_only_fields = ['user', 'updated_at']


def get_content(self, obj):
    """
    Example helper function that could transform content based on user accessibility preferences.
    It's not called by default – you'd need to use it in a field or override to_serializer().
    """
    content = obj.content
    request = self.context.get('request')
    
    if not request or not request.user.is_authenticated:
        return content
    
    accessibility = getattr(request, 'accessibility', None)
    if not accessibility:
        return content
    
    # Screen reader enhancements
    if accessibility.screen_reader_optimized:
        if obj.contains_sensitive_content:
            content = (
                '<span class="sr-only">Warning: This post contains sensitive content.</span>\n'
                + content
            )
        if obj.is_expert_response:
            content = (
                '<span class="sr-only">This is an expert response from a healthcare professional.</span>\n'
                + content
            )
    
    # Additional transformations for cognitive_support, etc.
    if accessibility.cognitive_support:
        # Placeholder for text simplification or similar
        pass
    
    return content
