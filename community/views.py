from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
import django_filters
from django_filters.rest_framework import DjangoFilterBackend

from community.permissions import (
    IsCommunityMemberOrPublic,
    IsPostAuthorOrReadOnly,
    IsModerationPermitted,
)
from community.models import (
    CommunityGroup,
    CommunityMembership,
    CommunityPost,
    CommunityComment,
    CommunityEvent,
    EventAttendee,
    CommunityResource,
    CommunityNotification,
    CommunityAccessibilitySetting,
    HealthTopicTag
)
from community.serializers import (
    CommunityGroupSerializer,
    CommunityMembershipSerializer,
    CommunityPostSerializer,
    CommunityCommentSerializer,
    CommunityEventSerializer,
    EventAttendeeSerializer,
    CommunityResourceSerializer,
    CommunityNotificationSerializer,
    CommunityAccessibilitySettingSerializer
)

# Example custom permission
class IsAdminOrSelfOnly(permissions.BasePermission):
    """
    Only an admin or the object's owner can access/modify.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        # For something like accessibility settings, ensure obj.user == request.user
        return getattr(obj, 'user', None) == request.user


class CommunityGroupFilter(django_filters.FilterSet):
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    min_members = django_filters.NumberFilter(field_name='member_count', lookup_expr='gte')
    health_topic = django_filters.ModelMultipleChoiceFilter(
        field_name='health_topics',
        queryset=HealthTopicTag.objects.all()
    )
    has_medical_professional = django_filters.BooleanFilter(field_name='has_medical_professional')
    is_condition_specific = django_filters.BooleanFilter(field_name='is_condition_specific')
    condition_name = django_filters.CharFilter(field_name='condition_name', lookup_expr='icontains')
    
    class Meta:
        model = CommunityGroup
        fields = {
            'name': ['exact', 'icontains'],
            'group_type': ['exact'],
            'is_private': ['exact'],
            'is_moderated': ['exact'],
            'is_peer_support': ['exact'],
        }


class CommunityPostFilter(django_filters.FilterSet):
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    is_question = django_filters.BooleanFilter(field_name='is_question')
    is_expert_response = django_filters.BooleanFilter(field_name='is_expert_response')
    expert_verified = django_filters.BooleanFilter(field_name='expert_verified')
    health_topic = django_filters.ModelMultipleChoiceFilter(
        field_name='health_topics',
        queryset=HealthTopicTag.objects.all()
    )
    
    class Meta:
        model = CommunityPost
        fields = {
            'title': ['exact', 'icontains'],
            'post_type': ['exact'],
            'status': ['exact'],
            'contains_sensitive_content': ['exact'],
        }


class CommunityGroupViewSet(viewsets.ModelViewSet):
    queryset = CommunityGroup.objects.all()
    serializer_class = CommunityGroupSerializer
    permission_classes = [permissions.IsAuthenticated, IsCommunityMemberOrPublic]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = CommunityGroupFilter
    search_fields = ['name', 'description', 'group_type', 'condition_name']
    ordering_fields = ['name', 'created_at', 'member_count', 'post_count']
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        if user.is_staff or getattr(user, 'role', None) == 'admin':
            return CommunityGroup.objects.all()
        return CommunityGroup.objects.filter(
            Q(is_private=False) | Q(memberships__user=user, memberships__status='approved')
        ).distinct()
    
    @action(detail=True, methods=['post'])
    def join(self, request, pk=None):
        group = self.get_object()
        user = request.user
        
        if CommunityMembership.objects.filter(user=user, group=group).exists():
            return Response({"detail": "You are already a member of this group."}, status=status.HTTP_400_BAD_REQUEST)
        
        membership_status = 'pending' if group.is_private else 'approved'
        membership = CommunityMembership.objects.create(
            user=user,
            group=group,
            role='member',
            status=membership_status
        )
        
        if membership_status == 'approved':
            group.member_count += 1
            group.save(update_fields=['member_count'])
        
        return Response(CommunityMembershipSerializer(membership).data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def leave(self, request, pk=None):
        group = self.get_object()
        user = request.user
        try:
            membership = CommunityMembership.objects.get(user=user, group=group)
        except CommunityMembership.DoesNotExist:
            return Response({"detail": "You are not a member of this group."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Save status before deleting
        old_status = membership.status
        membership.delete()
        
        if old_status == 'approved':
            group.member_count = max(0, group.member_count - 1)
            group.save(update_fields=['member_count'])
        
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True)
    def members(self, request, pk=None):
        group = self.get_object()
        memberships = group.memberships.filter(status='approved')
        page = self.paginate_queryset(memberships)
        if page is not None:
            serializer = CommunityMembershipSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = CommunityMembershipSerializer(memberships, many=True)
        return Response(serializer.data)


class CommunityMembershipViewSet(viewsets.ModelViewSet):
    queryset = CommunityMembership.objects.all()
    serializer_class = CommunityMembershipSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        if user.is_staff:
            return CommunityMembership.objects.all()
        # If user is admin/mod/expert in a group, they can see that group's memberships
        admin_groups = CommunityMembership.objects.filter(
            user=user, role__in=['admin', 'moderator', 'expert'], status='approved'
        ).values_list('group_id', flat=True)
        return CommunityMembership.objects.filter(
            Q(user=user) | Q(group_id__in=admin_groups)
        )
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        membership = self.get_object()
        user = request.user
        # Check if user has permission
        user_membership = CommunityMembership.objects.filter(
            user=user, group=membership.group, role__in=['admin', 'moderator', 'expert'], status='approved'
        ).first()
        if not user_membership and not user.is_staff:
            return Response({"detail": "You don't have permission to approve memberships."}, status=status.HTTP_403_FORBIDDEN)
        
        if membership.status == 'pending':
            membership.status = 'approved'
            membership.save(update_fields=['status'])
            membership.group.member_count += 1
            membership.group.save(update_fields=['member_count'])
            return Response(CommunityMembershipSerializer(membership).data)
        else:
            return Response({"detail": "Membership is not pending approval."}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        membership = self.get_object()
        user = request.user
        user_membership = CommunityMembership.objects.filter(
            user=user, group=membership.group, role__in=['admin', 'moderator', 'expert'], status='approved'
        ).first()
        if not user_membership and not user.is_staff:
            return Response({"detail": "You don't have permission to reject memberships."}, status=status.HTTP_403_FORBIDDEN)
        
        if membership.status == 'pending':
            membership.status = 'rejected'
            membership.save(update_fields=['status'])
            return Response(CommunityMembershipSerializer(membership).data)
        else:
            return Response({"detail": "Membership is not pending approval."}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def change_role(self, request, pk=None):
        membership = self.get_object()
        new_role = request.data.get('role')
        
        if new_role not in ['member', 'moderator', 'admin', 'expert']:
            return Response({"detail": "Invalid role."}, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        # Check if user is admin in that group (or staff)
        user_membership = CommunityMembership.objects.filter(
            user=user, group=membership.group, role='admin', status='approved'
        ).first()
        if not user_membership and not user.is_staff:
            return Response({"detail": "You don't have permission to change member roles."}, status=status.HTTP_403_FORBIDDEN)
        
        membership.role = new_role
        membership.save(update_fields=['role'])
        return Response(CommunityMembershipSerializer(membership).data)


class CommunityPostViewSet(viewsets.ModelViewSet):
    queryset = CommunityPost.objects.all()
    serializer_class = CommunityPostSerializer
    permission_classes = [permissions.IsAuthenticated, IsPostAuthorOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = CommunityPostFilter
    search_fields = ['title', 'content', 'tags']
    ordering_fields = ['created_at', 'updated_at', 'view_count', 'like_count', 'comment_count']
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        if user.is_staff or getattr(user, 'role', None) == 'admin':
            return CommunityPost.objects.all()
        
        user_groups = CommunityMembership.objects.filter(user=user, status='approved').values_list('group_id', flat=True)
        return CommunityPost.objects.filter(
            Q(status='published') & (
                Q(group__is_private=False) | Q(group_id__in=user_groups)
            )
        )
    
    def perform_create(self, serializer):
        post = serializer.save(author=self.request.user)
        group = post.group
        group.post_count += 1
        group.save(update_fields=['post_count'])
    
    @action(detail=True, methods=['post'])
    def like(self, request, pk=None):
        post = self.get_object()
        post.like_count += 1
        post.save(update_fields=['like_count'])
        return Response({"detail": "Post liked successfully."})
    
    @action(detail=True, methods=['post'])
    def view(self, request, pk=None):
        post = self.get_object()
        post.view_count += 1
        post.save(update_fields=['view_count'])
        return Response({"detail": "View recorded successfully."})


class CommunityCommentViewSet(viewsets.ModelViewSet):
    queryset = CommunityComment.objects.all()
    serializer_class = CommunityCommentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        if user.is_staff or getattr(user, 'role', None) == 'admin':
            return CommunityComment.objects.all()
        
        user_groups = CommunityMembership.objects.filter(user=user, status='approved').values_list('group_id', flat=True)
        return CommunityComment.objects.filter(
            Q(status='published') & (
                Q(post__group__is_private=False) | Q(post__group_id__in=user_groups)
            )
        )
    
    def perform_create(self, serializer):
        comment = serializer.save(author=self.request.user)
        post = comment.post
        post.comment_count += 1
        post.save(update_fields=['comment_count'])
    
    @action(detail=True, methods=['post'])
    def like(self, request, pk=None):
        comment = self.get_object()
        comment.like_count += 1
        comment.save(update_fields=['like_count'])
        return Response({"detail": "Comment liked successfully."})
    
    @action(detail=True, methods=['post'])
    def flag(self, request, pk=None):
        comment = self.get_object()
        reason = request.data.get('reason', '')
        comment.status = 'flagged'
        comment.save(update_fields=['status'])
        # Optionally notify moderators
        return Response({"detail": "Comment flagged for review."})


class CommunityEventViewSet(viewsets.ModelViewSet):
    queryset = CommunityEvent.objects.all()
    serializer_class = CommunityEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'description']
    ordering_fields = ['start_time', 'created_at', 'updated_at']
    

class CommunityResourceViewSet(viewsets.ModelViewSet):
    queryset = CommunityResource.objects.all()
    serializer_class = CommunityResourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', 'view_count', 'download_count']


class CommunityNotificationViewSet(viewsets.ModelViewSet):
    queryset = CommunityNotification.objects.all()
    serializer_class = CommunityNotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'message']
    ordering_fields = ['created_at']
    

class CommunityAccessibilitySettingViewSet(viewsets.ModelViewSet):
    queryset = CommunityAccessibilitySetting.objects.all()
    serializer_class = CommunityAccessibilitySettingSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSelfOnly]
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        return CommunityAccessibilitySetting.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        # Delete any old instance to keep OneToOne
        CommunityAccessibilitySetting.objects.filter(user=self.request.user).delete()
        serializer.save(user=self.request.user)
