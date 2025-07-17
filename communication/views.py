import logging
from django.utils import timezone
from django.db.models import Q, Count, Prefetch, F
from rest_framework import viewsets, status, filters, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from . import serializers
from .filters import ConversationFilterSet, MessageFilterSet, NotificationFilterSet

from .models import Conversation, Message, Notification
from .serializers import (
    ConversationSerializer, MessageSerializer, NotificationSerializer,
    ConversationDetailSerializer, MarkMessagesReadSerializer,
    CreateConversationSerializer, CreateMessageSerializer
)
from .permissions import (
    IsApprovedUser, IsConversationParticipant, CanAccessNotification,
    CanViewConversationBetweenRoles
)
from .services.message_service import (
    mark_messages_as_read, get_unread_message_count, create_conversation,
    send_message, add_participant_to_conversation, remove_participant_from_conversation
)
from .services.notification_service import mark_notification_as_read

logger = logging.getLogger(__name__)


class ConversationViewSet(viewsets.ModelViewSet):
    """ViewSet for conversations."""
    queryset = Conversation.objects.all()
    serializer_class = ConversationSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_class = ConversationFilterSet  # Replace filterset_fields
    search_fields = ['title', 'participants__first_name', 'participants__last_name', 'participants__username']
    ordering_fields = ['updated_at', 'created_at']
    ordering = ['-updated_at']
    permission_classes = [
        permissions.IsAuthenticated, 
        IsApprovedUser, 
        IsConversationParticipant, 
        CanViewConversationBetweenRoles
    ]
    
    def get_queryset(self):
        """Filter conversations based on user role."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
                
        user = self.request.user
        
        # Get conversations the user is participating in
        queryset = Conversation.objects.filter(participants=user)
        
        # Prefetch related data for efficiency
        queryset = queryset.prefetch_related(
            'participants',
            Prefetch(
                'messages',
                queryset=Message.objects.order_by('-created_at')[:5],
                to_attr='recent_messages'
            )
        )
        
        # Additional filtering
        if self.action == 'list':
            # For conversation list, provide unread counts
            queryset = queryset.annotate(
                unread_count=Count(
                    'messages',
                    filter=~Q(messages__read_by=user) & Q(messages__sender__isnull=False)
                )
            )
        
        return queryset
    
    def get_serializer_class(self):
        """Use different serializers based on action."""
        if self.action == 'retrieve':
            return ConversationDetailSerializer
        elif self.action == 'create':
            return CreateConversationSerializer
        return self.serializer_class
    
    def perform_create(self, serializer):
        """Use message service to create conversation."""
        # Extract data from serializer
        title = serializer.validated_data.get('title', '')
        participant_ids = serializer.validated_data.get('participant_ids', [])
        
        # Create conversation
        conversation = create_conversation(
            title=title,
            participants=participant_ids,
            created_by=self.request.user
        )
        
        # Initial message
        initial_message = serializer.validated_data.get('initial_message')
        if initial_message:
            send_message(
                conversation=conversation,
                sender=self.request.user,
                content=initial_message
            )
        
        # Update serializer instance
        serializer.instance = conversation
    
    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """Get messages for a conversation."""
        conversation = self.get_object()
        
        # Pagination parameters
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        
        # Calculate offset and limit
        offset = (page - 1) * page_size
        limit = page_size
        
        # Get messages with pagination, ordered by created_at (most recent first)
        messages = conversation.messages.all().order_by('-created_at')[offset:offset+limit]
        
        # Mark messages as read
        mark_messages_as_read(conversation, request.user)
        
        # Serialize messages
        serializer = MessageSerializer(messages, many=True, context={'request': request})
        
        # Count total messages for pagination info
        total_messages = conversation.messages.count()
        total_pages = (total_messages + page_size - 1) // page_size
        
        return Response({
            'results': serializer.data,
            'pagination': {
                'current_page': page,
                'total_pages': total_pages,
                'page_size': page_size,
                'total_count': total_messages
            }
        })
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark all messages in a conversation as read."""
        conversation = self.get_object()
        
        # Use message service to mark messages as read
        count = mark_messages_as_read(conversation, request.user)
        
        return Response({
            'success': True,
            'messages_read': count
        })
    
    @action(detail=True, methods=['post'])
    def add_participant(self, request, pk=None):
        """Add a participant to a conversation."""
        conversation = self.get_object()
        serializer = MarkMessagesReadSerializer(data=request.data)
        
        if serializer.is_valid():
            user_id = serializer.validated_data.get('user_id')
            
            try:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                
                user = User.objects.get(id=user_id)
                add_participant_to_conversation(conversation, user)
                
                return Response({
                    'success': True,
                    'message': f"{user.get_full_name() or user.username} added to conversation"
                })
                
            except User.DoesNotExist:
                return Response(
                    {'detail': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                logger.error(f"Error adding participant: {str(e)}")
                return Response(
                    {'detail': f'Error adding participant: {str(e)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def remove_participant(self, request, pk=None):
        """Remove a participant from a conversation."""
        conversation = self.get_object()
        serializer = MarkMessagesReadSerializer(data=request.data)
        
        if serializer.is_valid():
            user_id = serializer.validated_data.get('user_id')
            
            try:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                
                user = User.objects.get(id=user_id)
                remove_participant_from_conversation(conversation, user)
                
                return Response({
                    'success': True,
                    'message': f"{user.get_full_name() or user.username} removed from conversation"
                })
                
            except User.DoesNotExist:
                return Response(
                    {'detail': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                logger.error(f"Error removing participant: {str(e)}")
                return Response(
                    {'detail': f'Error removing participant: {str(e)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get total unread message count across all conversations."""
        count = get_unread_message_count(request.user)
        
        return Response({
            'unread_count': count
        })


class MessageViewSet(viewsets.ModelViewSet):
    """ViewSet for messages."""
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = MessageFilterSet  # Replace filterset_fields
    ordering_fields = ['created_at']
    ordering = ['-created_at']
    permission_classes = [
        permissions.IsAuthenticated, 
        IsApprovedUser, 
        IsConversationParticipant
    ]
    
    def get_queryset(self):
        """Filter messages based on conversations the user is in."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Get messages from conversations the user is participating in
        queryset = Message.objects.filter(conversation__participants=user)
        
        # Prefetch related data for efficiency
        queryset = queryset.select_related('conversation', 'sender')
        queryset = queryset.prefetch_related('read_by')
        
        return queryset
    
    def get_serializer_class(self):
        """Use different serializers based on action."""
        if self.action == 'create':
            return CreateMessageSerializer
        return self.serializer_class
    
    def perform_create(self, serializer):
        """Use message service to send message."""
        # Extract data from serializer
        conversation_id = serializer.validated_data.get('conversation')
        content = serializer.validated_data.get('content')
        
        try:
            # Get conversation
            conversation = Conversation.objects.get(id=conversation_id, participants=self.request.user)
            
            # Send message
            message = send_message(
                conversation=conversation,
                sender=self.request.user,
                content=content
            )
            
            # Update serializer instance
            serializer.instance = message
            
        except Conversation.DoesNotExist:
            raise serializers.ValidationError({"conversation": "You are not a participant in this conversation."})
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            raise serializers.ValidationError({"detail": f"Error sending message: {str(e)}"})


class NotificationViewSet(viewsets.ModelViewSet):
    """ViewSet for notifications."""
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = NotificationFilterSet  # Replace filterset_fields
    ordering_fields = ['created_at']
    ordering = ['-created_at']
    permission_classes = [
        permissions.IsAuthenticated, 
        IsApprovedUser, 
        CanAccessNotification
    ]
    
    def get_queryset(self):
        """Filter notifications for current user."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        return Notification.objects.filter(user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark a notification as read."""
        notification = self.get_object()
        
        # Already read
        if notification.read_at:
            return Response({'status': 'notification already marked as read'})
        
        # Mark as read
        mark_notification_as_read(notification.id, request.user)
        
        return Response({'status': 'notification marked as read'})
    
    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        """Mark all notifications as read."""
        unread_count = self.get_queryset().filter(read_at__isnull=True).count()
        
        # Mark all as read
        self.get_queryset().filter(read_at__isnull=True).update(
            read_at=timezone.now()
        )
        
        return Response({
            'status': 'all notifications marked as read',
            'count': unread_count
        })
    
    @action(detail=False, methods=['get'])
    def unread(self, request):
        """Get unread notifications."""
        unread_notifications = self.get_queryset().filter(read_at__isnull=True)
        page = self.paginate_queryset(unread_notifications)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = self.get_serializer(unread_notifications, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get count of unread notifications."""
        count = self.get_queryset().filter(read_at__isnull=True).count()
        return Response({'unread_count': count})
