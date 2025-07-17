# community/tasks.py
from __future__ import absolute_import, unicode_literals
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Count, Q
from celery import shared_task

from .models import (
    CommunityGroup, CommunityPost, CommunityComment, 
    CommunityNotification, CommunityMembership
)
from .services.content_safety import ContentSafetyService

logger = logging.getLogger(__name__)

@shared_task
def moderate_flagged_content():
    """
    Task to review and moderate flagged content.
    Runs every hour during business hours.
    """
    logger.info("Starting flagged content moderation")
    
    try:
        # Get flagged posts
        flagged_posts = CommunityPost.objects.filter(status='flagged')
        flagged_comments = CommunityComment.objects.filter(status='flagged')
        
        moderated_count = 0
        
        # Auto-moderate based on content analysis
        for post in flagged_posts:
            should_moderate, reason = ContentSafetyService.auto_moderate_content(post.content)
            
            if should_moderate:
                post.status = 'hidden'
                post.save(update_fields=['status'])
                
                # Notify moderators
                _notify_moderators_of_moderation(post, reason)
                moderated_count += 1
        
        for comment in flagged_comments:
            should_moderate, reason = ContentSafetyService.auto_moderate_content(comment.content)
            
            if should_moderate:
                comment.status = 'hidden'
                comment.save(update_fields=['status'])
                
                # Notify moderators
                _notify_moderators_of_moderation(comment, reason)
                moderated_count += 1
        
        logger.info(f"Content moderation completed: {moderated_count} items moderated")
        return f"Moderated {moderated_count} items"
        
    except Exception as e:
        logger.error(f"Error in content moderation: {str(e)}")
        return f"Error in moderation: {str(e)}"

@shared_task
def send_community_digest():
    """
    Send daily digest of community activity to members.
    """
    logger.info("Starting community digest generation")
    
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        
        # Get active groups with recent activity
        active_groups = CommunityGroup.objects.filter(
            posts__created_at__date=yesterday
        ).distinct().prefetch_related('memberships')
        
        digest_sent = 0
        
        for group in active_groups:
            # Get recent posts in this group
            recent_posts = CommunityPost.objects.filter(
                group=group,
                created_at__date=yesterday,
                status='published'
            ).order_by('-created_at')[:5]
            
            if recent_posts.exists():
                # Get members who want digests
                members = CommunityMembership.objects.filter(
                    group=group,
                    status='approved',
                    user__email_verified=True
                ).select_related('user')
                
                for membership in members:
                    _send_digest_email(membership.user, group, recent_posts)
                    digest_sent += 1
        
        logger.info(f"Community digest sent to {digest_sent} members")
        return f"Digest sent to {digest_sent} members"
        
    except Exception as e:
        logger.error(f"Error sending community digest: {str(e)}")
        return f"Error sending digest: {str(e)}"

@shared_task
def cleanup_old_notifications():
    """
    Clean up old read notifications to maintain database performance.
    """
    logger.info("Starting notification cleanup")
    
    try:
        # Delete read notifications older than 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        
        deleted_count = CommunityNotification.objects.filter(
            is_read=True,
            read_at__lt=cutoff_date
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old notifications")
        return f"Cleaned {deleted_count} notifications"
        
    except Exception as e:
        logger.error(f"Error cleaning notifications: {str(e)}")
        return f"Error cleaning notifications: {str(e)}"

@shared_task
def check_inactive_groups():
    """
    Check for inactive groups and notify admins.
    """
    logger.info("Checking for inactive groups")
    
    try:
        # Groups with no activity in last 30 days
        inactive_threshold = timezone.now() - timedelta(days=30)
        
        inactive_groups = CommunityGroup.objects.filter(
            posts__created_at__lt=inactive_threshold
        ).annotate(
            recent_posts=Count('posts', filter=Q(posts__created_at__gte=inactive_threshold))
        ).filter(recent_posts=0)
        
        if inactive_groups.exists():
            # Notify group admins
            for group in inactive_groups:
                group_admins = CommunityMembership.objects.filter(
                    group=group,
                    role__in=['admin', 'moderator'],
                    status='approved'
                ).select_related('user')
                
                for admin_membership in group_admins:
                    _notify_admin_inactive_group(admin_membership.user, group)
        
        logger.info(f"Found {inactive_groups.count()} inactive groups")
        return f"Found {inactive_groups.count()} inactive groups"
        
    except Exception as e:
        logger.error(f"Error checking inactive groups: {str(e)}")
        return f"Error checking groups: {str(e)}"

def _notify_moderators_of_moderation(content_obj, reason):
    """Send notification to moderators about auto-moderated content."""
    try:
        # Get group moderators
        if hasattr(content_obj, 'group'):
            group = content_obj.group
        elif hasattr(content_obj, 'post'):
            group = content_obj.post.group
        else:
            return
        
        moderators = CommunityMembership.objects.filter(
            group=group,
            role__in=['admin', 'moderator'],
            status='approved'
        ).select_related('user')
        
        content_type = 'post' if hasattr(content_obj, 'title') else 'comment'
        subject = f"Content Auto-Moderated in {group.name}"
        
        message = f"""
        A {content_type} has been automatically moderated in the group "{group.name}".
        
        Reason: {reason}
        
        Please review this content in the admin panel.
        """
        
        for moderator_membership in moderators:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[moderator_membership.user.email],
                fail_silently=True
            )
            
    except Exception as e:
        logger.error(f"Error notifying moderators: {str(e)}")

def _send_digest_email(user, group, posts):
    """Send digest email to user."""
    try:
        subject = f"Daily Digest: {group.name}"
        
        post_summaries = []
        for post in posts:
            post_summaries.append(f"• {post.title} by {post.author.get_full_name() or post.author.username}")
        
        message = f"""
        Hi {user.get_full_name() or user.username},
        
        Here's what happened yesterday in {group.name}:
        
        {chr(10).join(post_summaries)}
        
        Visit the community to participate in discussions.
        
        Best regards,
        Klararety Health Team
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True
        )
        
    except Exception as e:
        logger.error(f"Error sending digest email: {str(e)}")

def _notify_admin_inactive_group(admin_user, group):
    """Notify admin about inactive group."""
    try:
        subject = f"Inactive Group: {group.name}"
        
        message = f"""
        Hi {admin_user.get_full_name() or admin_user.username},
        
        The community group "{group.name}" has had no recent activity (30+ days).
        
        Consider:
        - Posting engaging content
        - Organizing community events
        - Reaching out to members
        
        Log in to manage your group.
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin_user.email],
            fail_silently=True
        )
        
    except Exception as e:
        logger.error(f"Error sending inactive group notification: {str(e)}")
