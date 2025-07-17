import logging
from django.db.models.signals import post_save, pre_save
from django.utils import timezone
from django.dispatch import receiver
from users.models import ConsentLog
from community.models import CommunityComment, CommunityMembership, CommunityPost, CommunityNotification

# Import audit utilities
from audit.utils import log_phi_access
from audit.models import AuditEvent

logger = logging.getLogger(__name__)

@receiver(post_save, sender=CommunityMembership)
def update_phi_consent_log(sender, instance, created, **kwargs):
    """Create consent log when a user joins a group with PHI warnings enabled."""
    if created and instance.group.phi_warning_enabled and instance.status == 'approved':
        # Log the PHI consent for this group
        ConsentLog.objects.create(
            user=instance.user,
            consent_type='DATA_SHARING',
            consented=True,
            user_agent=f"Community group join: {instance.group.name}"
        )

@receiver(pre_save, sender=CommunityPost)
def check_healthcare_content(sender, instance, **kwargs):
    """Flag potential PHI or sensitive content in posts."""
    if not instance.contains_sensitive_content:
        # Simple checks for common sensitive healthcare terms
        sensitive_terms = [
            'hiv', 'aids', 'cancer', 'depression', 'suicide', 'addiction',
            'diagnosis', 'diagnosed', 'test results', 'positive for', 
            'negative for', 'medical record', 'patient id'
        ]
        content_lower = instance.content.lower()
        
        for term in sensitive_terms:
            if term in content_lower:
                instance.contains_sensitive_content = True
                
                # If the term is highly sensitive, add a content warning
                high_sensitivity = ['suicide', 'hiv', 'addiction']
                if any(t in content_lower for t in high_sensitivity):
                    instance.requires_content_warning = True
                    instance.content_warning_text = "This post contains sensitive health information"
                break

@receiver(post_save, sender=CommunityPost)
def notify_healthcare_experts(sender, instance, created, **kwargs):
    """Notify healthcare experts when posts are created that may need expert input."""
    if created and instance.is_question:
        # Find experts in this group's topics
        experts = instance.group.verified_healthcare_experts.all()
        
        # In a real implementation, send notifications to these experts
        for expert in experts:
            CommunityNotification.objects.create(
                user=expert,
                title="Medical Question Posted",
                message=f"A medical question has been posted in {instance.group.name} that may need your expertise.",
                notification_type="medical_update",
                group=instance.group,
                post=instance
            )

@receiver(post_save, sender=CommunityPost)
def log_community_post_activity(sender, instance, created, **kwargs):
    """Log audit events for community post activities."""
    try:
        # Determine event type
        event_type = AuditEvent.EventType.CREATE if created else AuditEvent.EventType.UPDATE
        
        # Log audit event
        AuditEvent.objects.create(
            user=instance.author,
            event_type=event_type,
            resource_type='CommunityPost',
            resource_id=str(instance.id),
            description=f"{'Created' if created else 'Updated'} community post: {instance.title[:100]}",
            additional_data={
                'group_id': instance.group.id,
                'group_name': instance.group.name,
                'post_type': instance.post_type,
                'contains_sensitive_content': instance.contains_sensitive_content,
                'is_expert_response': instance.is_expert_response
            }
        )
        
        # If post contains sensitive content, log PHI access
        if instance.contains_sensitive_content and instance.patient:
            log_phi_access(
                user=instance.author,
                patient=instance.patient,
                access_type='share',
                reason=f"Community post in {instance.group.name}",
                record_type='CommunityPost',
                record_id=str(instance.id),
                additional_data={
                    'group_id': instance.group.id,
                    'post_title': instance.title[:100]
                }
            )
            
    except Exception as e:
        logger.error(f"Error logging community post audit event: {str(e)}")

@receiver(post_save, sender=CommunityMembership)
def log_membership_activity(sender, instance, created, **kwargs):
    """Log audit events for membership changes."""
    try:
        if created:
            AuditEvent.objects.create(
                user=instance.user,
                event_type=AuditEvent.EventType.ACCESS,
                resource_type='CommunityGroup',
                resource_id=str(instance.group.id),
                description=f"Joined community group: {instance.group.name}",
                additional_data={
                    'membership_role': instance.role,
                    'membership_status': instance.status,
                    'group_type': instance.group.group_type,
                    'is_condition_specific': instance.group.is_condition_specific
                }
            )
            
    except Exception as e:
        logger.error(f"Error logging membership audit event: {str(e)}")

@receiver(post_save, sender=CommunityComment)
def log_comment_activity(sender, instance, created, **kwargs):
    """Log audit events for comments."""
    try:
        if created:
            AuditEvent.objects.create(
                user=instance.author,
                event_type=AuditEvent.EventType.CREATE,
                resource_type='CommunityComment',
                resource_id=str(instance.id),
                description=f"Commented on post: {instance.post.title[:100]}",
                additional_data={
                    'post_id': instance.post.id,
                    'group_id': instance.post.group.id,
                    'is_reply': instance.parent is not None,
                    'parent_comment_id': instance.parent.id if instance.parent else None
                }
            )
            
    except Exception as e:
        logger.error(f"Error logging comment audit event: {str(e)}")
