from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from users.models import ConsentLog
from community.models import CommunityMembership, CommunityPost, CommunityNotification

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
