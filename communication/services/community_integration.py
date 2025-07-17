from community.models import SupportGroup, Post
from .notification_service import NotificationService

def notify_support_group_activity(support_group, activity_type, actor, details):
    """Notify support group members of relevant activity."""
    notification_service = NotificationService()
    
    for member in support_group.members.exclude(id=actor.id):
        notification_service.create_notification(
            user=member,
            title=f"Activity in {support_group.name}",
            message=f"{actor.get_full_name()} {details}",
            notification_type='community',
            related_object_id=support_group.id,
            related_object_type='support_group'
        )
