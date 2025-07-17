# models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
from fhir.models.patient import FHIRPatient
from django.db.models import JSONField


class CommunityGroup(models.Model):
    name = models.CharField(max_length=255, help_text="Name of the community group")
    description = models.TextField(help_text="Description of the community group")
    group_type = models.CharField(
        max_length=50,
        choices=[
            ('support', 'Support Group'),
            ('discussion', 'Discussion Group'),
            ('research', 'Research Group'),
            ('education', 'Educational Group'),
            ('social', 'Social Group'),
            ('other', 'Other')
        ],
        default='support',
        help_text="Type of community group"
    )
    is_private = models.BooleanField(default=False)
    is_moderated = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    member_count = models.IntegerField(default=0)
    post_count = models.IntegerField(default=0)
    image_url = models.URLField(blank=True)
    
    # Referencing HealthTopicTag by string to avoid forward-reference issues
    health_topics = models.ManyToManyField(
        'HealthTopicTag',
        blank=True,
        related_name="groups"
    )
    
    is_condition_specific = models.BooleanField(default=False)
    condition_name = models.CharField(max_length=255, blank=True)
    has_medical_professional = models.BooleanField(default=False)
    
    verified_healthcare_experts = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="expert_in_groups",
        limit_choices_to={'role': 'provider'}
    )
    is_peer_support = models.BooleanField(default=True)
    phi_warning_enabled = models.BooleanField(default=True)
    medical_disclaimer_text = models.TextField(blank=True)

    class Meta:
        verbose_name = "Community Group"
        verbose_name_plural = "Community Groups"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['group_type']),
            models.Index(fields=['is_private']),
        ]
    
    def __str__(self):
        return self.name


class CommunityResource(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    view_count = models.IntegerField(default=0)
    download_count = models.IntegerField(default=0)
    
    # Optional: If you want to link resources to a specific group or user,
    # you can add a ForeignKey or ManyToManyField here, for example:
    # group = models.ForeignKey('CommunityGroup', on_delete=models.CASCADE, null=True, blank=True)
    # or
    # uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        verbose_name = "Community Resource"
        verbose_name_plural = "Community Resources"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['title']),
            models.Index(fields=['created_at']),
            models.Index(fields=['updated_at']),
        ]

    def __str__(self):
        return self.title
    

class CommunityMembership(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='community_memberships'
    )
    group = models.ForeignKey(
        CommunityGroup,
        on_delete=models.CASCADE,
        related_name='memberships'
    )
    role = models.CharField(
        max_length=20,
        choices=[
            ('member', 'Member'),
            ('moderator', 'Moderator'),
            ('admin', 'Administrator'),
            ('expert', 'Expert')
        ],
        default='member'
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending Approval'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('blocked', 'Blocked')
        ],
        default='approved'
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(auto_now=True)
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='community_memberships'
    )
    
    class Meta:
        verbose_name = "Community Membership"
        verbose_name_plural = "Community Memberships"
        unique_together = ('user', 'group')
        ordering = ['-joined_at']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['group']),
            models.Index(fields=['role']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.user.username} in {self.group.name}"


class CommunityPost(models.Model):
    group = models.ForeignKey(
        CommunityGroup,
        on_delete=models.CASCADE,
        related_name='posts'
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='community_posts'
    )
    title = models.CharField(max_length=255)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('draft', 'Draft'),
            ('published', 'Published'),
            ('archived', 'Archived'),
            ('hidden', 'Hidden'),
            ('flagged', 'Flagged for Review')
        ],
        default='published'
    )
    view_count = models.IntegerField(default=0)
    like_count = models.IntegerField(default=0)
    comment_count = models.IntegerField(default=0)
    
    health_topics = models.ManyToManyField(
        'HealthTopicTag',
        blank=True,
        related_name="posts"
    )
    is_question = models.BooleanField(default=False)
    is_expert_response = models.BooleanField(default=False)
    expert_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="verified_posts"
    )
    medical_disclaimer = models.BooleanField(default=True)
    contains_sensitive_content = models.BooleanField(default=False)
    requires_content_warning = models.BooleanField(default=False)
    content_warning_text = models.CharField(max_length=255, blank=True)
    post_type = models.CharField(
        max_length=20,
        choices=[
            ('discussion', 'Discussion'),
            ('question', 'Question'),
            ('announcement', 'Announcement'),
            ('event', 'Event'),
            ('resource', 'Resource'),
            ('other', 'Other')
        ],
        default='discussion'
    )
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='community_posts'
    )
    # Example using Django's built-in JSONField if Django >= 3.1
    from django.db.models import JSONField
    tags = JSONField(default=list, blank=True)
    
    class Meta:
        verbose_name = "Community Post"
        verbose_name_plural = "Community Posts"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['group']),
            models.Index(fields=['author']),
            models.Index(fields=['created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['post_type']),
        ]
    
    def __str__(self):
        return self.title


class CommunityComment(models.Model):
    post = models.ForeignKey(
        CommunityPost,
        on_delete=models.CASCADE,
        related_name='comments'
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='community_comments'
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('published', 'Published'),
            ('hidden', 'Hidden'),
            ('flagged', 'Flagged for Review')
        ],
        default='published'
    )
    like_count = models.IntegerField(default=0)
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='replies'
    )
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='community_comments'
    )
    
    class Meta:
        verbose_name = "Community Comment"
        verbose_name_plural = "Community Comments"
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['post']),
            models.Index(fields=['author']),
            models.Index(fields=['created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['parent']),
        ]
    
    def __str__(self):
        return f"Comment by {self.author.username} on {self.post.title}"


class CommunityEvent(models.Model):
    group = models.ForeignKey(
        CommunityGroup,
        on_delete=models.CASCADE,
        related_name='events'
    )
    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_events'
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    timezone = models.CharField(max_length=50, default="UTC")
    location_type = models.CharField(
        max_length=20,
        choices=[
            ('online', 'Online'),
            ('in_person', 'In Person'),
            ('hybrid', 'Hybrid')
        ],
        default='online'
    )
    location_details = models.TextField(blank=True)
    meeting_url = models.URLField(blank=True)
    meeting_id = models.CharField(max_length=255, blank=True)
    meeting_password = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('scheduled', 'Scheduled'),
            ('cancelled', 'Cancelled'),
            ('postponed', 'Postponed'),
            ('completed', 'Completed')
        ],
        default='scheduled'
    )
    max_attendees = models.IntegerField(null=True, blank=True)
    current_attendees = models.IntegerField(default=0)
    image_url = models.URLField(blank=True)
    
    class Meta:
        verbose_name = "Community Event"
        verbose_name_plural = "Community Events"
        ordering = ['start_time']
        indexes = [
            models.Index(fields=['group']),
            models.Index(fields=['creator']),
            models.Index(fields=['start_time']),
            models.Index(fields=['status']),
            models.Index(fields=['location_type']),
        ]
    
    def __str__(self):
        return self.title


class EventAttendee(models.Model):
    event = models.ForeignKey(
        CommunityEvent,
        on_delete=models.CASCADE,
        related_name='attendees'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='event_attendances'
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('registered', 'Registered'),
            ('confirmed', 'Confirmed'),
            ('attended', 'Attended'),
            ('cancelled', 'Cancelled'),
            ('waitlisted', 'Waitlisted')
        ],
        default='registered'
    )
    registered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='event_attendances'
    )
    
    class Meta:
        verbose_name = "Event Attendee"
        verbose_name_plural = "Event Attendees"
        unique_together = ('event', 'user')
        ordering = ['registered_at']
        indexes = [
            models.Index(fields=['event']),
            models.Index(fields=['user']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.user.username} at {self.event.title}"


class CommunityNotification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='community_notifications'
    )
    title = models.CharField(max_length=255)
    message = models.TextField()
    notification_type = models.CharField(
        max_length=30,
        choices=[
            # General
            ('group_invitation', 'Group Invitation'),
            ('post_mention', 'Post Mention'),
            ('comment_mention', 'Comment Mention'),
            ('new_comment', 'New Comment'),
            ('event_reminder', 'Event Reminder'),
            ('post_in_group', 'New Post in Group'),
            ('membership_approval', 'Membership Approval'),
            ('content_flagged', 'Content Flagged'),
            ('resource_shared', 'Resource Shared'),
            # Healthcare
            ('medical_update', 'Medical Update'),
            ('expert_response', 'Expert Response'),
            ('medication_question', 'Medication Question'),
            ('clinical_trial', 'Clinical Trial Opportunity'),
            ('condition_update', 'Condition Information Update'),
            ('provider_post', 'Healthcare Provider Post')
        ],
        default='group_invitation'
    )
    group = models.ForeignKey(
        CommunityGroup,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    post = models.ForeignKey(
        'CommunityPost',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    comment = models.ForeignKey(
        'CommunityComment',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    event = models.ForeignKey(
        'CommunityEvent',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    patient = models.ForeignKey(
        FHIRPatient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='community_notifications'
    )
    delivery_method = models.CharField(
        max_length=20,
        choices=[
            ('in_app', 'In-App Notification'),
            ('email', 'Email Notification'),
            ('sms', 'SMS Notification'),
            ('all', 'All Methods')
        ],
        default='in_app'
    )
    priority = models.CharField(
        max_length=10,
        choices=[
            ('low', 'Low'),
            ('normal', 'Normal'),
            ('high', 'High'),
            ('urgent', 'Urgent')
        ],
        default='normal'
    )
    
    class Meta:
        verbose_name = "Community Notification"
        verbose_name_plural = "Community Notifications"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['created_at']),
            models.Index(fields=['is_read']),
            models.Index(fields=['notification_type']),
            models.Index(fields=['priority']),
        ]
    
    def __str__(self):
        return f"Notification for {self.user.username}: {self.title}"
    
    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    def send(self):
        # Example logic - adapt to your usage:
        try:
            from users.models import CommunityAccessibilitySetting
            accessibility = CommunityAccessibilitySetting.objects.get(user=self.user)
            method = accessibility.notification_method
        except:
            method = self.delivery_method
        
        if method in ['email', 'all']:
            self._send_email()
        if method in ['sms', 'all'] and getattr(self.user, 'phone_number', None):
            self._send_sms()
        return True
    
    def _send_email(self):
        from django.core.mail import send_mail
        from django.conf import settings
        import logging
        
        subject = f"Klararety Community: {self.title}"
        if self.notification_type in ['medical_update', 'expert_response', 'medication_question']:
            template = (
                f"Hello {self.user.first_name or self.user.username},\n\n"
                f"{self.message}\n\n"
                "Please note: Information shared in the community is not a substitute for "
                "professional medical advice.\n\n"
                "View in Klararety: [Link would be here]\n\n"
                "To manage your notification settings, visit your profile."
            )
        else:
            template = (
                f"Hello {self.user.first_name or self.user.username},\n\n"
                f"{self.message}\n\n"
                "View in Klararety: [Link would be here]\n\n"
                "To manage your notification settings, visit your profile."
            )
        try:
            send_mail(
                subject=subject,
                message=template,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[self.user.email],
                fail_silently=True,
            )
        except Exception as e:
            logger = logging.getLogger('django')
            logger.error(f"Failed to send notification email: {e}")
    
    def _send_sms(self):
        # Implement SMS delivery logic
        pass


class HealthTopicTag(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    is_condition = models.BooleanField(default=False)
    is_treatment = models.BooleanField(default=False)
    is_medication = models.BooleanField(default=False)
    is_lifestyle = models.BooleanField(default=False)
    icd10_code = models.CharField(max_length=10, blank=True)
    is_expert_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="verified_topics"
    )
    group_count = models.IntegerField(default=0)
    post_count = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = "Health Topic Tag"
        verbose_name_plural = "Health Topic Tags"
        ordering = ['name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['is_condition']),
            models.Index(fields=['is_treatment']),
            models.Index(fields=['is_medication']),
        ]
    
    def __str__(self):
        return self.name


class CommunityAccessibilitySetting(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='community_accessibility'
    )
    high_contrast = models.BooleanField(default=False)
    large_text = models.BooleanField(default=False)
    reduce_animations = models.BooleanField(default=False)
    screen_reader_optimized = models.BooleanField(default=False)
    simplified_ui = models.BooleanField(default=False)
    notification_method = models.CharField(
        max_length=20,
        choices=[
            ('visual', 'Visual Only'),
            ('audio', 'Audio Only'),
            ('both', 'Visual and Audio'),
            ('email', 'Email Only'),
            ('sms', 'SMS Only')
        ],
        default='visual'
    )
    speech_to_text = models.BooleanField(default=False)
    cognitive_support = models.BooleanField(default=False)
    motor_support = models.BooleanField(default=False)
    filter_sensitive_content = models.BooleanField(default=False)
    filter_specific_conditions = JSONField(default=list, blank=True)
    
    show_unread_first = models.BooleanField(default=True)
    auto_play_media = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Accessibility Setting"
        verbose_name_plural = "Accessibility Settings"
    
    def __str__(self):
        return f"Accessibility settings for {self.user.username}"
