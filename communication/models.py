from django.db import models
from django.conf import settings

class Conversation(models.Model):
    """Model for conversations between users."""
    participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='conversations')
    title = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.title or f"Conversation {self.id}"

class Message(models.Model):
    """Model for messages within conversations."""
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField()
    read_by = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='read_messages', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Message from {self.sender.username} in {self.conversation}"

class Notification(models.Model):
    """Model for user notifications."""
    class NotificationType(models.TextChoices):
        APPOINTMENT = 'appointment', 'Appointment'
        MESSAGE = 'message', 'Message'
        PRESCRIPTION = 'prescription', 'Prescription'
        LAB_RESULT = 'lab_result', 'Lab Result'
        SYSTEM = 'system', 'System'
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=NotificationType.choices)
    related_object_id = models.IntegerField(null=True, blank=True)
    related_object_type = models.CharField(max_length=50, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.notification_type} notification for {self.user.username}"

