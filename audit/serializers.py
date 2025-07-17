from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import AuditEvent, PHIAccessLog, SecurityAuditLog, ComplianceReport, AuditExport

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """Serializer for minimal user information in audit logs."""
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'full_name', 'role')
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username


class AuditEventSerializer(serializers.ModelSerializer):
    """Serializer for general audit events."""
    user_details = serializers.SerializerMethodField()
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    
    class Meta:
        model = AuditEvent
        fields = ('id', 'user', 'user_details', 'event_type', 'event_type_display', 
                  'resource_type', 'resource_id', 'description', 'ip_address', 
                  'user_agent', 'timestamp', 'additional_data')
        read_only_fields = ('id', 'timestamp')
    
    def get_user_details(self, obj):
        """Get user details if user exists."""
        if obj.user:
            return {
                'id': obj.user.id,
                'username': obj.user.username,
                'full_name': f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username,
                'role': getattr(obj.user, 'role', None)
            }
        return None


class PHIAccessLogSerializer(serializers.ModelSerializer):
    """Serializer for PHI access logs."""
    user_details = serializers.SerializerMethodField()
    patient_details = serializers.SerializerMethodField()
    access_type_display = serializers.CharField(source='get_access_type_display', read_only=True)
    
    class Meta:
        model = PHIAccessLog
        fields = ('id', 'user', 'user_details', 'patient', 'patient_details',
                  'access_type', 'access_type_display', 'reason', 'record_type', 
                  'record_id', 'ip_address', 'user_agent', 'timestamp', 'additional_data')
        read_only_fields = ('id', 'timestamp')
    
    def get_user_details(self, obj):
        """Get user details if user exists."""
        if obj.user:
            return {
                'id': obj.user.id,
                'username': obj.user.username,
                'full_name': f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username,
                'role': getattr(obj.user, 'role', None)
            }
        return None
    
    def get_patient_details(self, obj):
        """Get patient details if patient exists."""
        if obj.patient:
            return {
                'id': obj.patient.id,
                'username': obj.patient.username,
                'full_name': f"{obj.patient.first_name} {obj.patient.last_name}".strip() or obj.patient.username,
            }
        return None


class SecurityAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for security audit logs."""
    user_details = serializers.SerializerMethodField()
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    resolved_by_details = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityAuditLog
        fields = ('id', 'user', 'user_details', 'event_type', 'event_type_display',
                  'description', 'severity', 'severity_display', 'ip_address', 
                  'user_agent', 'timestamp', 'additional_data', 'resolved',
                  'resolved_by', 'resolved_by_details', 'resolved_at', 'resolution_notes')
        read_only_fields = ('id', 'timestamp', 'resolved_at')
    
    def get_user_details(self, obj):
        """Get user details if user exists."""
        if obj.user:
            return {
                'id': obj.user.id,
                'username': obj.user.username,
                'full_name': f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username,
                'role': getattr(obj.user, 'role', None)
            }
        return None
    
    def get_resolved_by_details(self, obj):
        """Get resolver details if user exists."""
        if obj.resolved_by:
            return {
                'id': obj.resolved_by.id,
                'username': obj.resolved_by.username,
                'full_name': f"{obj.resolved_by.first_name} {obj.resolved_by.last_name}".strip() or obj.resolved_by.username,
                'role': getattr(obj.resolved_by, 'role', None)
            }
        return None


class ComplianceReportSerializer(serializers.ModelSerializer):
    """Serializer for compliance reports."""
    generated_by_details = serializers.SerializerMethodField()
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = ComplianceReport
        fields = ('id', 'report_type', 'report_type_display', 'report_date',
                  'generated_by', 'generated_by_details', 'status', 'status_display',
                  'file_url', 'parameters', 'notes', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_generated_by_details(self, obj):
        """Get generator details if user exists."""
        if obj.generated_by:
            return {
                'id': obj.generated_by.id,
                'username': obj.generated_by.username,
                'full_name': f"{obj.generated_by.first_name} {obj.generated_by.last_name}".strip() or obj.generated_by.username,
                'role': getattr(obj.generated_by, 'role', None)
            }
        return None
    
    def validate_report_date(self, value):
        """Ensure report date is valid."""
        from django.utils import timezone
        from datetime import datetime, timedelta
        
        today = timezone.now().date()
        max_past_date = today - timedelta(days=365)  # Don't allow reports older than 1 year
        
        if value > today:
            raise serializers.ValidationError("Report date cannot be in the future.")
        if value < max_past_date:
            raise serializers.ValidationError("Report date cannot be more than one year in the past.")
            
        return value


class AuditExportSerializer(serializers.ModelSerializer):
    """Serializer for audit exports."""
    user_details = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = AuditExport
        fields = ('id', 'user', 'user_details', 'status', 'status_display', 
                  'file_url', 'filters', 'created_at', 'completed_at', 'error_message')
        read_only_fields = ('id', 'user', 'status', 'file_url', 'created_at', 'completed_at')
    
    def get_user_details(self, obj):
        """Get user details."""
        if obj.user:
            return {
                'id': obj.user.id,
                'username': obj.user.username,
                'full_name': f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username,
                'role': getattr(obj.user, 'role', None)
            }
        return None
