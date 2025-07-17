# security/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    SecurityThreat, VulnerabilityAssessment, Vulnerability,
    SecurityIncident, NetworkMonitor, FileIntegrityMonitor,
    SecurityConfiguration, ComplianceReport
)

User = get_user_model()


class UserSimpleSerializer(serializers.ModelSerializer):
    """Simple user serializer for security contexts."""
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'full_name', 'role')
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username


class SecurityThreatSerializer(serializers.ModelSerializer):
    """Serializer for security threats."""
    affected_user_details = serializers.SerializerMethodField()
    assigned_to_details = serializers.SerializerMethodField()
    resolved_by_details = serializers.SerializerMethodField()
    threat_type_display = serializers.CharField(source='get_threat_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    time_to_resolution = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityThreat
        fields = '__all__'
        read_only_fields = ('id', 'detection_time')
    
    def get_affected_user_details(self, obj):
        if obj.affected_user:
            return UserSimpleSerializer(obj.affected_user).data
        return None
    
    def get_assigned_to_details(self, obj):
        if obj.assigned_to:
            return UserSimpleSerializer(obj.assigned_to).data
        return None
    
    def get_resolved_by_details(self, obj):
        if obj.resolved_by:
            return UserSimpleSerializer(obj.resolved_by).data
        return None
    
    def get_time_to_resolution(self, obj):
        """Calculate time to resolution in hours."""
        if obj.resolved_at and obj.detection_time:
            delta = obj.resolved_at - obj.detection_time
            return round(delta.total_seconds() / 3600, 2)
        return None
    
    def validate_status(self, value):
        """Validate status transitions."""
        if self.instance:
            current_status = self.instance.status
            
            # Define valid status transitions
            valid_transitions = {
                'detected': ['investigating', 'false_positive'],
                'investigating': ['contained', 'mitigated', 'false_positive'],
                'contained': ['mitigated', 'resolved'],
                'mitigated': ['resolved'],
                'resolved': [],  # No transitions from resolved
                'false_positive': []  # No transitions from false positive
            }
            
            if value not in valid_transitions.get(current_status, []):
                raise serializers.ValidationError(
                    f"Invalid status transition from {current_status} to {value}"
                )
        
        return value


class VulnerabilityAssessmentSerializer(serializers.ModelSerializer):
    """Serializer for vulnerability assessments."""
    initiated_by_details = serializers.SerializerMethodField()
    scan_type_display = serializers.CharField(source='get_scan_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration_formatted = serializers.SerializerMethodField()
    vulnerability_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = VulnerabilityAssessment
        fields = '__all__'
        read_only_fields = ('id', 'started_at', 'completed_at', 'duration_seconds')
    
    def get_initiated_by_details(self, obj):
        if obj.initiated_by:
            return UserSimpleSerializer(obj.initiated_by).data
        return None
    
    def get_duration_formatted(self, obj):
        """Format duration in human-readable format."""
        if obj.duration_seconds:
            hours = obj.duration_seconds // 3600
            minutes = (obj.duration_seconds % 3600) // 60
            seconds = obj.duration_seconds % 60
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        return None
    
    def get_vulnerability_summary(self, obj):
        """Get vulnerability summary statistics."""
        return {
            'total': obj.total_vulnerabilities,
            'critical': obj.critical_count,
            'high': obj.high_count,
            'medium': obj.medium_count,
            'low': obj.low_count,
            'info': obj.info_count,
            'false_positives': obj.false_positive_count
        }


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for individual vulnerabilities."""
    assessment_details = serializers.SerializerMethodField()
    assigned_to_details = serializers.SerializerMethodField()
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    age_days = serializers.SerializerMethodField()
    risk_score = serializers.SerializerMethodField()
    
    class Meta:
        model = Vulnerability
        fields = '__all__'
        read_only_fields = ('id', 'first_discovered', 'last_seen')
    
    def get_assessment_details(self, obj):
        return {
            'id': str(obj.assessment.id),
            'scan_type': obj.assessment.scan_type,
            'target': obj.assessment.target,
            'completed_at': obj.assessment.completed_at
        }
    
    def get_assigned_to_details(self, obj):
        if obj.assigned_to:
            return UserSimpleSerializer(obj.assigned_to).data
        return None
    
    def get_age_days(self, obj):
        """Calculate age of vulnerability in days."""
        from django.utils import timezone
        delta = timezone.now() - obj.first_discovered
        return delta.days
    
    def get_risk_score(self, obj):
        """Calculate custom risk score based on CVSS and other factors."""
        base_score = obj.cvss_score or 0
        
        # Adjust based on asset criticality
        if obj.asset_criticality == 'high':
            base_score *= 1.2
        elif obj.asset_criticality == 'critical':
            base_score *= 1.5
        
        # Adjust based on exploitability
        if obj.exploitability == 'high':
            base_score *= 1.1
        
        return min(round(base_score, 1), 10.0)  # Cap at 10.0


class SecurityIncidentSerializer(serializers.ModelSerializer):
    """Serializer for security incidents."""
    reported_by_details = serializers.SerializerMethodField()
    assigned_to_details = serializers.SerializerMethodField()
    team_member_details = serializers.SerializerMethodField()
    affected_user_details = serializers.SerializerMethodField()
    incident_type_display = serializers.CharField(source='get_incident_type_display', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration = serializers.SerializerMethodField()
    related_threat_count = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityIncident
        fields = '__all__'
        read_only_fields = ('id', 'incident_id', 'reported_at', 'closed_at')
    
    def get_reported_by_details(self, obj):
        if obj.reported_by:
            return UserSimpleSerializer(obj.reported_by).data
        return None
    
    def get_assigned_to_details(self, obj):
        if obj.assigned_to:
            return UserSimpleSerializer(obj.assigned_to).data
        return None
    
    def get_team_member_details(self, obj):
        return [UserSimpleSerializer(member).data for member in obj.team_members.all()]
    
    def get_affected_user_details(self, obj):
        return [UserSimpleSerializer(user).data for user in obj.affected_users.all()]
    
    def get_duration(self, obj):
        """Calculate incident duration."""
        if obj.closed_at:
            delta = obj.closed_at - obj.reported_at
            return delta.total_seconds() / 3600  # Return hours
        return None
    
    def get_related_threat_count(self, obj):
        return obj.related_threats.count()


class NetworkMonitorSerializer(serializers.ModelSerializer):
    """Serializer for network monitoring alerts."""
    alert_type_display = serializers.CharField(source='get_alert_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    geographic_location = serializers.SerializerMethodField()
    threat_reputation = serializers.SerializerMethodField()
    
    class Meta:
        model = NetworkMonitor
        fields = '__all__'
        read_only_fields = ('id', 'timestamp')
    
    def get_geographic_location(self, obj):
        """Get geographic information for source IP."""
        if obj.geographic_info:
            return {
                'country': obj.geographic_info.get('country'),
                'city': obj.geographic_info.get('city'),
                'region': obj.geographic_info.get('region')
            }
        return None
    
    def get_threat_reputation(self, obj):
        """Get threat intelligence reputation score."""
        if obj.threat_intelligence:
            return obj.threat_intelligence.get('reputation_score')
        return None


class FileIntegrityMonitorSerializer(serializers.ModelSerializer):
    """Serializer for file integrity monitoring."""
    change_type_display = serializers.CharField(source='get_change_type_display', read_only=True)
    file_directory = serializers.SerializerMethodField()
    file_name = serializers.SerializerMethodField()
    change_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = FileIntegrityMonitor
        fields = '__all__'
        read_only_fields = ('id', 'timestamp')
    
    def get_file_directory(self, obj):
        """Extract directory from file path."""
        import os
        return os.path.dirname(obj.file_path)
    
    def get_file_name(self, obj):
        """Extract filename from file path."""
        import os
        return os.path.basename(obj.file_path)
    
    def get_change_summary(self, obj):
        """Provide human-readable change summary."""
        if obj.change_type == 'modified':
            size_change = ''
            if obj.old_size and obj.new_size:
                size_diff = obj.new_size - obj.old_size
                if size_diff > 0:
                    size_change = f" (+{size_diff} bytes)"
                elif size_diff < 0:
                    size_change = f" ({size_diff} bytes)"
            
            return f"File modified{size_change}"
        elif obj.change_type == 'created':
            size_info = f" ({obj.new_size} bytes)" if obj.new_size else ""
            return f"File created{size_info}"
        elif obj.change_type == 'deleted':
            return "File deleted"
        elif obj.change_type == 'permissions_changed':
            return f"Permissions changed from {obj.old_permissions} to {obj.new_permissions}"
        else:
            return obj.get_change_type_display()


class SecurityConfigurationSerializer(serializers.ModelSerializer):
    """Serializer for security configurations."""
    created_by_details = serializers.SerializerMethodField()
    config_type_display = serializers.CharField(source='get_config_type_display', read_only=True)
    
    class Meta:
        model = SecurityConfiguration
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_created_by_details(self, obj):
        if obj.created_by:
            return UserSimpleSerializer(obj.created_by).data
        return None
    
    def validate_configuration(self, value):
        """Validate configuration JSON structure."""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Configuration must be a valid JSON object")
        return value


class ComplianceReportSerializer(serializers.ModelSerializer):
    """Serializer for compliance reports."""
    generated_by_details = serializers.SerializerMethodField()
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    compliance_percentage = serializers.SerializerMethodField()
    report_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = ComplianceReport
        fields = '__all__'
        read_only_fields = ('id', 'generated_at')
    
    def get_generated_by_details(self, obj):
        if obj.generated_by:
            return UserSimpleSerializer(obj.generated_by).data
        return None
    
    def get_compliance_percentage(self, obj):
        """Calculate compliance percentage."""
        if obj.total_controls > 0:
            return round((obj.passed_controls / obj.total_controls) * 100, 1)
        return 0
    
    def get_report_summary(self, obj):
        """Get report summary statistics."""
        return {
            'total_controls': obj.total_controls,
            'passed_controls': obj.passed_controls,
            'failed_controls': obj.failed_controls,
            'compliance_score': obj.compliance_score,
            'compliance_percentage': self.get_compliance_percentage(obj)
        }


class SecurityMetricsSerializer(serializers.Serializer):
    """Serializer for security dashboard metrics."""
    active_threats = serializers.IntegerField()
    critical_vulnerabilities = serializers.IntegerField()
    active_incidents = serializers.IntegerField()
    threat_level = serializers.ChoiceField(choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    recent_activity = serializers.DictField()
    system_health = serializers.DictField()
    last_updated = serializers.DateTimeField()


class ThreatIndicatorSerializer(serializers.Serializer):
    """Serializer for threat indicators (IOCs)."""
    indicator_type = serializers.ChoiceField(
        choices=['ip', 'domain', 'url', 'hash', 'email', 'file_path']
    )
    indicator_value = serializers.CharField()
    confidence_level = serializers.ChoiceField(
        choices=['low', 'medium', 'high', 'critical']
    )
    description = serializers.CharField(required=False)
    source = serializers.CharField()
    created_at = serializers.DateTimeField(read_only=True)
