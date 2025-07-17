from rest_framework import serializers
from django.utils import timezone
from django.contrib.auth import get_user_model
from .models import (
    ReportConfiguration, Report, Dashboard, DashboardWidget,
    AnalyticsMetric, ReportScheduleLog, DataExport
)

User = get_user_model()

class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user information for references in reports."""
    
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'role')
        read_only_fields = fields


class ReportConfigurationSerializer(serializers.ModelSerializer):
    """Serializer for report configurations."""
    created_by = UserMinimalSerializer(read_only=True)
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    schedule_display = serializers.CharField(source='get_schedule_display', read_only=True)
    
    class Meta:
        model = ReportConfiguration
        fields = (
            'id', 'name', 'description', 'report_type', 'report_type_display',
            'parameters', 'schedule', 'schedule_display', 'last_run', 'next_run',
            'created_by', 'created_at', 'updated_at', 'is_public', 'allowed_roles',
            'recipients'
        )
        read_only_fields = ('created_at', 'updated_at', 'last_run')
    
    def create(self, validated_data):
        """Create a new report configuration."""
        recipients = validated_data.pop('recipients', [])
        
        # Set the creator
        validated_data['created_by'] = self.context['request'].user
        
        # Create the configuration
        config = ReportConfiguration.objects.create(**validated_data)
        
        # Add recipients
        if recipients:
            config.recipients.set(recipients)
        
        return config
    
    def validate(self, data):
        """Validate the report configuration."""
        # Validate next_run if schedule is not on-demand
        if data.get('schedule') != ReportConfiguration.Schedule.ON_DEMAND and not data.get('next_run'):
            raise serializers.ValidationError(
                {"next_run": "Next run date is required for scheduled reports."}
            )
            
        # Validate allowed_roles contains valid roles
        if 'allowed_roles' in data:
            valid_roles = [choice[0] for choice in User.Role.choices]
            for role in data['allowed_roles']:
                if role not in valid_roles:
                    raise serializers.ValidationError(
                        {"allowed_roles": f"Invalid role: {role}"}
                    )
        
        return data


class ReportSerializer(serializers.ModelSerializer):
    """Serializer for report results."""
    configuration_name = serializers.CharField(source='configuration.name', read_only=True)
    created_by = UserMinimalSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = (
            'id', 'report_id', 'configuration', 'configuration_name', 'status', 
            'status_display', 'started_at', 'completed_at', 'duration', 'error_message',
            'results_json', 'file_path', 'created_by', 'created_at', 'accessed_count',
            'last_accessed'
        )
        read_only_fields = (
            'report_id', 'status', 'started_at', 'completed_at', 'error_message',
            'file_path', 'created_at', 'accessed_count', 'last_accessed'
        )
    
    def get_duration(self, obj):
        """Calculate the report generation duration in seconds."""
        if obj.started_at and obj.completed_at:
            return (obj.completed_at - obj.started_at).total_seconds()
        return None
    
    def create(self, validated_data):
        """Create a new report, setting the creator and initial status."""
        # Set the creator
        validated_data['created_by'] = self.context['request'].user
        
        # Create the report
        report = Report.objects.create(**validated_data)
        
        return report
    
    def validate(self, data):
        """Validate permissions to create or access this report."""
        user = self.context['request'].user
        
        # Check if the user can create this report type
        if self.instance is None and 'configuration' in data:
            config = data['configuration']
            
            # Check if the configuration is public or user is the creator
            if not config.is_public and config.created_by != user:
                # Check if user's role is in allowed_roles
                if user.role not in config.allowed_roles:
                    raise serializers.ValidationError(
                        "You don't have permission to create reports from this configuration."
                    )
        
        return data


class DashboardWidgetSerializer(serializers.ModelSerializer):
    """Serializer for dashboard widgets."""
    widget_type_display = serializers.CharField(source='get_widget_type_display', read_only=True)
    
    class Meta:
        model = DashboardWidget
        fields = (
            'id', 'dashboard', 'title', 'widget_type', 'widget_type_display',
            'data_source', 'configuration', 'position', 'refresh_interval',
            'last_refresh', 'created_at', 'updated_at'
        )
        read_only_fields = ('created_at', 'updated_at', 'last_refresh')
    
    def validate_position(self, value):
        """Validate the widget position contains required fields."""
        required_fields = ['x', 'y', 'width', 'height']
        for field in required_fields:
            if field not in value:
                raise serializers.ValidationError(f"Position must include {field}")
        return value


class DashboardSerializer(serializers.ModelSerializer):
    """Serializer for dashboards."""
    owner = UserMinimalSerializer(read_only=True)
    widgets = DashboardWidgetSerializer(many=True, read_only=True)
    
    class Meta:
        model = Dashboard
        fields = (
            'id', 'name', 'description', 'layout', 'owner', 'created_at',
            'updated_at', 'is_public', 'shared_with', 'widgets'
        )
        read_only_fields = ('created_at', 'updated_at')
    
    def create(self, validated_data):
        """Create a new dashboard, setting the owner."""
        shared_with = validated_data.pop('shared_with', [])
        
        # Set the owner
        validated_data['owner'] = self.context['request'].user
        
        # Create the dashboard
        dashboard = Dashboard.objects.create(**validated_data)
        
        # Add shared users
        if shared_with:
            dashboard.shared_with.set(shared_with)
        
        return dashboard


class DashboardMinimalSerializer(serializers.ModelSerializer):
    """Minimal serializer for dashboard references."""
    owner_name = serializers.SerializerMethodField()
    widget_count = serializers.IntegerField(source='widgets.count', read_only=True)
    
    class Meta:
        model = Dashboard
        fields = ('id', 'name', 'owner', 'owner_name', 'is_public', 'widget_count')
    
    def get_owner_name(self, obj):
        return f"{obj.owner.first_name} {obj.owner.last_name}".strip() or obj.owner.username


class AnalyticsMetricSerializer(serializers.ModelSerializer):
    """Serializer for analytics metrics."""
    created_by = UserMinimalSerializer(read_only=True)
    
    class Meta:
        model = AnalyticsMetric
        fields = (
            'id', 'name', 'description', 'calculation_method', 'units',
            'data_source', 'parameters', 'created_by', 'created_at',
            'updated_at', 'is_active'
        )
        read_only_fields = ('created_at', 'updated_at')
    
    def create(self, validated_data):
        """Create a new metric, setting the creator."""
        validated_data['created_by'] = self.context['request'].user
        return AnalyticsMetric.objects.create(**validated_data)


class ReportScheduleLogSerializer(serializers.ModelSerializer):
    """Serializer for report schedule logs."""
    configuration_name = serializers.CharField(source='configuration.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = ReportScheduleLog
        fields = (
            'id', 'configuration', 'configuration_name', 'scheduled_time',
            'execution_time', 'status', 'status_display', 'report', 'error_message',
            'created_at'
        )
        read_only_fields = fields


class DataExportSerializer(serializers.ModelSerializer):
    """Serializer for data exports."""
    user = UserMinimalSerializer(read_only=True)
    export_format_display = serializers.CharField(source='get_export_format_display', read_only=True)
    
    class Meta:
        model = DataExport
        fields = (
            'id', 'user', 'export_date', 'export_format', 'export_format_display',
            'data_type', 'parameters', 'record_count', 'export_reason',
            'ip_address', 'file_size', 'file_path'
        )
        read_only_fields = ('export_date', 'ip_address', 'file_size', 'file_path')
    
    def create(self, validated_data):
        """Create a new data export record, setting the user and IP address."""
        request = self.context.get('request')
        
        # Set the user
        validated_data['user'] = request.user
        
        # Set the IP address
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                validated_data['ip_address'] = x_forwarded_for.split(',')[0].strip()
            else:
                validated_data['ip_address'] = request.META.get('REMOTE_ADDR', '')
        
        return DataExport.objects.create(**validated_data)
    
    def validate(self, data):
        """Validate export reason is provided for HIPAA compliance."""
        if not data.get('export_reason'):
            raise serializers.ValidationError(
                {"export_reason": "Export reason is required for HIPAA compliance."}
            )
        return data
