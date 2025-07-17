import json
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.http import HttpResponse, FileResponse
from django.db.models import Q, Count, Avg, Sum, F, ExpressionWrapper, FloatField, DateTimeField
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth, Cast
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .services.report_generator import ReportGeneratorService
from .services.data_export import DataExportService
from .services.analytics import AnalyticsService
from .models import (
    ReportConfiguration, Report, Dashboard, DashboardWidget,
    AnalyticsMetric, ReportScheduleLog, DataExport
)
from .serializers import (
    ReportConfigurationSerializer, ReportSerializer, DashboardSerializer,
    DashboardWidgetSerializer, AnalyticsMetricSerializer, DashboardMinimalSerializer,
    ReportScheduleLogSerializer, DataExportSerializer
)
from .permissions import (
    IsOwnerOrReadOnly, HasReportAccess, HasDashboardAccess,
    CanAccessAnalytics, IsApprovedUser, IsComplianceOfficerOrAdmin
)
from .filters import (
    ReportConfigurationFilter, ReportFilter, DashboardFilter, 
    DashboardWidgetFilter, AnalyticsMetricFilter, ReportScheduleLogFilter,
    DataExportFilter
)

User = get_user_model()
logger = logging.getLogger('hipaa_audit')


class ReportConfigurationViewSet(viewsets.ModelViewSet):
    """API endpoint for Report Configurations."""
    queryset = ReportConfiguration.objects.all()
    serializer_class = ReportConfigurationSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser]
    filterset_class = ReportConfigurationFilter
    
    def get_queryset(self):
        """Filter configurations based on user role and permissions."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Admins and compliance officers see all configurations
        if user.is_staff or user.role in ['admin', 'compliance']:
            return ReportConfiguration.objects.all()
        
        # Others see their own configurations, public ones, and ones shared with their role
        return ReportConfiguration.objects.filter(
            Q(created_by=user) |
            Q(is_public=True) |
            Q(allowed_roles__contains=[user.role])
        ).distinct()
    
    def perform_create(self, serializer):
        """Set creator when creating configuration."""
        serializer.save(created_by=self.request.user)
    
    @swagger_auto_schema(
        method='post',
        operation_description="Generate a report from this configuration",
        responses={
            201: ReportSerializer(),
            400: "Invalid configuration or parameters",
            403: "Permission denied"
        }
    )
    @action(detail=True, methods=['post'])
    def generate_report(self, request, pk=None):
        """Generate a report from this configuration."""
        configuration = self.get_object()
        
        # Check access permission
        if not configuration.is_public and configuration.created_by != request.user:
            if request.user.role not in configuration.allowed_roles:
                return Response(
                    {"detail": "You don't have permission to generate this report."},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Create the report
        report = Report.objects.create(
            configuration=configuration,
            status=Report.Status.PENDING,
            created_by=request.user
        )
        
        # Start the report generation process
        # In production, this would be done asynchronously with Celery
        try:
            # Update report status
            report.status = Report.Status.RUNNING
            report.started_at = timezone.now()
            report.save(update_fields=['status', 'started_at'])
            
            # Generate the report
            generator = ReportGeneratorService()
            results = generator.generate_report(configuration, request.user)
            
            # Update the report with results
            report.status = Report.Status.COMPLETED
            report.completed_at = timezone.now()
            report.results_json = results
            report.save(update_fields=['status', 'completed_at', 'results_json'])
            
            # Update the configuration last_run time
            configuration.last_run = timezone.now()
            configuration.save(update_fields=['last_run'])
            
            # Log the report generation for HIPAA compliance
            logger.info(
                f"REPORT_GENERATED: User {request.user.username} (ID: {request.user.id}) "
                f"generated report {report.report_id} of type {configuration.report_type}"
            )
            
            return Response(
                ReportSerializer(report).data,
                status=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            # Log the error
            logger.error(
                f"REPORT_GENERATION_FAILED: User {request.user.username} (ID: {request.user.id}) "
                f"failed to generate report from configuration {configuration.id}: {str(e)}"
            )
            
            # Update the report with error
            report.status = Report.Status.FAILED
            report.error_message = str(e)
            report.completed_at = timezone.now()
            report.save(update_fields=['status', 'error_message', 'completed_at'])
            
            return Response(
                {"detail": f"Report generation failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @swagger_auto_schema(
        method='post',
        operation_description="Clone this report configuration",
        responses={
            201: ReportConfigurationSerializer(),
            400: "Failed to clone",
            403: "Permission denied"
        }
    )
    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        """Clone an existing report configuration."""
        original = self.get_object()
        
        # Create a copy of the configuration
        new_config = ReportConfiguration.objects.create(
            name=f"Copy of {original.name}",
            description=original.description,
            report_type=original.report_type,
            parameters=original.parameters.copy(),
            schedule=ReportConfiguration.Schedule.ON_DEMAND,  # Default to on-demand
            is_public=False,  # Default to private
            created_by=request.user,
            allowed_roles=original.allowed_roles.copy() if original.allowed_roles else []
        )
        
        # Log the cloning action
        logger.info(
            f"REPORT_CONFIG_CLONED: User {request.user.username} (ID: {request.user.id}) "
            f"cloned report configuration {original.id} to create configuration {new_config.id}"
        )
        
        return Response(
            ReportConfigurationSerializer(new_config).data,
            status=status.HTTP_201_CREATED
        )


class ReportViewSet(viewsets.ModelViewSet):
    """API endpoint for Reports."""
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser, HasReportAccess]
    filterset_class = ReportFilter
    
    def get_queryset(self):
        """Filter reports based on user role and permissions."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Admins and compliance officers see all reports
        if user.is_staff or user.role in ['admin', 'compliance']:
            return Report.objects.all()
        
        # Others see reports they created or from configurations they can access
        accessible_configs = ReportConfiguration.objects.filter(
            Q(created_by=user) |
            Q(is_public=True) |
            Q(allowed_roles__contains=[user.role])
        )
        
        return Report.objects.filter(
            Q(created_by=user) |
            Q(configuration__in=accessible_configs)
        ).distinct()
    
    def retrieve(self, request, *args, **kwargs):
        """Track report access."""
        report = self.get_object()
        
        # Update access tracking for HIPAA compliance
        report.accessed_count += 1
        report.last_accessed = timezone.now()
        report.save(update_fields=['accessed_count', 'last_accessed'])
        
        # Log the access
        logger.info(
            f"REPORT_ACCESSED: User {request.user.username} (ID: {request.user.id}) "
            f"accessed report {report.report_id}"
        )
        
        return super().retrieve(request, *args, **kwargs)
    
    @swagger_auto_schema(
        method='get',
        operation_description="Export a report in the specified format",
        manual_parameters=[
            openapi.Parameter(
                'format',
                in_=openapi.IN_QUERY,
                description='Export format (csv, excel, json, pdf)',
                type=openapi.TYPE_STRING,
                required=True,
                enum=['csv', 'excel', 'json', 'pdf']
            ),
            openapi.Parameter(
                'reason',
                in_=openapi.IN_QUERY,
                description='Reason for export (HIPAA compliance)',
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: "File download",
            400: "Invalid format or missing reason",
            403: "Permission denied",
            404: "Report not found"
        }
    )
    @action(detail=True, methods=['get'])
    def export(self, request, pk=None):
        """Export a report in the specified format."""
        report = self.get_object()
        
        # Ensure the report is completed
        if report.status != Report.Status.COMPLETED:
            return Response(
                {"detail": "Cannot export an incomplete report."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get export format and reason
        export_format = request.query_params.get('format', 'csv').lower()
        export_reason = request.query_params.get('reason')
        
        if not export_reason:
            return Response(
                {"detail": "A reason for export is required for HIPAA compliance."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        valid_formats = ['csv', 'excel', 'json', 'pdf']
        if export_format not in valid_formats:
            return Response(
                {"detail": f"Invalid format. Valid formats are: {', '.join(valid_formats)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Create export service
            export_service = DataExportService()
            
            # Generate the export file
            file_content, file_name, content_type, file_size = export_service.export_report(
                report, export_format
            )
            
            # Log the export
            export_record = DataExport.objects.create(
                user=request.user,
                export_format=export_format.upper(),
                data_type=f"Report_{report.configuration.report_type}",
                parameters={"report_id": str(report.report_id)},
                record_count=export_service.get_record_count(report),
                export_reason=export_reason,
                ip_address=self._get_client_ip(request),
                file_size=file_size,
                file_path=f"exports/{file_name}"  # This would be the actual path in production
            )
            
            # Log the export for HIPAA compliance
            logger.info(
                f"REPORT_EXPORTED: User {request.user.username} (ID: {request.user.id}) "
                f"exported report {report.report_id} in {export_format} format. "
                f"Reason: {export_reason} - Export ID: {export_record.id}"
            )
            
            # Return the file
            response = HttpResponse(file_content, content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            return response
            
        except Exception as e:
            logger.error(
                f"REPORT_EXPORT_FAILED: User {request.user.username} (ID: {request.user.id}) "
                f"failed to export report {report.report_id}: {str(e)}"
            )
            
            return Response(
                {"detail": f"Export failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _get_client_ip(self, request):
        """Get client IP safely accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class DashboardViewSet(viewsets.ModelViewSet):
    """API endpoint for Dashboards."""
    queryset = Dashboard.objects.all()
    serializer_class = DashboardSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser, HasDashboardAccess]
    filterset_class = DashboardFilter
    
    def get_queryset(self):
        """Filter dashboards based on user role and permissions."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Admins see all dashboards
        if user.is_staff or user.role == 'admin':
            return Dashboard.objects.all()
        
        # Others see dashboards they own, public ones, or ones shared with them
        return Dashboard.objects.filter(
            Q(owner=user) |
            Q(is_public=True) |
            Q(shared_with=user)
        ).distinct()
    
    @action(detail=True, methods=['post'])
    def add_rare_disease_widget(self, request, pk=None):
        """Add specialized widget for rare disease monitoring."""
        dashboard = self.get_object()
        
        widget_type = request.data.get('widget_type')
        condition = request.data.get('condition')
        
        if widget_type not in ['medication_adherence', 'symptom_tracker', 'emergency_alerts', 'caregiver_updates']:
            return Response({'error': 'Invalid widget type for rare disease dashboard'}, status=400)
        
        # Create specialized configuration
        widget_config = {
            'condition_filter': condition,
            'auto_refresh': True,
            'alert_thresholds': {
                'medication_adherence': 80,  # Alert if below 80%
                'missed_appointments': 2,    # Alert if 2+ missed
                'emergency_events': 1        # Alert on any emergency
            },
            'display_options': {
                'show_trends': True,
                'show_predictions': True,
                'highlight_critical': True
            }
        }
        
        widget = DashboardWidget.objects.create(
            dashboard=dashboard,
            title=f"{widget_type.replace('_', ' ').title()} - {condition}",
            widget_type=widget_type,
            data_source=f'rare_disease_{widget_type}',
            configuration=widget_config,
            position={'x': 0, 'y': 0, 'width': 6, 'height': 4},
            refresh_interval=300  # 5 minutes for critical data
        )
        
        return Response(DashboardWidgetSerializer(widget).data, status=201)

    @action(detail=False, methods=['get'])
    def get_pharmaceutical_dashboard(self, request):
        """Get specialized dashboard for pharmaceutical companies."""
        if request.user.role != 'pharmco':
            return Response({'error': 'Access denied'}, status=403)
        
        # Create or get pharmaceutical company dashboard
        dashboard, created = Dashboard.objects.get_or_create(
            owner=request.user,
            name='Pharmaceutical Analytics Dashboard',
            defaults={
                'description': 'Real-time analytics for rare disease drug development',
                'is_public': False,
                'layout': 'pharmaceutical_layout'
            }
        )
        
        if created:
            # Add default widgets for pharmaceutical companies
            default_widgets = [
                {
                    'title': 'Trial Enrollment Status',
                    'widget_type': 'enrollment_tracker',
                    'data_source': 'trial_enrollment',
                    'position': {'x': 0, 'y': 0, 'width': 6, 'height': 4}
                },
                {
                    'title': 'Medication Adherence Rates',
                    'widget_type': 'adherence_chart',
                    'data_source': 'medication_adherence',
                    'position': {'x': 6, 'y': 0, 'width': 6, 'height': 4}
                },
                {
                    'title': 'Adverse Events Monitor',
                    'widget_type': 'safety_monitor',
                    'data_source': 'adverse_events',
                    'position': {'x': 0, 'y': 4, 'width': 12, 'height': 4}
                },
                {
                    'title': 'Real-World Evidence',
                    'widget_type': 'rwe_analytics',
                    'data_source': 'real_world_evidence',
                    'position': {'x': 0, 'y': 8, 'width': 8, 'height': 4}
                },
                {
                    'title': 'Regulatory Timeline',
                    'widget_type': 'regulatory_tracker',
                    'data_source': 'regulatory_milestones',
                    'position': {'x': 8, 'y': 8, 'width': 4, 'height': 4}
                }
            ]
            
            for widget_data in default_widgets:
                DashboardWidget.objects.create(
                    dashboard=dashboard,
                    **widget_data,
                    refresh_interval=600  # 10 minutes
                )
        
        return Response(DashboardSerializer(dashboard).data)

    def perform_create(self, serializer):
        """Set owner when creating dashboard."""
        serializer.save(owner=self.request.user)
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get a list of dashboards with minimal details",
        responses={200: DashboardMinimalSerializer(many=True)}
    )
    @action(detail=False, methods=['get'])
    def list_minimal(self, request):
        """Get a minimal list of dashboards for selection UI."""
        queryset = self.filter_queryset(self.get_queryset())
        serializer = DashboardMinimalSerializer(queryset, many=True)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        method='post',
        operation_description="Share dashboard with users",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['user_ids'],
            properties={
                'user_ids': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_INTEGER),
                    description='List of user IDs to share with'
                )
            }
        ),
        responses={
            200: "Dashboard shared successfully",
            400: "Invalid user IDs",
            403: "Permission denied",
            404: "Dashboard not found"
        }
    )
    @action(detail=True, methods=['post'])
    def share(self, request, pk=None):
        """Share dashboard with other users."""
        dashboard = self.get_object()
        
        # Only owner can share
        if dashboard.owner != request.user and not request.user.is_staff:
            return Response(
                {"detail": "Only the owner can share this dashboard."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get user IDs to share with
        user_ids = request.data.get('user_ids', [])
        if not user_ids:
            return Response(
                {"detail": "No user IDs provided."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get valid users
        users = User.objects.filter(id__in=user_ids)
        if len(users) != len(user_ids):
            return Response(
                {"detail": "Some user IDs are invalid."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Add users to shared_with
        dashboard.shared_with.add(*users)
        
        # Log the sharing
        user_names = ", ".join([f"{user.username} (ID: {user.id})" for user in users])
        logger.info(
            f"DASHBOARD_SHARED: User {request.user.username} (ID: {request.user.id}) "
            f"shared dashboard {dashboard.id} with users: {user_names}"
        )
        
        return Response({"detail": "Dashboard shared successfully."})
    
    @swagger_auto_schema(
        method='post',
        operation_description="Clone dashboard",
        responses={
            201: DashboardSerializer(),
            400: "Failed to clone",
            403: "Permission denied",
            404: "Dashboard not found"
        }
    )
    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        """Clone a dashboard with all widgets."""
        original = self.get_object()
        
        # Create a new dashboard
        new_dashboard = Dashboard.objects.create(
            name=f"Copy of {original.name}",
            description=original.description,
            layout=original.layout.copy() if original.layout else {},
            owner=request.user,
            is_public=False
        )
        
        # Clone widgets
        for widget in original.widgets.all():
            DashboardWidget.objects.create(
                dashboard=new_dashboard,
                title=widget.title,
                widget_type=widget.widget_type,
                data_source=widget.data_source,
                configuration=widget.configuration.copy(),
                position=widget.position.copy(),
                refresh_interval=widget.refresh_interval
            )
        
        # Log the cloning
        logger.info(
            f"DASHBOARD_CLONED: User {request.user.username} (ID: {request.user.id}) "
            f"cloned dashboard {original.id} to create dashboard {new_dashboard.id}"
        )
        
        return Response(
            DashboardSerializer(new_dashboard).data,
            status=status.HTTP_201_CREATED
        )


class DashboardWidgetViewSet(viewsets.ModelViewSet):
    """API endpoint for Dashboard Widgets."""
    queryset = DashboardWidget.objects.all()
    serializer_class = DashboardWidgetSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser]
    filterset_class = DashboardWidgetFilter
    
    def get_queryset(self):
        """Filter widgets based on user's dashboard access."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Get accessible dashboards
        if user.is_staff or user.role == 'admin':
            accessible_dashboards = Dashboard.objects.all()
        else:
            accessible_dashboards = Dashboard.objects.filter(
                Q(owner=user) |
                Q(is_public=True) |
                Q(shared_with=user)
            ).distinct()
        
        # Filter widgets by accessible dashboards
        return DashboardWidget.objects.filter(dashboard__in=accessible_dashboards)
    
    def perform_create(self, serializer):
        """Check dashboard access before creating widget."""
        dashboard = serializer.validated_data.get('dashboard')
        user = self.request.user
        
        # Check if user can modify this dashboard
        if dashboard.owner != user and not user.is_staff:
            raise serializer.ValidationError("You can only add widgets to your own dashboards.")
        
        serializer.save()
    
    @swagger_auto_schema(
        method='post',
        operation_description="Refresh widget data",
        responses={
            200: "Widget data refreshed",
            400: "Failed to refresh",
            403: "Permission denied",
            404: "Widget not found"
        }
    )
    @action(detail=True, methods=['post'])
    def refresh(self, request, pk=None):
        """Refresh widget data."""
        widget = self.get_object()
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Refresh widget data
            new_data = analytics_service.get_widget_data(
                widget.data_source,
                widget.configuration,
                request.user
            )
            
            # Update widget configuration with new data
            widget.configuration['data'] = new_data
            widget.last_refresh = timezone.now()
            widget.save(update_fields=['configuration', 'last_refresh'])
            
            return Response({"detail": "Widget data refreshed successfully."})
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to refresh widget data: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


class AnalyticsMetricViewSet(viewsets.ModelViewSet):
    """API endpoint for Analytics Metrics."""
    queryset = AnalyticsMetric.objects.all()
    serializer_class = AnalyticsMetricSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser, CanAccessAnalytics]
    filterset_class = AnalyticsMetricFilter
    
    def get_queryset(self):
        """Filter metrics based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Admins see all metrics
        if user.is_staff or user.role == 'admin':
            return AnalyticsMetric.objects.all()
        
        # Providers, compliance officers, researchers see active metrics
        if user.role in ['provider', 'compliance', 'researcher']:
            return AnalyticsMetric.objects.filter(is_active=True)
        
        # Others see active metrics they created
        return AnalyticsMetric.objects.filter(
            Q(created_by=user, is_active=True)
        )
    
    def perform_create(self, serializer):
        """Set creator when creating metric."""
        serializer.save(created_by=self.request.user)
    
    @swagger_auto_schema(
        method='post',
        operation_description="Calculate metric with parameters",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'parameters': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    description='Parameters for the calculation'
                )
            }
        ),
        responses={
            200: "Metric calculated successfully",
            400: "Failed to calculate metric",
            403: "Permission denied",
            404: "Metric not found"
        }
    )
    @action(detail=True, methods=['post'])
    def calculate(self, request, pk=None):
        """Calculate this metric with the given parameters."""
        metric = self.get_object()
        
        # Get parameters
        parameters = request.data.get('parameters', {})
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Calculate the metric
            result = analytics_service.calculate_metric(
                metric,
                parameters,
                request.user
            )
            
            # Log the calculation
            logger.info(
                f"METRIC_CALCULATED: User {request.user.username} (ID: {request.user.id}) "
                f"calculated metric {metric.id} ({metric.name})"
            )
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to calculate metric: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


class ReportScheduleLogViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for Report Schedule Logs (read-only)."""
    queryset = ReportScheduleLog.objects.all()
    serializer_class = ReportScheduleLogSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser, IsComplianceOfficerOrAdmin]
    filterset_class = ReportScheduleLogFilter
    
    def get_queryset(self):
        """Filter schedule logs based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Only admins and compliance officers can see logs
        if user.is_staff or user.role in ['admin', 'compliance']:
            return ReportScheduleLog.objects.all()
        
        # Others can't see schedule logs
        return ReportScheduleLog.objects.none()


class DataExportViewSet(viewsets.ModelViewSet):
    """API endpoint for Data Exports."""
    queryset = DataExport.objects.all()
    serializer_class = DataExportSerializer
    permission_classes = [IsAuthenticated, IsApprovedUser]
    filterset_class = DataExportFilter
    
    def get_queryset(self):
        """Filter exports based on user role."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Admins and compliance officers see all exports
        if user.is_staff or user.role in ['admin', 'compliance']:
            return DataExport.objects.all()
        
        # Others see only their own exports
        return DataExport.objects.filter(user=user)
    
    def perform_create(self, serializer):
        """Set user and IP address when creating export."""
        serializer.save(
            user=self.request.user,
            ip_address=self._get_client_ip(self.request)
        )
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get data export usage statistics",
        responses={
            200: "Export statistics",
            403: "Permission denied"
        }
    )
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get statistics about data exports for compliance reporting."""
        user = request.user
        
        # Only admins and compliance officers can see statistics
        if not user.is_staff and user.role not in ['admin', 'compliance']:
            return Response(
                {"detail": "You don't have permission to view export statistics."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Calculate statistics
        # Get total exports in last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        recent_exports = DataExport.objects.filter(export_date__gte=thirty_days_ago)
        
        # Exports by format
        exports_by_format = recent_exports.values('export_format').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Exports by data type
        exports_by_type = recent_exports.values('data_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Exports by user role
        exports_by_role = recent_exports.values('user__role').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Top exporters
        top_exporters = recent_exports.values(
            'user_id', 'user__username', 'user__role'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Total data exported (in bytes)
        total_data_volume = recent_exports.aggregate(Sum('file_size'))['file_size__sum'] or 0
        
        # Return the statistics
        return Response({
            'time_period': '30 days',
            'total_exports': recent_exports.count(),
            'total_data_volume_bytes': total_data_volume,
            'total_data_volume_mb': round(total_data_volume / (1024 * 1024), 2),
            'exports_by_format': exports_by_format,
            'exports_by_type': exports_by_type,
            'exports_by_role': exports_by_role,
            'top_exporters': top_exporters
        })
    
    def _get_client_ip(self, request):
        """Get client IP safely accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class AnalyticsViewSet(viewsets.ViewSet):
    """API endpoint for Analytics operations."""
    permission_classes = [IsAuthenticated, IsApprovedUser, CanAccessAnalytics]
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get patient adherence metrics",
        manual_parameters=[
            openapi.Parameter(
                'time_period',
                in_=openapi.IN_QUERY,
                description='Time period (30d, 90d, 6m, 1y)',
                type=openapi.TYPE_STRING,
                required=False,
                default='30d'
            ),
            openapi.Parameter(
                'condition',
                in_=openapi.IN_QUERY,
                description='Filter by condition',
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'medication',
                in_=openapi.IN_QUERY,
                description='Filter by medication',
                type=openapi.TYPE_STRING,
                required=False
            )
        ],
        responses={
            200: "Adherence metrics",
            400: "Invalid parameters",
            403: "Permission denied"
        }
    )
    @action(detail=False, methods=['get'])
    def adherence_metrics(self, request):
        """Get medication adherence metrics."""
        # Get parameters
        time_period = request.query_params.get('time_period', '30d')
        condition = request.query_params.get('condition')
        medication = request.query_params.get('medication')
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Get adherence metrics
            metrics = analytics_service.get_adherence_metrics(
                time_period=time_period,
                condition=condition,
                medication=medication,
                user=request.user
            )
            
            return Response(metrics)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get adherence metrics: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get patient vitals trends",
        manual_parameters=[
            openapi.Parameter(
                'time_period',
                in_=openapi.IN_QUERY,
                description='Time period (30d, 90d, 6m, 1y)',
                type=openapi.TYPE_STRING,
                required=False,
                default='30d'
            ),
            openapi.Parameter(
                'metric',
                in_=openapi.IN_QUERY,
                description='Vital metric (heart_rate, blood_pressure, etc)',
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'patient_id',
                in_=openapi.IN_QUERY,
                description='Filter by patient ID',
                type=openapi.TYPE_INTEGER,
                required=False
            )
        ],
        responses={
            200: "Vitals trends",
            400: "Invalid parameters",
            403: "Permission denied"
        }
    )
    @action(detail=False, methods=['get'])
    def vitals_trends(self, request):
        """Get patient vitals trends."""
        # Get parameters
        time_period = request.query_params.get('time_period', '30d')
        metric = request.query_params.get('metric')
        patient_id = request.query_params.get('patient_id')
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Get vitals trends
            trends = analytics_service.get_vitals_trends(
                time_period=time_period,
                metric=metric,
                patient_id=patient_id,
                user=request.user
            )
            
            return Response(trends)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get vitals trends: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get provider performance metrics",
        manual_parameters=[
            openapi.Parameter(
                'provider_id',
                in_=openapi.IN_QUERY,
                description='Filter by provider ID',
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'metric',
                in_=openapi.IN_QUERY,
                description='Performance metric (consultation_time, patient_satisfaction, etc)',
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'time_period',
                in_=openapi.IN_QUERY,
                description='Time period (30d, 90d, 6m, 1y)',
                type=openapi.TYPE_STRING,
                required=False,
                default='30d'
            )
        ],
        responses={
            200: "Provider performance metrics",
            400: "Invalid parameters",
            403: "Permission denied"
        }
    )
    @action(detail=False, methods=['get'])
    def provider_performance(self, request):
        """Get provider performance metrics."""
        # Get parameters
        provider_id = request.query_params.get('provider_id')
        metric = request.query_params.get('metric')
        time_period = request.query_params.get('time_period', '30d')
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Get provider performance metrics
            performance = analytics_service.get_provider_performance(
                provider_id=provider_id,
                metric=metric,
                time_period=time_period,
                user=request.user
            )
            
            return Response(performance)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get provider performance: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get population health metrics",
        manual_parameters=[
            openapi.Parameter(
                'condition',
                in_=openapi.IN_QUERY,
                description='Filter by condition',
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'demographic',
                in_=openapi.IN_QUERY,
                description='Demographic factor (age, gender, etc)',
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'metric',
                in_=openapi.IN_QUERY,
                description='Health metric (adherence_rate, hospitalization_rate, etc)',
                type=openapi.TYPE_STRING,
                required=False
            )
        ],
        responses={
            200: "Population health metrics",
            400: "Invalid parameters",
            403: "Permission denied"
        }
    )
    @action(detail=False, methods=['get'])
    def population_health(self, request):
        """Get population health metrics."""
        # Get parameters
        condition = request.query_params.get('condition')
        demographic = request.query_params.get('demographic')
        metric = request.query_params.get('metric')
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Get population health metrics
            health_metrics = analytics_service.get_population_health(
                condition=condition,
                demographic=demographic,
                metric=metric,
                user=request.user
            )
            
            return Response(health_metrics)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get population health metrics: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @swagger_auto_schema(
        method='get',
        operation_description="Get AI-ready data for external analysis",
        manual_parameters=[
            openapi.Parameter(
                'data_type',
                in_=openapi.IN_QUERY,
                description='Type of data (patient_conditions, medication_adherence, etc)',
                type=openapi.TYPE_STRING,
                required=True
            ),
            openapi.Parameter(
                'time_period',
                in_=openapi.IN_QUERY,
                description='Time period (30d, 90d, 6m, 1y)',
                type=openapi.TYPE_STRING,
                required=False,
                default='30d'
            ),
            openapi.Parameter(
                'format',
                in_=openapi.IN_QUERY,
                description='Data format (json, csv)',
                type=openapi.TYPE_STRING,
                required=False,
                default='json'
            ),
            openapi.Parameter(
                'reason',
                in_=openapi.IN_QUERY,
                description='Reason for export (HIPAA compliance)',
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: "AI-ready data",
            400: "Invalid parameters",
            403: "Permission denied"
        }
    )
    @action(detail=False, methods=['get'])
    def ai_ready_data(self, request):
        """Get data prepared for AI analysis (Claude, ChatGPT, etc.)."""
        # Get parameters
        data_type = request.query_params.get('data_type')
        time_period = request.query_params.get('time_period', '30d')
        export_format = request.query_params.get('format', 'json')
        export_reason = request.query_params.get('reason')
        
        if not data_type:
            return Response(
                {"detail": "Data type is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not export_reason:
            return Response(
                {"detail": "Export reason is required for HIPAA compliance."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get analytics service
            analytics_service = AnalyticsService()
            
            # Prepare data for AI analysis
            data, record_count = analytics_service.prepare_ai_data(
                data_type=data_type,
                time_period=time_period,
                user=request.user
            )
            
            # Log the data export
            export_record = DataExport.objects.create(
                user=request.user,
                export_format=export_format.upper(),
                data_type=f"AI_Analysis_{data_type}",
                parameters={"time_period": time_period},
                record_count=record_count,
                export_reason=export_reason,
                ip_address=self._get_client_ip(request),
                file_size=len(json.dumps(data)),  # Approximate size
            )
            
            # Log the export for HIPAA compliance
            logger.info(
                f"AI_DATA_EXPORTED: User {request.user.username} (ID: {request.user.id}) "
                f"exported {data_type} data for AI analysis. "
                f"Reason: {export_reason} - Export ID: {export_record.id}"
            )
            
            return Response(data)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to prepare AI data: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _get_client_ip(self, request):
        """Get client IP safely accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
