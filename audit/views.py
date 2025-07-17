import csv
import io
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.http import HttpResponse, StreamingHttpResponse
from django.db.models import Q, Count
from rest_framework import viewsets, status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from .models import AuditEvent, PHIAccessLog, SecurityAuditLog, ComplianceReport, AuditExport
from .filters import AuditExportFilterSet
from .serializers import (
    AuditEventSerializer, 
    PHIAccessLogSerializer,
    SecurityAuditLogSerializer, 
    ComplianceReportSerializer,
    AuditExportSerializer
)
from .permissions import IsAdminUser, IsComplianceOfficer, CanAccessPHILogs
from .services.hipaa_reports import HIPAAReportService
from .services.security_alerts import SecurityAlertService
from .tasks import generate_audit_export, generate_compliance_report


class AuditEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing audit events.
    Only administrators and compliance officers can access this endpoint.
    """
    queryset = AuditEvent.objects.all().order_by('-timestamp')
    serializer_class = AuditEventSerializer
    permission_classes = [IsComplianceOfficer]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['user', 'event_type', 'resource_type']
    search_fields = ['description', 'resource_id', 'user__username', 'user__email']
    
    def get_queryset(self):
        """Filter audit events based on query parameters."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        queryset = super().get_queryset()
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                queryset = queryset.filter(timestamp__gte=start_date)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date.replace(hour=23, minute=59, second=59)
                queryset = queryset.filter(timestamp__lte=end_date)
            except ValueError:
                pass
        
        # Filter by user role
        user_role = self.request.query_params.get('user_role')
        if user_role:
            queryset = queryset.filter(user__role=user_role)
        
        # Filter by IP address
        ip_address = self.request.query_params.get('ip_address')
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)
        
        return queryset
    
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get a summary of audit events."""
        # Get timeframe from query params or default to last 30 days
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Get events in time period
        events = AuditEvent.objects.filter(timestamp__gte=start_date)
        
        # Calculate summary statistics
        total_events = events.count()
        events_by_type = events.values('event_type').annotate(count=Count('id'))
        events_by_resource = events.values('resource_type').annotate(count=Count('id'))
        events_by_user = events.filter(user__isnull=False).values('user__username').annotate(count=Count('id'))
        
        return Response({
            'total_events': total_events,
            'events_by_type': {item['event_type']: item['count'] for item in events_by_type},
            'events_by_resource': {item['resource_type']: item['count'] for item in events_by_resource},
            'events_by_user': {item['user__username']: item['count'] for item in events_by_user},
            'timeframe_days': days
        })
    
    @action(detail=False, methods=['get'])
    def export(self, request):
        """Create a new export of filtered audit events."""
        # Get filters from query params
        filters = {}
        for key, value in request.query_params.items():
            if key in ['user', 'event_type', 'resource_type', 'start_date', 'end_date', 'search', 'user_role', 'ip_address']:
                filters[key] = value
        
        # Create export record
        export = AuditExport.objects.create(
            user=request.user,
            filters=filters
        )
        
        # Schedule export generation task
        generate_audit_export.delay(str(export.id))
        
        # Return export details
        serializer = AuditExportSerializer(export)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)


class PHIAccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing PHI access logs.
    Only administrators, compliance officers, and providers can access this endpoint.
    """
    queryset = PHIAccessLog.objects.all().order_by('-timestamp')
    serializer_class = PHIAccessLogSerializer
    permission_classes = [CanAccessPHILogs]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['user', 'patient', 'access_type', 'record_type']
    search_fields = ['reason', 'record_id', 'user__username', 'patient__username']
    
    def get_queryset(self):
        """Filter PHI access logs based on query parameters and user role."""
            # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        queryset = super().get_queryset()
        
        # For providers, only show their own access logs unless they're an admin
        if self.request.user.role == 'provider' and not self.request.user.is_staff:
            queryset = queryset.filter(user=self.request.user)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                queryset = queryset.filter(timestamp__gte=start_date)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date.replace(hour=23, minute=59, second=59)
                queryset = queryset.filter(timestamp__lte=end_date)
            except ValueError:
                pass
        
        # Filter by user role
        user_role = self.request.query_params.get('user_role')
        if user_role:
            queryset = queryset.filter(user__role=user_role)
            
        return queryset
    
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get a summary of PHI access logs."""
        # Get timeframe from query params or default to last 30 days
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Get base queryset (respecting permissions)
        base_queryset = self.get_queryset().filter(timestamp__gte=start_date)
        
        # Calculate summary statistics
        total_accesses = base_queryset.count()
        accesses_by_type = base_queryset.values('access_type').annotate(count=Count('id'))
        accesses_by_user_role = base_queryset.filter(user__isnull=False).values('user__role').annotate(count=Count('id'))
        accesses_by_record_type = base_queryset.values('record_type').annotate(count=Count('id'))
        
        # Calculate accesses without reason
        missing_reason = base_queryset.filter(Q(reason='') | Q(reason='No reason provided')).count()
        
        return Response({
            'total_accesses': total_accesses,
            'accesses_by_type': {item['access_type']: item['count'] for item in accesses_by_type},
            'accesses_by_user_role': {item['user__role']: item['count'] for item in accesses_by_user_role},
            'accesses_by_record_type': {item['record_type']: item['count'] for item in accesses_by_record_type},
            'missing_reason': missing_reason,
            'timeframe_days': days
        })


class SecurityAuditLogViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing security audit logs.
    Only administrators can access this endpoint.
    """
    queryset = SecurityAuditLog.objects.all().order_by('-timestamp')
    serializer_class = SecurityAuditLogSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['event_type', 'severity', 'resolved', 'user']
    search_fields = ['description', 'ip_address', 'user__username']
    
    def get_queryset(self):
        """Filter security audit logs based on query parameters."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        queryset = super().get_queryset()
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                queryset = queryset.filter(timestamp__gte=start_date)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date.replace(hour=23, minute=59, second=59)
                queryset = queryset.filter(timestamp__lte=end_date)
            except ValueError:
                pass
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve a security incident."""
        incident = self.get_object()
        
        # Get resolution notes from request
        notes = request.data.get('notes', '')
        
        # Resolve the incident
        incident.resolve(request.user, notes)
        
        # Return updated incident
        serializer = self.get_serializer(incident)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get a summary of security incidents."""
        # Get timeframe from query params or default to last 30 days
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Get incidents in time period
        incidents = SecurityAuditLog.objects.filter(timestamp__gte=start_date)
        
        # Calculate summary statistics
        total_incidents = incidents.count()
        incidents_by_type = incidents.values('event_type').annotate(count=Count('id'))
        incidents_by_severity = incidents.values('severity').annotate(count=Count('id'))
        unresolved = incidents.filter(resolved=False).count()
        critical_unresolved = incidents.filter(resolved=False, severity=SecurityAuditLog.Severity.CRITICAL).count()
        
        return Response({
            'total_incidents': total_incidents,
            'incidents_by_type': {item['event_type']: item['count'] for item in incidents_by_type},
            'incidents_by_severity': {item['severity']: item['count'] for item in incidents_by_severity},
            'unresolved': unresolved,
            'critical_unresolved': critical_unresolved,
            'timeframe_days': days
        })


class ComplianceReportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing compliance reports.
    Only administrators and compliance officers can access this endpoint.
    """
    queryset = ComplianceReport.objects.all().order_by('-report_date')
    serializer_class = ComplianceReportSerializer
    permission_classes = [IsComplianceOfficer]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['report_type', 'status', 'report_date']
    
    def get_queryset(self):
        """Filter reports based on user roles."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        queryset = super().get_queryset()
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                queryset = queryset.filter(report_date__gte=start_date)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                queryset = queryset.filter(report_date__lte=end_date)
            except ValueError:
                pass
        
        return queryset
    
    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate a new compliance report."""
        # Validate the request data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create new report
        report = HIPAAReportService.schedule_report(
            report_type=serializer.validated_data['report_type'],
            report_date=serializer.validated_data.get('report_date', timezone.now().date()),
            generated_by=request.user,
            parameters=serializer.validated_data.get('parameters', {})
        )
        
        # Return the created report
        result_serializer = self.get_serializer(report)
        return Response(result_serializer.data, status=status.HTTP_202_ACCEPTED)
    
    @action(detail=False, methods=['get'])
    def dashboard(self, request):
        """Get data for the compliance dashboard."""
        dashboard_data = HIPAAReportService.generate_compliance_dashboard_data()
        return Response(dashboard_data)


class AuditExportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for managing audit exports.
    Only administrators and compliance officers can access this endpoint.
    """
    serializer_class = AuditExportSerializer
    permission_classes = [IsComplianceOfficer]
    filterset_class = AuditExportFilterSet
    
    def get_queryset(self):
        """Get exports for the current user."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return AuditExport.objects.none()
        
        return AuditExport.objects.filter(user=self.request.user).order_by('-created_at')

class ComplianceDashboardViewSet(viewsets.ViewSet):
    """
    API endpoints for HIPAA compliance dashboard.
    Provides metrics and reports for monitoring compliance.
    """
    permission_classes = [IsComplianceOfficer]
    
    @action(detail=False, methods=['get'])
    def metrics(self, request):
        """Get dashboard metrics."""
        from .services.hipaa_reports import HIPAAComplianceReporter
        
        metrics = HIPAAComplianceReporter.generate_hipaa_dashboard_metrics()
        return Response(metrics)
    
    @action(detail=False, methods=['get'])
    def risk_assessment(self, request):
        """Get security risk assessment."""
        from .services.hipaa_reports import HIPAAComplianceReporter
        
        assessment = HIPAAComplianceReporter.generate_security_risk_assessment()
        return Response(assessment)
    
    @action(detail=False, methods=['get'])
    def data_sharing(self, request):
        """Get data sharing report."""
        from .services.hipaa_reports import HIPAAComplianceReporter
        
        # Parse date parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                return Response({"error": "Invalid start_date format"}, status=400)
        else:
            start_date = None
            
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                return Response({"error": "Invalid end_date format"}, status=400)
        else:
            end_date = None
            
        report = HIPAAComplianceReporter.generate_data_sharing_report(start_date, end_date)
        return Response(report)
    
    @action(detail=False, methods=['get'])
    def minimum_necessary(self, request):
        """Get report on minimum necessary rule compliance."""
        from .services.hipaa_reports import HIPAAComplianceReporter
        
        # Parse date parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                return Response({"error": "Invalid start_date format"}, status=400)
        else:
            start_date = None
            
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                return Response({"error": "Invalid end_date format"}, status=400)
        else:
            end_date = None
            
        report = HIPAAComplianceReporter.generate_minimum_necessary_report(start_date, end_date)
        return Response(report)
    
    @action(detail=True, methods=['get'], url_path='patient-access/(?P<patient_id>[^/.]+)')
    def patient_access(self, request, patient_id=None):
        """Get report of all data access for a specific patient."""
        from .services.hipaa_reports import HIPAAComplianceReporter
        
        # Parse date parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                return Response({"error": "Invalid start_date format"}, status=400)
        else:
            start_date = None
            
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                return Response({"error": "Invalid end_date format"}, status=400)
        else:
            end_date = None
            
        report = HIPAAComplianceReporter.generate_patient_access_report(patient_id, start_date, end_date)
        return Response(report)

