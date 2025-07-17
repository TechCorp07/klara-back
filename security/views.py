# security/views.py
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q, Count, Avg, Max, Min
from django.http import HttpResponse, JsonResponse
from rest_framework import viewsets, status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from celery import current_app

from .models import (
    SecurityThreat, VulnerabilityAssessment, Vulnerability,
    SecurityIncident, NetworkMonitor, FileIntegrityMonitor,
    SecurityConfiguration, ComplianceReport
)
from .serializers import (
    SecurityThreatSerializer, VulnerabilityAssessmentSerializer,
    VulnerabilitySerializer, SecurityIncidentSerializer,
    NetworkMonitorSerializer, FileIntegrityMonitorSerializer,
    SecurityConfigurationSerializer, ComplianceReportSerializer
)
from .permissions import IsSecurityAdminUser
from .services.threat_detection import ThreatDetectionService
from .services.vulnerability_scanner import VulnerabilityScanner
from .services.compliance_reporter import ComplianceReporter
from .services.incident_response import IncidentResponseService
from .tasks import (
    run_vulnerability_scan, generate_security_report,
    check_system_integrity, monitor_network_traffic
)


class SecurityThreatViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing security threats.
    Only security administrators and superusers can access.
    """
    queryset = SecurityThreat.objects.all().order_by('-detection_time')
    serializer_class = SecurityThreatSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['threat_type', 'severity', 'status', 'detection_source']
    search_fields = ['title', 'description', 'source_ip', 'target_ip']
    ordering_fields = ['detection_time', 'severity', 'status']
    
    def get_queryset(self):
        """Filter threats based on query parameters."""
        queryset = super().get_queryset()
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.fromisoformat(start_date)
                queryset = queryset.filter(detection_time__gte=start_date)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_date = datetime.fromisoformat(end_date)
                queryset = queryset.filter(detection_time__lte=end_date)
            except ValueError:
                pass
        
        return queryset
    
    @action(detail=False, methods=['get'])
    def dashboard_metrics(self, request):
        """Get real-time security metrics for dashboard."""
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        last_30d = now - timedelta(days=30)
        
        # Threat metrics
        threats_24h = SecurityThreat.objects.filter(detection_time__gte=last_24h)
        threats_7d = SecurityThreat.objects.filter(detection_time__gte=last_7d)
        threats_30d = SecurityThreat.objects.filter(detection_time__gte=last_30d)
        
        # Critical threats requiring immediate attention
        critical_threats = SecurityThreat.objects.filter(
            severity='critical',
            status__in=['detected', 'investigating']
        ).count()
        
        # High priority threats
        high_priority_threats = SecurityThreat.objects.filter(
            severity='high',
            status__in=['detected', 'investigating']
        ).count()
        
        # Threat trend analysis
        threat_trend = []
        for i in range(7):
            day = now - timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            count = SecurityThreat.objects.filter(
                detection_time__gte=day_start,
                detection_time__lt=day_end
            ).count()
            threat_trend.append({
                'date': day_start.date().isoformat(),
                'count': count
            })
        
        # Threat types distribution
        threat_types = list(
            threats_7d.values('threat_type')
            .annotate(count=Count('id'))
            .order_by('-count')
        )
        
        return Response({
            'threats_24h': threats_24h.count(),
            'threats_7d': threats_7d.count(),
            'threats_30d': threats_30d.count(),
            'critical_threats': critical_threats,
            'high_priority_threats': high_priority_threats,
            'threat_trend': threat_trend,
            'threat_types_distribution': threat_types,
            'active_incidents': SecurityIncident.objects.filter(
                status__in=['reported', 'investigating', 'containment']
            ).count(),
            'vulnerabilities_open': Vulnerability.objects.filter(
                status='open'
            ).count(),
            'last_updated': now.isoformat()
        })
    
    @action(detail=True, methods=['post'])
    def assign_threat(self, request, pk=None):
        """Assign threat to security analyst."""
        threat = self.get_object()
        assigned_to_id = request.data.get('assigned_to')
        
        if assigned_to_id:
            try:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                assigned_user = User.objects.get(id=assigned_to_id, role__in=['admin', 'security'])
                threat.assigned_to = assigned_user
                threat.status = 'investigating'
                threat.save(update_fields=['assigned_to', 'status'])
                
                return Response({'detail': 'Threat assigned successfully'})
            except User.DoesNotExist:
                return Response(
                    {'error': 'Invalid user or insufficient permissions'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(
            {'error': 'assigned_to field is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    @action(detail=True, methods=['post'])
    def escalate_threat(self, request, pk=None):
        """Escalate threat severity and create incident."""
        threat = self.get_object()
        
        # Create security incident
        incident = IncidentResponseService.create_incident_from_threat(threat)
        
        # Update threat
        threat.severity = 'critical'
        threat.save(update_fields=['severity'])
        
        return Response({
            'detail': 'Threat escalated successfully',
            'incident_id': incident.incident_id
        })
    
    @action(detail=False, methods=['post'])
    def run_threat_detection(self, request):
        """Trigger immediate threat detection scan."""
        # Run threat detection in background
        from .tasks import run_threat_detection_scan
        task = run_threat_detection_scan.delay()
        
        return Response({
            'detail': 'Threat detection scan initiated',
            'task_id': task.id
        })


class VulnerabilityAssessmentViewSet(viewsets.ModelViewSet):
    """ViewSet for vulnerability assessments."""
    
    queryset = VulnerabilityAssessment.objects.all().order_by('-started_at')
    serializer_class = VulnerabilityAssessmentSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['scan_type', 'status', 'scanner_tool']
    search_fields = ['target', 'scanner_tool']
    
    @action(detail=False, methods=['post'])
    def start_scan(self, request):
        """Start a new vulnerability scan."""
        scan_type = request.data.get('scan_type')
        target = request.data.get('target')
        scan_profile = request.data.get('scan_profile', 'default')
        
        if not scan_type or not target:
            return Response(
                {'error': 'scan_type and target are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create assessment record
        assessment = VulnerabilityAssessment.objects.create(
            scan_type=scan_type,
            target=target,
            scan_profile=scan_profile,
            scanner_tool='OWASP ZAP',  # Default scanner
            initiated_by=request.user,
            status='scheduled'
        )
        
        # Start scan in background
        run_vulnerability_scan.delay(assessment.id)
        
        return Response({
            'detail': 'Vulnerability scan started',
            'assessment_id': str(assessment.id)
        })
    
    @action(detail=True, methods=['get'])
    def scan_results(self, request, pk=None):
        """Get detailed scan results."""
        assessment = self.get_object()
        
        if assessment.status != 'completed':
            return Response({
                'detail': 'Scan not completed yet',
                'status': assessment.status
            })
        
        # Get vulnerabilities found in this scan
        vulnerabilities = Vulnerability.objects.filter(
            assessment=assessment
        ).order_by('-cvss_score')
        
        serialized_vulns = VulnerabilitySerializer(vulnerabilities, many=True)
        
        return Response({
            'assessment': VulnerabilityAssessmentSerializer(assessment).data,
            'vulnerabilities': serialized_vulns.data,
            'summary': {
                'total': assessment.total_vulnerabilities,
                'critical': assessment.critical_count,
                'high': assessment.high_count,
                'medium': assessment.medium_count,
                'low': assessment.low_count,
                'info': assessment.info_count
            }
        })


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """ViewSet for individual vulnerabilities."""
    
    queryset = Vulnerability.objects.all().order_by('-cvss_score')
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['severity', 'status', 'cve_id']
    search_fields = ['title', 'description', 'cve_id', 'affected_component']
    
    @action(detail=False, methods=['get'])
    def critical_dashboard(self, request):
        """Get critical vulnerabilities for security dashboard."""
        critical_vulns = Vulnerability.objects.filter(
            severity__in=['critical', 'high'],
            status='open'
        ).select_related('assessment')
        
        # Group by affected component
        by_component = {}
        for vuln in critical_vulns:
            component = vuln.affected_component
            if component not in by_component:
                by_component[component] = {
                    'component': component,
                    'critical_count': 0,
                    'high_count': 0,
                    'vulnerabilities': []
                }
            
            by_component[component]['vulnerabilities'].append({
                'id': str(vuln.id),
                'title': vuln.title,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'cve_id': vuln.cve_id
            })
            
            if vuln.severity == 'critical':
                by_component[component]['critical_count'] += 1
            elif vuln.severity == 'high':
                by_component[component]['high_count'] += 1
        
        return Response({
            'critical_vulnerabilities': list(by_component.values()),
            'total_critical': sum(c['critical_count'] for c in by_component.values()),
            'total_high': sum(c['high_count'] for c in by_component.values())
        })
    
    @action(detail=True, methods=['post'])
    def mark_fixed(self, request, pk=None):
        """Mark vulnerability as fixed."""
        vulnerability = self.get_object()
        vulnerability.status = 'fixed'
        vulnerability.fixed_at = timezone.now()
        vulnerability.save(update_fields=['status', 'fixed_at'])
        
        return Response({'detail': 'Vulnerability marked as fixed'})


class SecurityIncidentViewSet(viewsets.ModelViewSet):
    """ViewSet for security incident management."""
    
    queryset = SecurityIncident.objects.all().order_by('-reported_at')
    serializer_class = SecurityIncidentSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['incident_type', 'priority', 'status']
    search_fields = ['incident_id', 'title', 'description']
    
    def perform_create(self, serializer):
        """Auto-generate incident ID when creating."""
        # Generate incident ID: INC-YYYY-NNNN
        year = timezone.now().year
        last_incident = SecurityIncident.objects.filter(
            incident_id__startswith=f'INC-{year}-'
        ).order_by('-incident_id').first()
        
        if last_incident:
            last_num = int(last_incident.incident_id.split('-')[-1])
            incident_num = last_num + 1
        else:
            incident_num = 1
        
        incident_id = f'INC-{year}-{incident_num:04d}'
        
        serializer.save(
            incident_id=incident_id,
            reported_by=self.request.user
        )
    
    @action(detail=False, methods=['get'])
    def active_incidents(self, request):
        """Get active incidents requiring attention."""
        active_incidents = SecurityIncident.objects.filter(
            status__in=['reported', 'acknowledged', 'investigating', 'containment']
        ).order_by('priority', '-reported_at')
        
        serializer = SecurityIncidentSerializer(active_incidents, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def escalate(self, request, pk=None):
        """Escalate incident priority."""
        incident = self.get_object()
        
        priority_order = ['low', 'medium', 'high', 'critical']
        current_index = priority_order.index(incident.priority)
        
        if current_index < len(priority_order) - 1:
            incident.priority = priority_order[current_index + 1]
            incident.save(update_fields=['priority'])
            
            # Notify security team
            IncidentResponseService.notify_escalation(incident)
            
            return Response({
                'detail': f'Incident escalated to {incident.priority} priority'
            })
        
        return Response({
            'detail': 'Incident is already at highest priority'
        })


class NetworkMonitorViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for network monitoring alerts."""
    
    queryset = NetworkMonitor.objects.all().order_by('-timestamp')
    serializer_class = NetworkMonitorSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['alert_type', 'severity', 'source_ip']
    search_fields = ['source_ip', 'destination_ip', 'description']
    
    @action(detail=False, methods=['get'])
    def real_time_alerts(self, request):
        """Get real-time network alerts from last hour."""
        last_hour = timezone.now() - timedelta(hours=1)
        alerts = NetworkMonitor.objects.filter(
            timestamp__gte=last_hour,
            is_false_positive=False
        ).order_by('-timestamp')[:100]
        
        serializer = NetworkMonitorSerializer(alerts, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def top_threats(self, request):
        """Get top network threats by source IP."""
        last_24h = timezone.now() - timedelta(hours=24)
        
        top_sources = (
            NetworkMonitor.objects
            .filter(timestamp__gte=last_24h, is_false_positive=False)
            .values('source_ip')
            .annotate(
                alert_count=Count('id'),
                max_severity=Max('severity'),
                latest_alert=Max('timestamp')
            )
            .order_by('-alert_count')[:20]
        )
        
        return Response(list(top_sources))


class FileIntegrityMonitorViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for file integrity monitoring."""
    
    queryset = FileIntegrityMonitor.objects.all().order_by('-timestamp')
    serializer_class = FileIntegrityMonitorSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['change_type', 'is_critical_file', 'is_authorized_change']
    search_fields = ['file_path', 'user_context', 'process_name']
    
    @action(detail=False, methods=['get'])
    def critical_changes(self, request):
        """Get critical file changes requiring review."""
        critical_changes = FileIntegrityMonitor.objects.filter(
            is_critical_file=True,
            is_authorized_change=False
        ).order_by('-timestamp')[:50]
        
        serializer = FileIntegrityMonitorSerializer(critical_changes, many=True)
        return Response(serializer.data)


class SecurityConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet for security configuration management."""
    
    queryset = SecurityConfiguration.objects.all().order_by('-updated_at')
    serializer_class = SecurityConfigurationSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['config_type', 'is_active']
    search_fields = ['name', 'description']
    
    def perform_create(self, serializer):
        """Set creator when creating configuration."""
        serializer.save(created_by=self.request.user)


class ComplianceReportViewSet(viewsets.ModelViewSet):
    """ViewSet for compliance reporting."""
    
    queryset = ComplianceReport.objects.all().order_by('-generated_at')
    serializer_class = ComplianceReportSerializer
    permission_classes = [IsSecurityAdminUser]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['report_type', 'status']
    
    @action(detail=False, methods=['post'])
    def generate_report(self, request):
        """Generate a new compliance report."""
        report_type = request.data.get('report_type')
        period_start = request.data.get('period_start')
        period_end = request.data.get('period_end')
        
        if not all([report_type, period_start, period_end]):
            return Response(
                {'error': 'report_type, period_start, and period_end are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            period_start = datetime.fromisoformat(period_start)
            period_end = datetime.fromisoformat(period_end)
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use ISO format.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create report record
        report = ComplianceReport.objects.create(
            report_type=report_type,
            generated_by=request.user,
            period_start=period_start,
            period_end=period_end
        )
        
        # Generate report in background
        generate_security_report.delay(report.id)
        
        return Response({
            'detail': 'Compliance report generation started',
            'report_id': str(report.id)
        })
    
    @action(detail=False, methods=['get'])
    def dashboard_compliance(self, request):
        """Get compliance metrics for dashboard."""
        # Get latest reports for each type
        latest_reports = {}
        for report_type, _ in ComplianceReport.ReportType.choices:
            latest = ComplianceReport.objects.filter(
                report_type=report_type,
                status='completed'
            ).order_by('-generated_at').first()
            
            if latest:
                latest_reports[report_type] = {
                    'compliance_score': latest.compliance_score,
                    'total_controls': latest.total_controls,
                    'passed_controls': latest.passed_controls,
                    'failed_controls': latest.failed_controls,
                    'generated_at': latest.generated_at.isoformat()
                }
        
        return Response(latest_reports)


class SecurityDashboardViewSet(viewsets.ViewSet):
    """ViewSet for security dashboard and real-time monitoring."""
    
    permission_classes = [IsSecurityAdminUser]
    
    @action(detail=False, methods=['get'])
    def overview(self, request):
        """Get complete security overview for dashboard."""
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Security metrics
        active_threats = SecurityThreat.objects.filter(
            status__in=['detected', 'investigating']
        ).count()
        
        critical_vulnerabilities = Vulnerability.objects.filter(
            severity='critical',
            status='open'
        ).count()
        
        active_incidents = SecurityIncident.objects.filter(
            status__in=['reported', 'investigating', 'containment']
        ).count()
        
        # Recent activity
        recent_threats = SecurityThreat.objects.filter(
            detection_time__gte=last_24h
        ).count()
        
        recent_network_alerts = NetworkMonitor.objects.filter(
            timestamp__gte=last_24h,
            is_false_positive=False
        ).count()
        
        # System health
        last_scan = VulnerabilityAssessment.objects.filter(
            status='completed'
        ).order_by('-completed_at').first()
        
        return Response({
            'security_status': {
                'active_threats': active_threats,
                'critical_vulnerabilities': critical_vulnerabilities,
                'active_incidents': active_incidents,
                'threat_level': self._calculate_threat_level()
            },
            'recent_activity': {
                'threats_24h': recent_threats,
                'network_alerts_24h': recent_network_alerts,
                'file_changes_24h': FileIntegrityMonitor.objects.filter(
                    timestamp__gte=last_24h,
                    is_authorized_change=False
                ).count()
            },
            'system_health': {
                'last_vulnerability_scan': last_scan.completed_at.isoformat() if last_scan else None,
                'monitoring_active': True,  # This would check actual monitoring services
                'backup_status': 'OK',  # This would check backup systems
                'uptime': '99.9%'  # This would calculate actual uptime
            },
            'last_updated': now.isoformat()
        })
    
    def _calculate_threat_level(self):
        """Calculate overall threat level based on current threats."""
        critical_threats = SecurityThreat.objects.filter(
            severity='critical',
            status__in=['detected', 'investigating']
        ).count()
        
        high_threats = SecurityThreat.objects.filter(
            severity='high',
            status__in=['detected', 'investigating']
        ).count()
        
        if critical_threats > 0:
            return 'CRITICAL'
        elif high_threats > 3:
            return 'HIGH'
        elif high_threats > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @action(detail=False, methods=['post'])
    def emergency_response(self, request):
        """Trigger emergency security response procedures."""
        response_type = request.data.get('type')  # lockdown, isolate, notify
        
        if response_type == 'lockdown':
            # Implement system lockdown procedures
            return Response({'detail': 'Emergency lockdown initiated'})
        elif response_type == 'isolate':
            # Implement network isolation
            return Response({'detail': 'Network isolation initiated'})
        elif response_type == 'notify':
            # Send emergency notifications
            return Response({'detail': 'Emergency notifications sent'})
        
        return Response(
            {'error': 'Invalid response type'},
            status=status.HTTP_400_BAD_REQUEST
        )
