# security/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SecurityThreatViewSet,
    VulnerabilityAssessmentViewSet,
    VulnerabilityViewSet,
    SecurityIncidentViewSet,
    NetworkMonitorViewSet,
    FileIntegrityMonitorViewSet,
    SecurityConfigurationViewSet,
    ComplianceReportViewSet,
    SecurityDashboardViewSet
)

router = DefaultRouter()
router.register(r'threats', SecurityThreatViewSet)
router.register(r'vulnerability-assessments', VulnerabilityAssessmentViewSet)
router.register(r'vulnerabilities', VulnerabilityViewSet)
router.register(r'incidents', SecurityIncidentViewSet)
router.register(r'network-monitoring', NetworkMonitorViewSet)
router.register(r'file-integrity', FileIntegrityMonitorViewSet)
router.register(r'configurations', SecurityConfigurationViewSet)
router.register(r'compliance-reports', ComplianceReportViewSet)
router.register(r'dashboard', SecurityDashboardViewSet, basename='security-dashboard')

urlpatterns = [
    path('', include(router.urls)),
    
    # Real-time monitoring endpoints
    path('monitoring/real-time/', SecurityDashboardViewSet.as_view({'get': 'overview'}), name='realtime-monitoring'),
    path('monitoring/emergency/', SecurityDashboardViewSet.as_view({'post': 'emergency_response'}), name='emergency-response'),
    
    # Threat management endpoints
    path('threats/detection/run/', SecurityThreatViewSet.as_view({'post': 'run_threat_detection'}), name='run-threat-detection'),
    path('threats/<uuid:pk>/assign/', SecurityThreatViewSet.as_view({'post': 'assign_threat'}), name='assign-threat'),
    path('threats/<uuid:pk>/escalate/', SecurityThreatViewSet.as_view({'post': 'escalate_threat'}), name='escalate-threat'),
    
    # Vulnerability scanning endpoints
    path('scanning/start/', VulnerabilityAssessmentViewSet.as_view({'post': 'start_scan'}), name='start-vulnerability-scan'),
    path('scanning/<uuid:pk>/results/', VulnerabilityAssessmentViewSet.as_view({'get': 'scan_results'}), name='scan-results'),
    
    # Incident management endpoints
    path('incidents/active/', SecurityIncidentViewSet.as_view({'get': 'active_incidents'}), name='active-incidents'),
    path('incidents/<uuid:pk>/escalate/', SecurityIncidentViewSet.as_view({'post': 'escalate'}), name='escalate-incident'),
    
    # Compliance reporting endpoints
    path('compliance/generate/', ComplianceReportViewSet.as_view({'post': 'generate_report'}), name='generate-compliance-report'),
    path('compliance/dashboard/', ComplianceReportViewSet.as_view({'get': 'dashboard_compliance'}), name='compliance-dashboard'),
    
    # Monitoring endpoints
    path('monitoring/network/alerts/', NetworkMonitorViewSet.as_view({'get': 'real_time_alerts'}), name='network-alerts'),
    path('monitoring/network/threats/', NetworkMonitorViewSet.as_view({'get': 'top_threats'}), name='network-threats'),
    path('monitoring/files/critical/', FileIntegrityMonitorViewSet.as_view({'get': 'critical_changes'}), name='critical-file-changes'),
    
    # Dashboard metrics endpoints
    path('metrics/dashboard/', SecurityThreatViewSet.as_view({'get': 'dashboard_metrics'}), name='security-metrics'),
    path('metrics/vulnerabilities/', VulnerabilityViewSet.as_view({'get': 'critical_dashboard'}), name='vulnerability-metrics'),
]