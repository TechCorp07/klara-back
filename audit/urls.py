# Update to audit/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AuditEventViewSet, 
    PHIAccessLogViewSet, 
    SecurityAuditLogViewSet, 
    ComplianceReportViewSet, 
    AuditExportViewSet,
    ComplianceDashboardViewSet
)

router = DefaultRouter()
router.register(r'events', AuditEventViewSet)
router.register(r'phi-access', PHIAccessLogViewSet)
router.register(r'security', SecurityAuditLogViewSet)
router.register(r'reports', ComplianceReportViewSet)
router.register(r'exports', AuditExportViewSet, basename='audit-export')
router.register(r'dashboard', ComplianceDashboardViewSet, basename='compliance-dashboard')

urlpatterns = [
    path('', include(router.urls)),
    
    # Custom compliance endpoints for direct access
    path('compliance/metrics/', ComplianceDashboardViewSet.as_view({'get': 'metrics'}), name='compliance-metrics'),
    path('compliance/risk-assessment/', ComplianceDashboardViewSet.as_view({'get': 'risk_assessment'}), name='compliance-risk-assessment'),
    path('compliance/data-sharing/', ComplianceDashboardViewSet.as_view({'get': 'data_sharing'}), name='compliance-data-sharing'),
    path('compliance/minimum-necessary/', ComplianceDashboardViewSet.as_view({'get': 'minimum_necessary'}), name='compliance-minimum-necessary'),
    path('compliance/patient-access/<str:patient_id>/', ComplianceDashboardViewSet.as_view({'get': 'patient_access'}), name='compliance-patient-access'),
]
