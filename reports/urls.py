from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ReportConfigurationViewSet, ReportViewSet, DashboardViewSet,
    DashboardWidgetViewSet, AnalyticsMetricViewSet, ReportScheduleLogViewSet,
    DataExportViewSet, AnalyticsViewSet
)
from .views_ai import AIAnalysisViewSet

router = DefaultRouter()
router.register(r'report-configurations', ReportConfigurationViewSet)
router.register(r'reports', ReportViewSet, basename='report')
router.register(r'dashboards', DashboardViewSet, basename='dashboard')
router.register(r'dashboard-widgets', DashboardWidgetViewSet, basename='dashboard-widget')
router.register(r'analytics-metrics', AnalyticsMetricViewSet, basename='analytics-metric')
router.register(r'schedule-logs', ReportScheduleLogViewSet, basename='schedule-log')
router.register(r'data-exports', DataExportViewSet, basename='data-export')
router.register(r'analytics', AnalyticsViewSet, basename='analytics')
router.register(r'ai-analysis', AIAnalysisViewSet, basename='ai-analysis')

urlpatterns = [
    path('', include(router.urls)),
]
