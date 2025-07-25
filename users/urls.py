# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AdminViewSet, PatientViewSet, UserViewSet, PatientProfileViewSet, ProviderProfileViewSet,
    PharmcoProfileViewSet, CaregiverProfileViewSet, ResearcherProfileViewSet,
    ComplianceProfileViewSet, CaregiverRequestViewSet, EmergencyAccessViewSet,
    HIPAADocumentViewSet, ConsentRecordViewSet
)
from .enhanced_views import (
    EnhancedResearchViewSet, 
    EnhancedNotificationViewSet
)
# Create router
router = DefaultRouter()

# Register viewsets
router.register(r'users', UserViewSet, basename='user')
router.register(r'patient', PatientViewSet, basename='patient')
router.register(r'patient-profiles', PatientProfileViewSet, basename='patient-profile')
router.register(r'provider-profiles', ProviderProfileViewSet, basename='provider-profile')
router.register(r'pharmco-profiles', PharmcoProfileViewSet, basename='pharmco-profile')
router.register(r'caregiver-profiles', CaregiverProfileViewSet, basename='caregiver-profile')
router.register(r'researcher-profiles', ResearcherProfileViewSet, basename='researcher-profile')
router.register(r'compliance-profiles', ComplianceProfileViewSet, basename='compliance-profile')
router.register(r'caregiver-requests', CaregiverRequestViewSet, basename='caregiver-request')
router.register(r'emergency-access', EmergencyAccessViewSet, basename='emergency-access')
router.register(r'hipaa-documents', HIPAADocumentViewSet, basename='hipaa-document')
router.register(r'consent-records', ConsentRecordViewSet, basename='consent-record')

urlpatterns = [
    path('', include(router.urls)),
    
    # Core Authentication (JWT-based)
    path('auth/login/', UserViewSet.as_view({'post': 'login'}), name='jwt-login'),
    path('auth/logout/', UserViewSet.as_view({'post': 'logout'}), name='jwt-logout'),
    path('auth/refresh/', UserViewSet.as_view({'post': 'refresh_token'}), name='jwt-refresh'),
    path('auth/me/', UserViewSet.as_view({'get': 'me'}), name='current-user'),
    path('auth/refresh-session/', UserViewSet.as_view({'post': 'refresh_session'}), name='session-refresh'),
    
    # Enhanced authentication endpoints
    path('auth/check-status/', UserViewSet.as_view({'get': 'check_status'}), name='check-status'),
    path('auth/verify-email/', UserViewSet.as_view({'post': 'verify_email'}), name='verify-email'),
    path('auth/request-verification/', UserViewSet.as_view({'post': 'request_email_verification'}), name='request-verification'),
    path('auth/request-phone-verification/', UserViewSet.as_view({'post': 'request_phone_verification'}), name='request-phone-verification'),
    path('auth/verify-phonenumber/', UserViewSet.as_view({'post': 'verify_phone'}), name='verify-phone'),
    path('auth/forgot-password/', UserViewSet.as_view({'post': 'forgot_password'}), name='forgot-password'),
    path('auth/reset-password/', UserViewSet.as_view({'post': 'reset_password'}), name='reset-password'),
    path('auth/setup-2fa/', UserViewSet.as_view({'post': 'setup_2fa'}), name='setup-2fa'),
    path('auth/confirm-2fa/', UserViewSet.as_view({'post': 'confirm_2fa'}), name='confirm-2fa'),
    path('auth/verify-2fa/', UserViewSet.as_view({'post': 'verify_2fa'}), name='verify-2fa'),
    path('auth/disable-2fa/', UserViewSet.as_view({'post': 'disable_2fa'}), name='disable-2fa'),
    path('auth/register/', UserViewSet.as_view({'post': 'create'}), name='register'),

    # Session Management
    path('auth/sessions/', UserViewSet.as_view({'get': 'list_user_sessions'}), name='user-sessions'),
    path('auth/session/terminate/', UserViewSet.as_view({'post': 'terminate_session'}), name='terminate-session'),
    path('auth/session/terminate-all/', UserViewSet.as_view({'post': 'terminate_all_sessions'}), name='terminate-all-sessions'),
    path('auth/session/health/', UserViewSet.as_view({'get': 'session_health'}), name='session-health'),
    path('auth/debug/', UserViewSet.as_view({'get': 'debug_auth'}), name='debug-auth'),

    # Emergency Access
    path('auth/emergency-access/', UserViewSet.as_view({'post': 'emergency_access'}), name='emergency-access'),
    
    # Pharmaceutical Tenant Management
    path('auth/switch-tenant/', UserViewSet.as_view({'post': 'switch_tenant'}), name='switch-tenant'),
    path('tenants/', UserViewSet.as_view({'get': 'list_tenants'}), name='list-tenants'),
    
    # User management
    path('users/pending-approvals/', UserViewSet.as_view({'get': 'pending_approvals'}), name='pending-approvals'),
    path('users/<int:pk>/approve/', UserViewSet.as_view({'post': 'approve_user'}), name='approve-user'),
    path('users/create-admin/', UserViewSet.as_view({'post': 'create_admin'}), name='create-admin'),
    path('users/<int:pk>/reactivate/', UserViewSet.as_view({'post': 'reactivate_user'}), name='reactivate-user'),

    # Patient specific endpoints
    path('patient-profiles/<int:pk>/verify-identity/', PatientProfileViewSet.as_view({'post': 'verify_identity'}), name='verify-patient-identity'),
    path('patient-profiles/<int:pk>/update-consent/', PatientProfileViewSet.as_view({'post': 'update_consent'}), name='update-patient-consent'),
    path('patient/profile/medication-reminders/', PatientProfileViewSet.as_view({'patch': 'update_medication_reminders'}), name='patient-medication-reminders'),

    #dashboard endpoints
    path('provider/dashboard/', ProviderProfileViewSet.as_view({'get': 'dashboard'}), name='provider-dashboard'),     
    path('pharmco/dashboard/', PharmcoProfileViewSet.as_view({'get': 'dashboard'}), name='pharmco-dashboard'),       
    #path('researcher/dashboard/', ResearcherViewSet.as_view({'get': 'dashboard'}), name='researcher-dashboard'),
    #path('caregiver/dashboard/', CaregiverViewSet.as_view({'get': 'dashboard'}), name='caregiver-dashboard'),
    #path('compliance/dashboard/', ComplianceViewSet.as_view({'get': 'dashboard'}), name='compliance-dashboard'),

    # Caregiver request endpoints
    path('caregiver-requests/<int:pk>/approve/', CaregiverRequestViewSet.as_view({'post': 'approve'}), name='approve-caregiver'),
    path('caregiver-requests/<int:pk>/deny/', CaregiverRequestViewSet.as_view({'post': 'deny'}), name='deny-caregiver'),
    
    # Emergency access endpoints
    path('emergency-access/initiate/', EmergencyAccessViewSet.as_view({'post': 'initiate'}), name='initiate-emergency-access'),
    path('emergency-access/<int:pk>/end/', EmergencyAccessViewSet.as_view({'post': 'end_access'}), name='end-emergency-access'),
    path('emergency-access/<int:pk>/review/', EmergencyAccessViewSet.as_view({'post': 'review'}), name='review-emergency-access'),
    
    # HIPAA document endpoints
    path('hipaa-documents/latest/', HIPAADocumentViewSet.as_view({'get': 'get_latest'}), name='latest-documents'),
    path('hipaa-documents/<int:pk>/sign/', HIPAADocumentViewSet.as_view({'post': 'sign'}), name='sign-document'),
    
    # Researcher verification and Consent Management
    path('researcher-profiles/<int:pk>/verify/', ResearcherProfileViewSet.as_view({'post': 'verify'}), name='verify-researcher'),
    path('research/consents/', UserViewSet.as_view({'get': 'list_research_consents', 'post': 'grant_research_consent'}), name='research-consents'),
    path('research/consents/<uuid:consent_id>/', UserViewSet.as_view({'patch': 'update_research_consent', 'delete': 'withdraw_research_consent'}), name='research-consent-detail'),
    path('research/create-study/', EnhancedResearchViewSet.as_view({'post': 'create_research_study'}), name='create-research-study'),
    path('research/patient-dashboard/', EnhancedResearchViewSet.as_view({'get': 'get_patient_research_dashboard'}), name='patient-research-dashboard'),
    
    # Profile completion endpoints
    path('patient-profiles/<int:pk>/complete/', PatientProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-patient-profile'),
    path('provider-profiles/<int:pk>/complete/', ProviderProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-provider-profile'),
    path('pharmco-profiles/<int:pk>/complete/', PharmcoProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-pharmco-profile'),
    path('caregiver-profiles/<int:pk>/complete/', CaregiverProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-caregiver-profile'),
    path('researcher-profiles/<int:pk>/complete/', ResearcherProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-researcher-profile'),
    path('compliance-profiles/<int:pk>/complete/', ComplianceProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-compliance-profile'),
    
    # Admin and Management Endpoints
    path('auth/bulk-approve/', UserViewSet.as_view({'post': 'bulk_approve'}), name='bulk-approve-users'),
    path('auth/bulk-deny/', UserViewSet.as_view({'post': 'bulk_deny'}), name='bulk-deny-users'),
    path('auth/security-invalidate/', UserViewSet.as_view({'post': 'security_invalidate_tokens'}), name='security-invalidate'),
    path('admin/dashboard-stats/', AdminViewSet.as_view({'get': 'admin-dashboard-stats'}), name='admin-dashboard-stats'),
    path('admin/dashboard-overview/', AdminViewSet.as_view({'get': 'dashboard-overview'}), name='dashboard-overview'),
    path('admin/notification-summary/', AdminViewSet.as_view({'get': 'admin_notification_summary'}), name='admin-notification-summary'),
    
    # Audit and Compliance endpoints
    path('compliance/audit-trail/', ConsentRecordViewSet.as_view({'get': 'audit_trail'}), name='compliance-audit-trail'),
    path('compliance/emergency-summary/', EmergencyAccessViewSet.as_view({'get': 'compliance_summary'}), name='emergency-compliance-summary'),
    path('audit/trails/', UserViewSet.as_view({'get': 'list_audit_trails'}), name='audit-trails'),
    path('audit/compliance-report/', UserViewSet.as_view({'get': 'compliance_report'}), name='compliance-report'),
    path('audit/security-events/', UserViewSet.as_view({'get': 'security_events'}), name='security-events'),

    # Identity verification endpoints
    path('patient-profiles/<int:pk>/initiate-verification/', PatientProfileViewSet.as_view({'post': 'initiate_verification'}), name='initiate-identity-verification'),
    path('patient-profiles/<int:pk>/complete-verification/', PatientProfileViewSet.as_view({'post': 'complete_verification'}), name='complete-identity-verification'),
    
    # Enhanced Notification endpoints
    path('notifications/wearable-alerts/', EnhancedNotificationViewSet.as_view({'post': 'send_wearable_notification'}), name='wearable-alerts'),
]

app_name = 'users'
