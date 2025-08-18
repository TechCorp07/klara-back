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
    
    # Enhanced authentication endpoints
    path('auth/check-status/', UserViewSet.as_view({'get': 'check_status'}), name='check-status'),
    path('auth/verify-email/', UserViewSet.as_view({'post': 'verify_email'}), name='verify-email'),
    path('auth/request-verification/', UserViewSet.as_view({'post': 'request_email_verification'}), name='request-verification'),
    path('auth/request-phone-verification/', UserViewSet.as_view({'post': 'request_phone_verification'}), name='request-phone-verification'),
    path('auth/verify-phonenumber/', UserViewSet.as_view({'post': 'verify_phone'}), name='verify-phone'),
    path('auth/forgot-password/', UserViewSet.as_view({'post': 'forgot_password'}), name='forgot-password'),
    path('auth/reset-password/', UserViewSet.as_view({'post': 'reset_password'}), name='reset-password'),
    path('auth/change-password/', UserViewSet.as_view({'post': 'change_password'}), name='change-password'),
    path('auth/setup-2fa/', UserViewSet.as_view({'get': 'get_2fa_status', 'post': 'setup_2fa'}), name='setup-2fa'),
    path('auth/confirm-2fa/', UserViewSet.as_view({'post': 'confirm_2fa'}), name='confirm-2fa'),
    path('auth/verify-2fa/', UserViewSet.as_view({'post': 'verify_2fa'}), name='verify-2fa'),
    path('auth/disable-2fa/', UserViewSet.as_view({'post': 'disable_2fa'}), name='disable-2fa'),
    path('auth/request-2fa-email-backup/', UserViewSet.as_view({'post': 'request_2fa_email_backup'}), name='request-2fa-email-backup'),
    path('auth/verify-2fa-email-backup/', UserViewSet.as_view({'post': 'verify_2fa_email_backup'}), name='verify-2fa-email-backup'),
    path('auth/register/', UserViewSet.as_view({'post': 'create'}), name='register'),
    
    # Session Management
    path('auth/sessions/', UserViewSet.as_view({'get': 'list_user_sessions'}), name='user-sessions'),
    path('auth/session/terminate/', UserViewSet.as_view({'post': 'terminate_session'}), name='terminate-session'),
    path('auth/session/terminate-all/', UserViewSet.as_view({'post': 'terminate_all_sessions'}), name='terminate-all-sessions'),
    path('auth/session/health/', UserViewSet.as_view({'get': 'session_health'}), name='session-health'),
    path('auth/refresh-session/', UserViewSet.as_view({'post': 'refresh_session'}), name='refresh-session'),
    
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
    path('patient/dashboard/', PatientViewSet.as_view({'get': 'dashboard'}), name='patient-dashboard'),
    path('patient-profiles/<int:pk>/verify-identity/', PatientProfileViewSet.as_view({'post': 'verify_identity'}), name='verify-patient-identity'),
    path('patient-profiles/<int:pk>/update-consent/', PatientProfileViewSet.as_view({'post': 'update_consent'}), name='update-patient-consent'),
    path('patient/upload-photo/', PatientViewSet.as_view({'post': 'upload_photo'}), name='patient-upload-photo'),
    path('patient/delete-photo/', PatientViewSet.as_view({'delete': 'delete_photo'}), name='patient-delete-photo'),
    
    # Medication endpoints
    path('patient/medications/', PatientViewSet.as_view({'get': 'medications_list'}), name='patient-medications'),
    path('patient/medications/<int:medication_id>/log/', PatientViewSet.as_view({'post': 'log_medication'}), name='patient-log-medication'),
    path('patient/medications/analytics/', PatientViewSet.as_view({'get': 'medication_analytics'}), name='patient-medication-analytics'),
    
    # Vital signs endpoints
    path('patient/vitals/', PatientViewSet.as_view({'get': 'vitals_list', 'post': 'record_vitals'}), name='patient-vitals'),
    path('patient/vitals/latest/', PatientViewSet.as_view({'get': 'latest_vitals'}), name='patient-latest-vitals'),
    
    # Wearable device endpoints
    path('patient/wearable-devices/', PatientViewSet.as_view({'get': 'wearable_devices'}), name='patient-wearable-devices'),
    path('patient/wearable-devices/connect/', PatientViewSet.as_view({'post': 'connect_wearable_device'}), name='patient-connect-device'),
    path('patient/wearable-devices/<int:device_id>/disconnect/', PatientViewSet.as_view({'post': 'disconnect_wearable_device'}), name='patient-disconnect-device'),
    
    # Appointment endpoints
    path('patient/appointments/', PatientViewSet.as_view({'get': 'appointments_list'}), name='patient-appointments'),
    path('patient/appointments/request/', PatientViewSet.as_view({'post': 'request_appointment'}), name='patient-request-appointment'),
    path('patient/appointments/<int:appointment_id>/cancel/', PatientViewSet.as_view({'post': 'cancel_appointment'}), name='patient-cancel-appointment'),
    
    # Health alerts endpoints
    path('patient/alerts/', PatientViewSet.as_view({'get': 'alerts_list'}), name='patient-alerts'),
    path('patient/alerts/<int:alert_id>/acknowledge/', PatientViewSet.as_view({'post': 'acknowledge_alert'}), name='patient-acknowledge-alert'),
    path('patient/privacy-settings/', PatientViewSet.as_view({'get': 'privacy_settings', 'patch': 'update_privacy_settings'}), name='patient-privacy-settings'),
    
    # Research participation endpoints
    path('patient/research/available-studies/', PatientViewSet.as_view({'get': 'available_research_studies'}), name='patient-research-studies'),
    path('patient/research/studies/<int:study_id>/interest/', PatientViewSet.as_view({'post': 'express_research_interest'}), name='patient-research-interest'),
    
    # FHIR endpoints
    path('patient/fhir/export/', PatientViewSet.as_view({'post': 'export_fhir_data'}), name='patient-fhir-export'),
    path('patient/fhir/import-request/', PatientViewSet.as_view({'post': 'request_fhir_import'}), name='patient-fhir-import'),
    
    # Family history endpoints
    path('patient/family-history/', PatientViewSet.as_view({'get': 'family_history', 'post': 'update_family_history'}), name='patient-family-history'),
    
    # Medication reminders endpoints
    path('patient/profile/medication-reminders/', PatientProfileViewSet.as_view({'patch': 'update_medication_reminders'}), name='patient-medication-reminders'),
    
    # Telemedicine endpoints
    path('patient/telemedicine/request/', PatientViewSet.as_view({'post': 'request_telemedicine_session'}), name='patient-telemedicine-request'),
    path('patient/send_message_to_provider/', PatientViewSet.as_view({'post': 'send_message_to_provider'}), name='patient-send-message-provider'),
    
    # Chat groups endpoints
    path('patient/chat-groups/', PatientViewSet.as_view({'get': 'chat_groups'}), name='patient-chat-groups'),
    path('patient/chat-groups/<int:group_id>/join/', PatientViewSet.as_view({'post': 'join_chat_group'}), name='patient-join-chat-group'),
    
    # Emergency notification endpoints
    path('patient/emergency/notify/', PatientViewSet.as_view({'post': 'emergency_notification'}), name='patient-emergency-notification'),
    
    #dashboard endpoints
    path('provider-profiles/<int:pk>/complete/', ProviderProfileViewSet.as_view({'post': 'complete_profile'}), name='complete-provider-profile'),
    path('provider/dashboard/', ProviderProfileViewSet.as_view({'get': 'dashboard'}), name='provider-dashboard'),
    path('provider/available/', ProviderProfileViewSet.as_view({'get': 'get_available_providers'}), name='available-providers'),
    
    
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
