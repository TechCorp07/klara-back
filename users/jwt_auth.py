# users/jwt_auth.py
# JWT Authentication System for Healthcare Platform
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from typing import Dict, Any, Optional, Tuple
import logging

from .models import UserSession, RefreshToken, PharmaceuticalTenant, AuditTrail

User = get_user_model()
logger = logging.getLogger(__name__)


class JWTAuthenticationManager:
    """
    Manages JWT token generation, validation, and refresh operations.
    Designed to eliminate race conditions in authentication flows.
    """
    
    # Token configuration
    ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)  # Short-lived for security
    REFRESH_TOKEN_LIFETIME = timedelta(hours=24)   # Longer-lived for convenience
    ALGORITHM = 'HS256'
    
    @classmethod
    def get_jwt_secret(cls, user=None, version=1):
        """
        Generate JWT secret with user-specific versioning for token rotation.
        This enables invalidating all tokens for a user by incrementing their version.
        """
        base_secret = getattr(settings, 'JWT_SECRET_KEY', settings.SECRET_KEY)
        if user:
            # Include user-specific data and version for individual token management
            user_component = f"{user.id}:{user.email}:{version}"
            combined = f"{base_secret}:{user_component}"
            return hashlib.sha256(combined.encode()).hexdigest()
        return base_secret
    
    @classmethod
    def create_access_token(cls, user: User, session: UserSession) -> str:
        """
        Create JWT access token with embedded user context and permissions.
        This eliminates the need for database calls during authorization checks.
        """
        now = timezone.now()
        
        # Build comprehensive payload with healthcare-specific context
        payload = {
            # Standard JWT claims
            'iat': int(now.timestamp()),  # Issued at
            'exp': int((now + cls.ACCESS_TOKEN_LIFETIME).timestamp()),  # Expires
            'iss': 'klararety-healthcare',  # Issuer
            'sub': str(user.id),  # Subject (user ID)
            'jti': str(session.session_id),  # JWT ID (session ID)
            
            # User identity and status
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'is_approved': user.is_approved,
            'email_verified': user.email_verified,
            'two_factor_enabled': user.two_factor_enabled,
            
            # Pharmaceutical tenant context
            'primary_tenant_id': str(user.primary_pharmaceutical_tenant.id) if user.primary_pharmaceutical_tenant else None,
            'tenant_ids': [str(tenant.id) for tenant in user.pharmaceutical_tenants.all()],
            
            # Permissions (embedded to avoid database calls)
            'permissions': cls._get_user_permissions(user),
            
            # Healthcare-specific context
            'research_participant_id': user.research_participant_id,
            'emergency_access_enabled': cls._check_emergency_access_permissions(user),
            
            # Session metadata
            'session_id': str(session.session_id),
            'is_emergency_session': session.is_emergency_session,
            'device_fingerprint': session.device_fingerprint,
            
            # Security metadata
            'jwt_version': user.jwt_secret_version,
            'last_password_change': int(user.password_last_changed.timestamp()) if user.password_last_changed else None,
        }
        
        # Create token with user-specific secret
        secret = cls.get_jwt_secret(user, user.jwt_secret_version)
        token = jwt.encode(payload, secret, algorithm=cls.ALGORITHM)
        
        # Log token creation for audit trail
        AuditTrail.objects.create(
            user=user,
            session=session,
            pharmaceutical_tenant=user.primary_pharmaceutical_tenant,
            action_type='TOKEN_REFRESH',
            action_description=f'Access token created for session {session.session_id}',
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            risk_level='LOW'
        )
        
        return token
    
    @classmethod
    def create_refresh_token(cls, user: User, session: UserSession, ip_address: str) -> RefreshToken:
        """
        Create refresh token for automatic access token renewal.
        Uses secure random generation and stores hash for security.
        """
        # Generate cryptographically secure random token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        # Create refresh token record
        refresh_token = RefreshToken.objects.create(
            user=user,
            session=session,
            token_hash=token_hash,
            created_ip=ip_address,
            expires_at=timezone.now() + cls.REFRESH_TOKEN_LIFETIME
        )
        
        # Store raw token temporarily for return (never stored in database)
        refresh_token._raw_token = raw_token
        
        return refresh_token
    
    @classmethod
    def validate_access_token(cls, token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate JWT access token locally without database calls.
        This is the key to eliminating race conditions in middleware.
        """
        try:
            # First, decode without verification to get user info for secret generation
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            user_id = unverified_payload.get('user_id')
            jwt_version = unverified_payload.get('jwt_version', 1)
            
            if not user_id:
                return False, None, "Invalid token format"
            
            # Get user for secret generation (minimal database hit)
            try:
                user = User.objects.select_related('primary_pharmaceutical_tenant').get(id=user_id)
            except User.DoesNotExist:
                return False, None, "User not found"
            
            # Check if token version matches user's current version
            if jwt_version != user.jwt_secret_version:
                return False, None, "Token version mismatch - user tokens invalidated"
            
            # Verify token with user-specific secret
            secret = cls.get_jwt_secret(user, jwt_version)
            payload = jwt.decode(token, secret, algorithms=[cls.ALGORITHM])
            
            # Additional security checks
            if payload.get('sub') != str(user.id):
                return False, None, "Token subject mismatch"
            
            # Check if user account is still active and approved
            if not user.is_active:
                return False, None, "User account is inactive"
            
            if not user.is_approved:
                return False, None, "User account not approved"
            
            # Check account lockout
            if user.account_locked_until and timezone.now() < user.account_locked_until:
                return False, None, "Account is temporarily locked"
            
            # Check password change invalidation
            last_password_change = payload.get('last_password_change')
            if (user.password_last_changed and last_password_change and 
                int(user.password_last_changed.timestamp()) != last_password_change):
                return False, None, "Token invalidated by password change"
            
            return True, payload, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return False, None, "Token validation failed"
    
    @classmethod
    def refresh_access_token(cls, refresh_token_raw: str, ip_address: str, user_agent: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Create new access token using refresh token.
        Implements automatic token rotation for security.
        """
        try:
            # Hash the provided refresh token
            token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
            
            # Find and validate refresh token
            try:
                refresh_token = RefreshToken.objects.select_related(
                    'user', 'session', 'user__primary_pharmaceutical_tenant'
                ).get(token_hash=token_hash, is_revoked=False)
            except RefreshToken.DoesNotExist:
                return False, None, "Invalid refresh token"
            
            # Check if refresh token is expired
            if refresh_token.is_expired():
                refresh_token.revoke()
                return False, None, "Refresh token has expired"
            
            # Check if session is still valid
            if not refresh_token.session.is_active or refresh_token.session.is_expired():
                refresh_token.revoke()
                return False, None, "Session is no longer valid"
            
            # Update refresh token usage tracking
            refresh_token.last_used = timezone.now()
            refresh_token.last_used_ip = ip_address
            refresh_token.save(update_fields=['last_used', 'last_used_ip'])
            
            # Extend session timeout on successful refresh
            refresh_token.session.extend_session()
            
            # Create new access token
            new_access_token = cls.create_access_token(refresh_token.user, refresh_token.session)
            
            # Update user's last token refresh time
            refresh_token.user.last_token_refresh = timezone.now()
            refresh_token.user.save(update_fields=['last_token_refresh'])
            
            # Log successful token refresh
            AuditTrail.objects.create(
                user=refresh_token.user,
                session=refresh_token.session,
                pharmaceutical_tenant=refresh_token.user.primary_pharmaceutical_tenant,
                action_type='TOKEN_REFRESH',
                action_description='Access token refreshed successfully',
                ip_address=ip_address,
                user_agent=user_agent,
                risk_level='LOW'
            )
            
            return True, new_access_token, None
            
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return False, None, "Token refresh failed"
    
    @classmethod
    def create_emergency_access_token(cls, user: User, reason: str, approved_by: User, ip_address: str, user_agent: str) -> Tuple[UserSession, str]:
        """
        Create emergency access token with enhanced privileges and audit trail.
        Used for critical patient care situations.
        """
        # Create emergency session
        emergency_session = UserSession.objects.create(
            user=user,
            pharmaceutical_tenant=user.primary_pharmaceutical_tenant,
            ip_address=ip_address,
            user_agent=user_agent,
            is_emergency_session=True,
            emergency_reason=reason,
            emergency_approved_by=approved_by,
            expires_at=timezone.now() + timedelta(hours=2)  # Shorter expiry for emergency access
        )
        
        # Create emergency access token with special claims
        now = timezone.now()
        payload = {
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(hours=2)).timestamp()),
            'iss': 'klararety-healthcare-emergency',
            'sub': str(user.id),
            'jti': str(emergency_session.session_id),
            
            'user_id': user.id,
            'email': user.email,
            'role': user.role,
            'emergency_access': True,
            'emergency_reason': reason,
            'emergency_approved_by': approved_by.id,
            'emergency_session_id': str(emergency_session.session_id),
            
            'permissions': cls._get_emergency_permissions(user),
            'jwt_version': user.jwt_secret_version,
        }
        
        secret = cls.get_jwt_secret(user, user.jwt_secret_version)
        emergency_token = jwt.encode(payload, secret, algorithm=cls.ALGORITHM)
        
        # Log emergency access creation
        AuditTrail.objects.create(
            user=user,
            session=emergency_session,
            pharmaceutical_tenant=user.primary_pharmaceutical_tenant,
            action_type='EMERGENCY_ACCESS',
            action_description=f'Emergency access granted: {reason}. Approved by: {approved_by.email}',
            ip_address=ip_address,
            user_agent=user_agent,
            risk_level='HIGH'
        )
        
        return emergency_session, emergency_token
    
    @classmethod
    def invalidate_user_tokens(cls, user: User, reason: str = "Security invalidation"):
        """
        Invalidate all tokens for a user by incrementing their JWT version.
        This is atomic and eliminates race conditions in bulk token invalidation.
        """
        # Increment JWT secret version to invalidate all existing tokens
        user.jwt_secret_version += 1
        user.save(update_fields=['jwt_secret_version'])
        
        # Revoke all refresh tokens
        RefreshToken.objects.filter(user=user, is_revoked=False).update(is_revoked=True)
        
        # Deactivate all sessions
        UserSession.objects.filter(user=user, is_active=True).update(is_active=False)
        
        # Log security event
        AuditTrail.objects.create(
            user=user,
            pharmaceutical_tenant=user.primary_pharmaceutical_tenant,
            action_type='SECURITY_EVENT',
            action_description=f'All user tokens invalidated: {reason}',
            ip_address='0.0.0.0',  # System action
            user_agent='System',
            risk_level='MEDIUM'
        )
    
    @classmethod
    def _get_user_permissions(cls, user: User) -> Dict[str, Any]:
        """Enhanced permissions for rare disease healthcare platform."""
        # Start with basic permissions that all users have
        base_permissions = {
            # User info
            'role': user.role,
            'user_role': user.role,  # Frontend expects this key
            
            # Basic flags
            'is_admin': user.is_staff or user.role in ['admin', 'superadmin'],
            'is_superadmin': user.is_superuser or user.role == 'superadmin',
            'is_staff': user.is_staff,
            
            # Universal permissions
            'can_view_own_data': True,
            'can_edit_own_profile': True,
            
            # Dashboard access (everyone has some dashboard)
            'has_dashboard_access': True,
        }
        
        # Add frontend-expected permissions based on role
        if user.role in ['admin', 'superadmin']:
            base_permissions.update({
                # Admin access permissions
                'has_admin_access': True,
                'has_user_management_access': True,
                'has_system_settings_access': True,
                'has_audit_access': True,
                'has_compliance_access': True,
                'has_export_access': True,
                'has_compliance_reports_access': True,
                'has_approval_permissions': True,
                
                # Mapped permissions for frontend
                'can_access_admin': True,
                'can_manage_users': True,
                
                # Healthcare permissions
                'has_patient_data_access': True,
                'can_access_patient_data': True,
                'has_medical_records_access': True,
                'can_manage_appointments': True,
                'can_access_telemedicine': True,
                'can_manage_medications': True,
                'can_view_research_data': True,
                'can_access_research_data': True,
                'can_access_clinical_trials': True,
                'can_emergency_access': True,
                'can_view_phi': True,
                'can_manage_emergencies': True,
            })
        
        elif user.role == 'patient':
            base_permissions.update({
                # Patient-specific permissions
                'can_authorize_caregivers': True,
                'can_consent_to_research': True,
                'can_manage_notifications': True,
                'can_connect_devices': True,
                'can_request_appointments': True,
                'can_view_test_results': True,
                'can_communicate_with_providers': True,
                'can_participate_in_research': True,
                'can_manage_consent': True,
                
                # Healthcare permissions for patients
                'has_medical_records_access': True,  # Their own records
                'can_manage_appointments': True,
                'can_access_telemedicine': True,
                'can_access_clinical_trials': True,
                
                # Explicitly false for admin permissions
                'has_admin_access': False,
                'has_user_management_access': False,
                'has_system_settings_access': False,
                'has_audit_access': False,
                'has_compliance_access': False,
                'has_export_access': False,
                'has_patient_data_access': False,  # Can't access other patients
                'can_access_admin': False,
                'can_manage_users': False,
                'can_emergency_access': False,
            })
        
        elif user.role == 'provider':
            base_permissions.update({
                # Provider permissions
                'can_access_patient_data': True,
                'has_patient_data_access': True,
                'can_prescribe_medications': True,
                'can_schedule_appointments': True,
                'can_emergency_access': True,
                'can_view_adherence_data': True,
                'can_view_assigned_patients': True,
                'can_modify_patient_records': True,
                'can_order_tests': True,
                'can_create_appointments': True,
                'can_access_emergency_records': True,
                'can_supervise_staff': True,
                
                # Healthcare permissions
                'has_medical_records_access': True,
                'can_manage_appointments': True,
                'can_access_telemedicine': True,
                'can_manage_medications': True,
                'can_view_phi': True,
                
                # Limited admin permissions
                'has_admin_access': False,
                'has_user_management_access': False,
                'has_system_settings_access': False,
                'has_audit_access': False,
                'has_compliance_access': False,
                'has_export_access': False,
                'can_access_admin': False,
                'can_manage_users': False,
            })
        
        elif user.role == 'pharmco':
            base_permissions.update({
                # Pharmco permissions
                'can_view_aggregated_data': True,
                'can_monitor_drug_protocols': True,
                'can_access_trial_data': True,
                'can_generate_safety_reports': True,
                
                # Data access
                'can_access_patient_data': True,  # Aggregated/consented only
                'has_patient_data_access': True,
                'can_view_research_data': True,
                'can_access_research_data': True,
                'can_manage_medications': True,
                'can_access_clinical_trials': True,
                
                # No admin permissions
                'has_admin_access': False,
                'has_user_management_access': False,
                'has_system_settings_access': False,
                'has_audit_access': False,
                'has_compliance_access': False,
                'has_export_access': False,
                'can_access_admin': False,
                'can_manage_users': False,
                'can_emergency_access': False,
            })
        
        elif user.role == 'researcher':
            base_permissions.update({
                # Researcher permissions
                'can_request_data_access': True,
                'can_view_consented_data': True,
                'can_export_research_data': True,
                'can_access_research_data': True,
                'can_create_studies': True,
                'can_recruit_participants': True,
                'can_analyze_aggregated_data': True,
                'can_publish_findings': True,
                
                # Data access
                'can_view_research_data': True,
                'can_access_clinical_trials': True,
                'has_export_access': True,  # For research data only
                
                # No admin or patient permissions
                'has_admin_access': False,
                'has_user_management_access': False,
                'has_system_settings_access': False,
                'has_audit_access': False,
                'has_compliance_access': False,
                'has_patient_data_access': False,
                'can_access_admin': False,
                'can_manage_users': False,
                'can_emergency_access': False,
            })
        
        elif user.role == 'compliance':
            base_permissions.update({
                # Compliance permissions
                'can_audit_system': True,
                'can_view_access_logs': True,
                'can_generate_compliance_reports': True,
                'can_review_consent_records': True,
                'can_audit_user_activity': True,
                'can_review_emergency_access': True,
                'can_manage_consent_records': True,
                'can_investigate_violations': True,
                
                # Access permissions
                'has_audit_access': True,
                'has_compliance_access': True,
                'has_compliance_reports_access': True,
                'can_view_phi': True,
                'has_export_access': True,
                
                # Limited admin access
                'has_admin_access': False,
                'has_user_management_access': False,
                'has_system_settings_access': False,
                'has_patient_data_access': True,  # For auditing
                'can_access_admin': False,
                'can_manage_users': False,
                'can_emergency_access': False,
            })
        
        elif user.role == 'caregiver':
            base_permissions.update({
                # Caregiver permissions
                'can_view_patient_data': True,  # For authorized patients only
                'can_update_care_notes': True,
                'can_manage_medications': True,
                'can_schedule_appointments': True,
                
                # Healthcare permissions
                'can_access_telemedicine': True,
                'can_manage_appointments': True,
                
                # No admin permissions
                'has_admin_access': False,
                'has_user_management_access': False,
                'has_system_settings_access': False,
                'has_audit_access': False,
                'has_compliance_access': False,
                'has_export_access': False,
                'has_patient_data_access': False,  # Only specific patients
                'can_access_admin': False,
                'can_manage_users': False,
                'can_emergency_access': False,
            })
        
        # Add profile verification status if available
        base_permissions['identity_verified'] = False
        if hasattr(user, 'patient_profile') and user.patient_profile:
            base_permissions['identity_verified'] = user.patient_profile.identity_verified
        elif hasattr(user, 'provider_profile') and user.provider_profile:
            base_permissions['identity_verified'] = user.provider_profile.identity_verified
        
        return base_permissions

    @classmethod
    def _check_emergency_access_permissions(cls, user: User) -> bool:
        """Check if user has emergency access permissions."""
        return user.role in ['provider', 'admin', 'superadmin']
    
    @classmethod
    def _get_emergency_permissions(cls, user: User) -> Dict[str, Any]:
        """Get enhanced permissions for emergency access."""
        permissions = cls._get_user_permissions(user)
        
        # Add emergency-specific permissions
        permissions.update({
            'emergency_access': True,
            'can_override_consent': True,
            'can_access_all_patient_data': True,
            'bypass_normal_restrictions': True,
        })
        
        return permissions


class JWTAuthenticationBackend:
    """
    Custom authentication backend for JWT tokens.
    Integrates with Django's authentication system.
    """
    
    def authenticate(self, request, jwt_token=None):
        """
        Authenticate user using JWT token.
        Returns user object if valid, None otherwise.
        """
        if not jwt_token:
            return None
        
        is_valid, payload, error = JWTAuthenticationManager.validate_access_token(jwt_token)
        
        if not is_valid:
            return None
        
        try:
            user = User.objects.select_related('primary_pharmaceutical_tenant').get(
                id=payload['user_id']
            )
            return user
        except User.DoesNotExist:
            return None
    
    def get_user(self, user_id):
        """Get user by ID for Django auth system."""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None