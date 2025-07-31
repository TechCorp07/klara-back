# users/session_manager.py
# Distributed Session Management for Healthcare Platform
import json
import hashlib
from datetime import timedelta
from typing import Dict, Any, Optional, List, Tuple
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from django.contrib.auth import get_user_model
from cryptography.fernet import Fernet
import logging

from .models import UserSession, RefreshToken, PharmaceuticalTenant, AuditTrail

User = get_user_model()
logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages distributed user sessions with healthcare-specific context preservation.
    
    Think of this as a sophisticated coordinator that ensures all parts of your
    authentication system work together seamlessly, eliminating the race conditions
    that occur when multiple processes try to modify session state simultaneously.
    """
    
    # Session configuration for HIPAA compliance
    DEFAULT_SESSION_TIMEOUT = timedelta(minutes=20)  # HIPAA recommended timeout
    EMERGENCY_SESSION_TIMEOUT = timedelta(hours=2)   # Emergency access shorter timeout
    MAX_CONCURRENT_SESSIONS = 5                      # Prevent session abuse
    
    @classmethod
    def create_session(cls, user: User, ip_address: str, user_agent: str, 
                      pharmaceutical_tenant: Optional[PharmaceuticalTenant] = None,
                      is_emergency: bool = False, emergency_reason: str = None,
                      emergency_approved_by: User = None) -> UserSession:
        """
        Create a new user session with comprehensive context tracking.
        
        This method is atomic - either the entire session gets created successfully
        with all its components, or nothing gets created at all. This prevents the
        race conditions that occur when session creation gets interrupted midway.
        """
        with transaction.atomic():
            # Clean up any expired sessions first to prevent buildup
            cls._cleanup_expired_sessions(user)
            
            # Check session limits to prevent abuse
            active_sessions = UserSession.objects.filter(
                user=user, 
                is_active=True,
                expires_at__gt=timezone.now()
            ).count()
            
            if active_sessions >= cls.MAX_CONCURRENT_SESSIONS:
                # Deactivate oldest session to make room
                oldest_session = UserSession.objects.filter(
                    user=user, 
                    is_active=True,
                    is_emergency_session=False  # Never auto-remove emergency sessions
                ).order_by('last_activity').first()
                
                if oldest_session:
                    cls.terminate_session(oldest_session.session_id, reason="Session limit exceeded")
            
            # Determine session timeout based on type
            timeout = cls.EMERGENCY_SESSION_TIMEOUT if is_emergency else cls.DEFAULT_SESSION_TIMEOUT
            
            # Use primary tenant if not specified
            if not pharmaceutical_tenant and user.primary_pharmaceutical_tenant:
                pharmaceutical_tenant = user.primary_pharmaceutical_tenant
            
            # Create the session with all required context
            session = UserSession.objects.create(
                user=user,
                pharmaceutical_tenant=pharmaceutical_tenant,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=timezone.now() + timeout,
                is_emergency_session=is_emergency,
                emergency_reason=emergency_reason,
                emergency_approved_by=emergency_approved_by,
                device_fingerprint=cls._generate_device_fingerprint(user_agent, ip_address)
            )
            
            # Log session creation for audit trail
            AuditTrail.objects.create(
                user=user,
                session=session,
                pharmaceutical_tenant=pharmaceutical_tenant,
                action_type='LOGIN',
                action_description=f'New session created {"(EMERGENCY)" if is_emergency else ""}',
                ip_address=ip_address,
                user_agent=user_agent,
                risk_level='HIGH' if is_emergency else 'LOW'
            )
            
            logger.info(f"Session created for user {user.email}: {session.session_id}")
            return session
    
    @classmethod
    def get_active_session(cls, session_id: str) -> Optional[UserSession]:
        """
        Retrieve an active session by ID with validation.
        
        This method ensures that only valid, non-expired sessions are returned,
        preventing race conditions where expired sessions might be used briefly
        before cleanup processes remove them.
        """
        try:
            session = UserSession.objects.select_related(
                'user', 'pharmaceutical_tenant', 'emergency_approved_by'
            ).get(session_id=session_id, is_active=True)
            
            # Check if session has expired
            if session.is_expired():
                cls.terminate_session(session_id, reason="Session expired")
                return None
            
            return session
            
        except UserSession.DoesNotExist:
            return None
    
    @classmethod
    def extend_session(cls, session_id: str, activity_context: Optional[Dict] = None) -> bool:
        """
        Extend session timeout and update activity tracking.
        
        This is called whenever a user performs an action, ensuring their session
        stays active during legitimate use while still timing out appropriately
        during periods of inactivity.
        """
        try:
            with transaction.atomic():
                session = UserSession.objects.select_for_update().get(
                    session_id=session_id, 
                    is_active=True
                )
                
                # Don't extend if already expired
                if session.is_expired():
                    return False
                
                # Extend the session timeout
                timeout = cls.EMERGENCY_SESSION_TIMEOUT if session.is_emergency_session else cls.DEFAULT_SESSION_TIMEOUT
                session.expires_at = timezone.now() + timeout
                session.last_activity = timezone.now()
                session.save(update_fields=['expires_at', 'last_activity'])
                
                # Update activity context if provided
                if activity_context:
                    cls.update_session_context(session_id, activity_context)
                
                return True
                
        except UserSession.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Failed to extend session {session_id}: {str(e)}")
            return False
    
    @classmethod
    def update_session_context(cls, session_id: str, context_updates: Dict[str, Any]) -> bool:
        """
        Update session context while preserving clinical workflow state.
        
        This method ensures that when healthcare providers are working with patient
        data, their clinical context (current patient, open charts, active orders)
        is preserved across authentication events like token refreshes.
        """
        try:
            with transaction.atomic():
                session = UserSession.objects.select_for_update().get(
                    session_id=session_id, 
                    is_active=True
                )
                
                # Update different types of context
                if 'patient_context' in context_updates:
                    encrypted_context = session.encrypt_context(
                        context_updates['patient_context'], 
                        'patient'
                    )
                    session.patient_context = encrypted_context
                
                if 'clinical_context' in context_updates:
                    encrypted_context = session.encrypt_context(
                        context_updates['clinical_context'], 
                        'clinical'
                    )
                    session.clinical_context = encrypted_context
                
                if 'research_context' in context_updates:
                    encrypted_context = session.encrypt_context(
                        context_updates['research_context'], 
                        'research'
                    )
                    session.research_context = encrypted_context
                
                session.save()
                return True
                
        except UserSession.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Failed to update session context {session_id}: {str(e)}")
            return False
    
    @classmethod
    def get_session_context(cls, session_id: str) -> Dict[str, Any]:
        """
        Retrieve complete session context for workflow restoration.
        
        When a user's session refreshes or they switch between browser tabs,
        this method ensures they return to exactly where they were in their
        clinical or research workflow.
        """
        try:
            session = UserSession.objects.get(session_id=session_id, is_active=True)
            
            context = {
                'session_id': str(session.session_id),
                'user_id': session.user.id,
                'pharmaceutical_tenant_id': str(session.pharmaceutical_tenant.id) if session.pharmaceutical_tenant else None,
                'is_emergency_session': session.is_emergency_session,
                'emergency_reason': session.emergency_reason,
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'expires_at': session.expires_at.isoformat(),
            }
            
            # Decrypt and include sensitive context data
            if session.patient_context:
                context['patient_context'] = session.decrypt_context(session.patient_context)
            
            if session.clinical_context:
                context['clinical_context'] = session.decrypt_context(session.clinical_context)
            
            if session.research_context:
                context['research_context'] = session.decrypt_context(session.research_context)
            
            return context
            
        except UserSession.DoesNotExist:
            return {}
        except Exception as e:
            logger.error(f"Failed to get session context {session_id}: {str(e)}")
            return {}
    
    @classmethod
    def terminate_session(cls, session_id: str, reason: str = "User logout") -> bool:
        """
        Safely terminate a session and clean up all associated resources.
        
        This method ensures that when a session ends, all related tokens are
        invalidated and audit trails are properly recorded, preventing any
        leftover authentication artifacts that could cause security issues.
        """
        try:
            with transaction.atomic():
                session = UserSession.objects.select_for_update().get(
                    session_id=session_id
                )
                
                # Mark session as inactive
                session.is_active = False
                session.save(update_fields=['is_active'])
                
                # Revoke associated refresh token
                try:
                    refresh_token = RefreshToken.objects.get(session=session)
                    refresh_token.revoke()
                except RefreshToken.DoesNotExist:
                    pass  # Session might not have a refresh token yet
                
                # Log session termination
                AuditTrail.objects.create(
                    user=session.user,
                    session=session,
                    pharmaceutical_tenant=session.pharmaceutical_tenant,
                    action_type='LOGOUT',
                    action_description=f'Session terminated: {reason}',
                    ip_address=session.ip_address,
                    user_agent=session.user_agent,
                    risk_level='LOW'
                )
                
                logger.info(f"Session terminated for user {session.user.email}: {session_id} - {reason}")
                return True
                
        except UserSession.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Failed to terminate session {session_id}: {str(e)}")
            return False
    
    @classmethod
    def get_user_sessions(cls, user: User, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """
        Get all sessions for a user with detailed information.
        
        This is useful for user account management, allowing users to see
        all their active sessions and terminate suspicious ones.
        """
        filter_kwargs = {'user': user}
        if not include_inactive:
            filter_kwargs.update({
                'is_active': True,
                'expires_at__gt': timezone.now()
            })
        
        sessions = UserSession.objects.filter(**filter_kwargs).order_by('-last_activity')
        
        session_data = []
        for session in sessions:
            session_info = {
                'session_id': str(session.session_id),
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'expires_at': session.expires_at.isoformat(),
                'is_active': session.is_active,
                'is_emergency_session': session.is_emergency_session,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'device_fingerprint': session.device_fingerprint,
                'pharmaceutical_tenant': session.pharmaceutical_tenant.name if session.pharmaceutical_tenant else None,
                'is_expired': session.is_expired(),
            }
            
            if session.is_emergency_session:
                session_info.update({
                    'emergency_reason': session.emergency_reason,
                    'emergency_approved_by': session.emergency_approved_by.email if session.emergency_approved_by else None,
                })
            
            session_data.append(session_info)
        
        return session_data
    
    @classmethod
    def terminate_all_user_sessions(cls, user: User, reason: str = "Security action", exclude_session_id: str = None) -> int:
        """
        Terminate all sessions for a user except optionally one current session.
        
        This is used for security actions like password changes, where we want
        to force re-authentication on all devices except the one that initiated
        the security action.
        """
        # Build base queryset
        sessions_query = UserSession.objects.filter(user=user, is_active=True)
        
        if exclude_session_id:
            sessions_query = sessions_query.exclude(session_id=exclude_session_id)
        
        sessions = sessions_query.all()
        terminated_count = 0
        
        for session in sessions:
            if cls.terminate_session(str(session.session_id), reason):
                terminated_count += 1
        
        return terminated_count
    
    @classmethod
    def _cleanup_expired_sessions(cls, user: User = None):
        """
        Clean up expired sessions to prevent database bloat.
        
        This maintenance function runs automatically during session operations
        to keep the session table clean and performant.
        """
        filter_kwargs = {
            'is_active': True,
            'expires_at__lt': timezone.now()
        }
        
        if user:
            filter_kwargs['user'] = user
        
        expired_sessions = UserSession.objects.filter(**filter_kwargs)
        
        for session in expired_sessions:
            cls.terminate_session(str(session.session_id), reason="Session expired")
    
    @classmethod
    def _generate_device_fingerprint(cls, user_agent: str, ip_address: str) -> str:
        """
        Generate a device fingerprint for session tracking.
        
        This helps identify when the same device is being used for multiple
        sessions, which is useful for security analysis and session management.
        """
        # Create a hash of user agent and IP for basic device identification
        # In production, you might want more sophisticated fingerprinting
        fingerprint_data = f"{user_agent}:{ip_address}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()
    
    @classmethod
    def check_concurrent_session_limit(cls, user: User) -> Tuple[bool, int]:
        """
        Check if user has reached concurrent session limit.
        
        Returns (within_limit, current_count)
        """
        active_sessions = UserSession.objects.filter(
            user=user,
            is_active=True,
            expires_at__gt=timezone.now()
        ).count()
        
        return active_sessions < cls.MAX_CONCURRENT_SESSIONS, active_sessions
    
    @classmethod
    def get_session_analytics(cls, user: User, days: int = 30) -> Dict[str, Any]:
        """
        Get session analytics for security monitoring.
        
        Provides insights into user session patterns for security analysis
        and compliance reporting.
        """
        from django.db.models import Count, Avg
        from datetime import datetime, timedelta
        
        start_date = timezone.now() - timedelta(days=days)
        
        sessions = UserSession.objects.filter(
            user=user,
            created_at__gte=start_date
        )
        
        analytics = {
            'total_sessions': sessions.count(),
            'emergency_sessions': sessions.filter(is_emergency_session=True).count(),
            'unique_ips': sessions.values('ip_address').distinct().count(),
            'unique_devices': sessions.values('device_fingerprint').distinct().count(),
            'average_session_duration': sessions.aggregate(
                avg_duration=Avg('last_activity') - Avg('created_at')
            )['avg_duration'],
            'sessions_by_tenant': list(
                sessions.values('pharmaceutical_tenant__name')
                .annotate(count=Count('pharmaceutical_tenant'))
                .order_by('-count')
            ),
            'sessions_by_day': list(
                sessions.extra({'day': 'date(created_at)'})
                .values('day')
                .annotate(count=Count('session_id'))
                .order_by('day')
            ),
        }
        
        return analytics


class SessionMiddleware:
    """
    Middleware component for session management integration.
    
    This integrates the session manager with Django's request/response cycle,
    ensuring that session context is properly maintained throughout the
    application's operation.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process the request and maintain session context
        response = self.get_response(request)
        
        # Update session activity if user is authenticated
        if hasattr(request, 'user') and request.user.is_authenticated:
            if hasattr(request, 'session_id'):
                SessionManager.extend_session(request.session_id)
        
        return response