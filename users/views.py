# users/views.py
import hashlib
import pyotp
import qrcode
import io
import base64
import logging
from datetime import timedelta
from django.db import transaction
from django.db.models import Count, Q
from django.contrib.auth import authenticate
from django.utils import timezone
from django.conf import settings
from .jwt_auth import JWTAuthenticationManager
from .session_manager import SessionManager
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth.models import AnonymousUser
from rest_framework.pagination import PageNumberPagination
from wearables.models import WearableIntegration, WearableMeasurement          
from medication.models import AdherenceRecord

from .models import (
    AuditTrail, EmergencyAccess, ConsentRecord, HIPAADocument, PharmaceuticalTenant, RefreshToken, ResearchConsent, TwoFactorDevice, 
    PatientProfile, ProviderProfile, PharmcoProfile, CaregiverProfile, 
    ResearcherProfile, ComplianceProfile, CaregiverRequest, UserSession
)
from .serializers import (
    AuditTrailSerializer, PharmaceuticalTenantSerializer, ResearchConsentSerializer, UserSerializer, LoginSerializer, TwoFactorAuthSerializer,
    TwoFactorSetupSerializer, TwoFactorDisableSerializer,
    PatientProfileSerializer, ProviderProfileSerializer,
    PharmcoProfileSerializer, CaregiverProfileSerializer,
    ResearcherProfileSerializer, ComplianceProfileSerializer,
    ConsentRecordSerializer, CaregiverRequestSerializer,
    EmergencyAccessSerializer, HIPAADocumentSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    EmailVerificationConfirmSerializer,
    UserRegistrationSerializer, UserSessionListSerializer
)
from .permissions import (
    IsAdminOrSelfOnly, IsApprovedUser, IsRoleOwnerOrReadOnly, 
    IsComplianceOfficer
)
from .utils import EmailService, SecurityLogger

User = get_user_model()
logger = logging.getLogger(__name__)

class BaseViewSet(viewsets.ModelViewSet):
    """Base ViewSet with common utilities."""
    
    def get_client_ip(self, request):
        """Get client IP safely accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent from request."""
        return request.META.get('HTTP_USER_AGENT', '')
    
    def log_security_event(self, user, event_type, description, request):
        """Log security event."""
        SecurityLogger.log_event(
            user=user,
            event_type=event_type,
            description=description,
            ip_address=self.get_client_ip(request),
            user_agent=self.get_user_agent(request)
        )


class UserViewSet(BaseViewSet):
    """ViewSet for user management."""
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @action(detail=False, methods=['get'], permission_classes=[])  # No permissions for testing
    def debug_auth(self, request):
        """Debug authentication status."""
        
        # Access the underlying Django request to avoid DRF authentication
        django_request = request._request
        
        debug_info = {
            # DRF request info
            'drf_request_type': type(request).__name__,
            'has_jwt_payload': hasattr(request, 'jwt_payload'),
            'jwt_payload_user_id': request.jwt_payload.get('user_id') if hasattr(request, 'jwt_payload') else None,
            'session_id': getattr(request, 'session_id', None),
            
            # Django request info (what our middleware sets)
            'django_user_exists': hasattr(django_request, 'user'),
            'django_user_type': type(django_request.user).__name__ if hasattr(django_request, 'user') else None,
            'django_user_id': getattr(django_request.user, 'id', None) if hasattr(django_request, 'user') else None,
            'django_user_email': getattr(django_request.user, 'email', None) if hasattr(django_request, 'user') else None,
            'django_user_is_authenticated': getattr(django_request.user, 'is_authenticated', None) if hasattr(django_request, 'user') else None,
            'django_user_is_anonymous': getattr(django_request.user, 'is_anonymous', None) if hasattr(django_request, 'user') else None,
            'django_user_is_staff': getattr(django_request.user, 'is_staff', None) if hasattr(django_request, 'user') else None,
            'django_user_is_approved': getattr(django_request.user, 'is_approved', None) if hasattr(django_request, 'user') else None,
            'django_user_role': getattr(django_request.user, 'role', None) if hasattr(django_request, 'user') else None,
            'django_user_has_backend': hasattr(django_request.user, 'backend') if hasattr(django_request, 'user') else False,
            'django_user_backend': getattr(django_request.user, 'backend', None) if hasattr(django_request, 'user') else None,
            
            # JWT payload details (truncated for readability)
            'jwt_payload_keys': list(request.jwt_payload.keys()) if hasattr(request, 'jwt_payload') else None,
            
            # Authentication process
            'middleware_user_set': (hasattr(django_request, 'user') and 
                                django_request.user and 
                                type(django_request.user).__name__ != 'AnonymousUser'),
        }
        
        return Response(debug_info)

    def get_permissions(self):
        """Set permissions based on action."""
        permission_map = {
            # Public endpoints
            'create': [AllowAny],
            'login': [AllowAny],
            'verify_2fa': [AllowAny],
            'forgot_password': [AllowAny],
            'reset_password': [AllowAny],
            'verify_email': [AllowAny],
            'check_status': [AllowAny],
            
            # Authenticated user endpoints
            'retrieve': [IsAuthenticated, IsAdminOrSelfOnly, IsApprovedUser],
            'update': [IsAuthenticated, IsAdminOrSelfOnly, IsApprovedUser],
            'partial_update': [IsAuthenticated, IsAdminOrSelfOnly, IsApprovedUser],
            'me': [IsAuthenticated, IsApprovedUser],
            'setup_2fa': [IsAuthenticated, IsApprovedUser],
            'confirm_2fa': [IsAuthenticated, IsApprovedUser],
            'disable_2fa': [IsAuthenticated, IsApprovedUser],
            'request_email_verification': [IsAuthenticated],
            'permissions': [IsAuthenticated, IsApprovedUser],
            
            # Admin only endpoints
            'approve_user': [IsAuthenticated, permissions.IsAdminUser],
            'pending_approvals': [IsAuthenticated, permissions.IsAdminUser],
            'create_admin': [IsAuthenticated, permissions.IsAdminUser],
            
            # Default admin access
            'list': [IsAuthenticated, permissions.IsAdminUser],
            'destroy': [IsAuthenticated, permissions.IsAdminUser],
        }
        
        permission_classes = permission_map.get(self.action, [permissions.IsAdminUser])
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        """Use different serializers for different actions."""
        if self.action == 'create':
            return UserRegistrationSerializer
        return UserSerializer

    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=UserRegistrationSerializer,
        responses={201: UserSerializer}
    )
    def create(self, request, *args, **kwargs):
        """Register a new user with role-specific validation."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create user
        user = serializer.save()
        
        # Handle caregiver requests
        if user.role == 'caregiver':
            patient_email = serializer.validated_data.get('patient_email')
            try:
                patient = User.objects.get(email=patient_email, role='patient')
                CaregiverRequest.objects.create(
                    caregiver=user,
                    patient=patient,
                    relationship=serializer.validated_data.get('relationship_to_patient', '')
                )
                # Notify patient
                EmailService.send_caregiver_request_notification(patient, user)
            except User.DoesNotExist:
                # Patient doesn't exist yet - store email in profile
                pass
        
        # Log registration
        self.log_security_event(
            user=user,
            event_type="USER_REGISTRATION",
            description=f"New {user.get_role_display()} registration",
            request=request
        )
        
        # Notify admins of new registration
        if not user.is_staff:
            EmailService.send_admin_notification_new_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'message': 'Registration successful. Your account is pending administrator approval.'
        }, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'], permission_classes=[], authentication_classes=[])  # ✅ ADD BOTH OF THESE
    def refresh_token(self, request):
        """
        Refresh JWT access token using refresh token.
        No DRF authentication required since we handle refresh token validation manually.
        """
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response({
                'error': 'Refresh token required',
                'detail': 'Refresh token is required for token renewal'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get client information for security logging
        ip_address = self.get_client_ip(request)
        user_agent = self.get_user_agent(request)
        
        # Attempt to refresh the token using the refresh token manager
        success, new_access_token, error_message = JWTAuthenticationManager.refresh_access_token(
            refresh_token, ip_address, user_agent
        )
        
        if not success:
            return Response({
                'error': 'Token refresh failed',
                'detail': error_message or 'Unable to refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Get user info from the new token for response
        try:
            import jwt
            unverified_payload = jwt.decode(new_access_token, options={"verify_signature": False})
            user_id = unverified_payload.get('user_id')
            
            if user_id:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                user = User.objects.get(id=user_id)
                user_data = UserSerializer(user).data
            else:
                user_data = None
                
        except Exception as e:
            user_data = None
        
        # Return new token with user data
        response_data = {
            'access_token': new_access_token,
            'token_type': 'Bearer', 
            'expires_in': 15 * 60,  # 15 minutes
        }
        
        # Include user data if available
        if user_data:
            response_data['user'] = user_data
        
        # Include tab_id if provided
        tab_id = request.data.get('tab_id')
        if tab_id:
            response_data['tab_id'] = tab_id
        
        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], permission_classes=[], authentication_classes=[])
    def refresh_session(self, request):
        """Refresh session token - simpler than JWT refresh."""
        session_token = request.data.get('session_token')
        
        if not session_token:
            return Response({'error': 'Session token required'}, status=400)
        
        success, new_token = SessionManager.refresh_session_token(session_token)
        
        if not success:
            return Response({'error': 'Invalid or expired session'}, status=401)
        
        return Response({
            'session_token': new_token,
            'expires_in': 60 * 60,  # 1 hour
            'token_type': 'Session'
        })
        
    @action(detail=False, methods=['get'])
    def session_health(self, request):
        """
        Check session health and return current session context.
        
        This endpoint allows the frontend to verify session status
        and retrieve current session context without race conditions.
        """
        if not hasattr(request, 'session_id') or not request.session_id:
            return Response({
                'detail': 'No active session found.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        session_context = SessionManager.get_session_context(request.session_id)
        
        if not session_context:
            return Response({
                'detail': 'Session not found or expired.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            'session': session_context,
            'user': UserSerializer(request.user).data,
            'permissions': JWTAuthenticationManager._get_user_permissions(request.user),
        })
    
    @swagger_auto_schema(
        method='post',
        operation_description="Login user",
        request_body=LoginSerializer
    )
    @action(detail=False, methods=['post'])
    def login(self, request):
        """
        Enhanced login with JWT token generation and session management.
        
        This new login method eliminates race conditions by creating
        authentication state atomically - either everything succeeds
        together, or everything fails together.
        """
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Get client information for session tracking
        ip_address = self.get_client_ip(request)
        user_agent = self.get_user_agent(request)
        
        # Authenticate user credentials
        user = authenticate(username=username, password=password)
        
        if not user:
            # Log failed login attempt
            self.log_security_event(
                user=None,
                event_type="LOGIN_FAILED",
                description=f"Failed login attempt for username: {username}",
                request=request
            )
            
            # Check for account lockout if user exists
            try:
                existing_user = User.objects.get(username=username)
                existing_user.failed_login_attempts += 1
                
                # Lock account after too many failures
                if existing_user.failed_login_attempts >= 5:
                    existing_user.account_locked_until = timezone.now() + timedelta(minutes=30)
                    existing_user.save(update_fields=['failed_login_attempts', 'account_locked_until'])
                    
                    return Response({
                        'detail': 'Account temporarily locked due to too many failed attempts.'
                    }, status=status.HTTP_423_LOCKED)
                
                existing_user.save(update_fields=['failed_login_attempts'])
                
            except User.DoesNotExist:
                pass  # Username doesn't exist
            
            return Response({
                'detail': 'Invalid username or password.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check account status
        if not user.is_active:
            return Response({
                'detail': 'Account is disabled.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_approved:
            return Response({
                'detail': 'Account is pending approval.',
                'requires_approval': True,
                'submitted_at': user.date_joined.isoformat(),
                'role': user.role,
                'message': f'Your {user.get_role_display()} account is being reviewed by administrators.'
            }, status=status.HTTP_403_FORBIDDEN)

        # Check account lockout
        if user.account_locked_until and timezone.now() < user.account_locked_until:
            return Response({
                'detail': 'Account is temporarily locked.'
            }, status=status.HTTP_423_LOCKED)
        
        # Reset failed login attempts on successful login
        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            user.save(update_fields=['failed_login_attempts'])
        
        # Create session atomically - this is the key to eliminating race conditions
        with transaction.atomic():
            # Create distributed session
            session = SessionManager.create_session(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                pharmaceutical_tenant=user.primary_pharmaceutical_tenant
            )
            
            # Generate JWT access token
            access_token = JWTAuthenticationManager.create_access_token(user, session)
            
            # Generate refresh token
            refresh_token = JWTAuthenticationManager.create_refresh_token(
                user, session, ip_address
            )
            # Generate session token - ADD DEBUG HERE
            print(f"🔍 BACKEND: Creating session token for session {session.session_id}")
            session_token = SessionManager.create_session_token(session, duration_hours=1)
            print(f"🔍 BACKEND: Session token created: {session_token[:20]}..." if session_token else "❌ BACKEND: Session token creation failed")
            
            # Update user login tracking
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
        
        # Build response with comprehensive user context
        user_serializer = UserSerializer(user)
        
        response_data = {
            'access_token': access_token,
            'refresh_token': refresh_token._raw_token,  # Raw token for client storage
            'token_type': 'Bearer',
            'expires_in': JWTAuthenticationManager.ACCESS_TOKEN_LIFETIME.total_seconds(),
            
            # Add session token info
            'session_token': session_token,
            'session_expires_in': 60 * 60,  # 1 hour

            'user': user_serializer.data,
            'session': {
                'session_id': str(session.session_id),
                'expires_at': session.expires_at.isoformat(),
                'pharmaceutical_tenant': session.pharmaceutical_tenant.name if session.pharmaceutical_tenant else None,
            },
            'permissions': JWTAuthenticationManager._get_user_permissions(user),
        }
        # ADD DEBUG FOR RESPONSE DATA
        print(f"🔍 BACKEND: Response includes session_token: {bool(response_data.get('session_token'))}")
        print(f"🔍 BACKEND: Response keys: {list(response_data.keys())}")
        print(f"🔍 BACKEND: Session token in response: {response_data.get('session_token', 'MISSING')[:20]}..." if response_data.get('session_token') else "❌ BACKEND: No session_token in response")
        
        # Add verification warnings if needed
        if hasattr(user, 'patient_profile') and user.patient_profile:
            if not user.patient_profile.identity_verified:
                days_remaining = user.patient_profile.days_until_verification_required() or 30
                if days_remaining <= 7:
                    response_data['verification_warning'] = {
                        'days_remaining': days_remaining,
                        'message': f'Identity verification required within {days_remaining} days.'
                    }
        
        # Log successful login
        self.log_security_event(
            user=user,
            event_type="LOGIN_SUCCESS",
            description="User login successful",
            request=request
        )
        
        return Response(response_data)

    @action(detail=False, methods=['post'])
    def logout(self, request):
        """
        Enhanced logout with comprehensive session cleanup.
        
        This ensures that when a user logs out, all authentication
        artifacts are properly cleaned up to prevent security issues.
        """
        # Extract session ID from JWT token
        session_id = None
        if hasattr(request, 'session_id'):
            session_id = request.session_id
        
        # If no session ID available, try to get it from the JWT payload
        if not session_id and hasattr(request, 'jwt_payload'):
            session_id = request.jwt_payload.get('session_id')
        
        if session_id:
            # Terminate the session cleanly
            SessionManager.terminate_session(session_id, reason="User logout")
        
        # Log logout event
        if hasattr(request, 'user') and request.user.is_authenticated:
            self.log_security_event(
                user=request.user,
                event_type="LOGOUT",
                description="User logout",
                request=request
            )
        
        return Response({'detail': 'Successfully logged out.'})

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        """
        Get current user information with pharmaceutical tenant context.
        
        Enhanced to include session context and pharmaceutical tenant information
        for the new multi-tenant architecture.
        """
        user = request.user
        serializer = UserSerializer(user)
        user_data = serializer.data
        
        # Add role-specific profile
        profile_map = {
            'patient': ('patient_profile', PatientProfileSerializer),
            'provider': ('provider_profile', ProviderProfileSerializer),
            'pharmco': ('pharmco_profile', PharmcoProfileSerializer),
            'caregiver': ('caregiver_profile', CaregiverProfileSerializer),
            'researcher': ('researcher_profile', ResearcherProfileSerializer),
            'compliance': ('compliance_profile', ComplianceProfileSerializer),
        }
        
        user_data['pharmaceutical_context'] = {
            'primary_tenant': user.primary_pharmaceutical_tenant.name if user.primary_pharmaceutical_tenant else None,
            'available_tenants': [
                {
                    'id': str(tenant.id),
                    'name': tenant.name,
                    'slug': tenant.slug,
                    } for tenant in user.pharmaceutical_tenants.all()
                ],
            }
        
        if user.role in profile_map:
            profile_attr, profile_serializer = profile_map[user.role]
            if hasattr(user, profile_attr):
                profile = getattr(user, profile_attr)
                user_data['profile'] = profile_serializer(profile).data
        
        # Add pending caregiver requests for patients
        if user.role == 'patient':
            pending_requests = CaregiverRequest.objects.filter(
                patient=user,
                status='PENDING'
            )
            if pending_requests.exists():
                user_data['pending_caregiver_requests'] = CaregiverRequestSerializer(
                    pending_requests, many=True
                ).data
        
        if hasattr(request, 'session_id') and request.session_id:
            session_context = SessionManager.get_session_context(request.session_id)
            user_data['session_context'] = session_context
        
        # ⭐ Include permissions directly in user data
        user_data['permissions'] = JWTAuthenticationManager._get_user_permissions(user)
        
        return Response(user_data)

    @action(detail=False, methods=['post'])
    def emergency_access(self, request):
        """
        Grant emergency access for critical patient care situations.
        
        This creates a special emergency session with enhanced privileges
        and comprehensive audit logging.
        """
        # Verify user has emergency access permissions
        if not JWTAuthenticationManager._check_emergency_access_permissions(request.user):
            return Response({
                'detail': 'Emergency access not authorized for this user.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        reason = request.data.get('reason')
        if not reason:
            return Response({
                'detail': 'Emergency reason is required.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # For now, auto-approve. In production, you might require approval workflow
        approved_by = request.user  # or get from approval system
        
        # Create emergency session and token
        emergency_session, emergency_token = JWTAuthenticationManager.create_emergency_access_token(
            user=request.user,
            reason=reason,
            approved_by=approved_by,
            ip_address=self.get_client_ip(request),
            user_agent=self.get_user_agent(request)
        )
        
        return Response({
            'emergency_token': emergency_token,
            'session_id': str(emergency_session.session_id),
            'expires_at': emergency_session.expires_at.isoformat(),
            'reason': reason,
            'message': 'Emergency access granted. This session will be closely monitored.',
        })

    @action(detail=False, methods=['post'])
    def switch_tenant(self, request):
        """
        Switch active pharmaceutical tenant context.
        
        Allows users with multi-tenant access to switch between
        pharmaceutical companies they're authorized to access.
        """
        tenant_id = request.data.get('tenant_id')
        
        if not tenant_id:
            return Response({
                'detail': 'Tenant ID is required.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify user has access to this tenant
        if not request.user.pharmaceutical_tenants.filter(id=tenant_id).exists():
            return Response({
                'detail': 'Access to this pharmaceutical tenant is not authorized.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update user's primary tenant
        try:
            new_tenant = PharmaceuticalTenant.objects.get(id=tenant_id)
            request.user.primary_pharmaceutical_tenant = new_tenant
            request.user.save(update_fields=['primary_pharmaceutical_tenant'])
            
            # Log tenant switch for audit trail
            self.log_security_event(
                user=request.user,
                event_type="TENANT_SWITCH",
                description=f"Switched to pharmaceutical tenant: {new_tenant.name}",
                request=request
            )
            
            return Response({
                'detail': f'Switched to {new_tenant.name}',
                'tenant': {
                    'id': str(new_tenant.id),
                    'name': new_tenant.name,
                    'slug': new_tenant.slug,
                }
            })
            
        except PharmaceuticalTenant.DoesNotExist:
            return Response({
                'detail': 'Pharmaceutical tenant not found.'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'])
    def pending_approvals(self, request):
        """Get list of users pending approval (admin only)."""
        pending_users = User.objects.filter(
            is_approved=False,
            is_staff=False
        ).exclude(role='admin')
        
        serializer = self.get_serializer(pending_users, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def approve_user(self, request, pk=None):
        """Approve a user and create their profile."""
        user = self.get_object()
        
        if user.is_approved:
            return Response({
                'detail': 'User is already approved'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Approve user (this creates profile)
        user.approve_user(request.user)
        
        # Send approval email
        EmailService.send_approval_email(user)
        
        self.log_security_event(
            user=request.user,
            event_type="USER_APPROVED",
            description=f"Approved user: {user.email}",
            request=request
        )
        
        return Response({
            'detail': 'User approved successfully',
            'user': UserSerializer(user).data
        })

    @action(detail=False, methods=['post'])
    def create_admin(self, request):
        """Create admin user (superuser only)."""
        if not request.user.is_superuser:
            return Response({
                'detail': 'Only superusers can create admin accounts'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Required fields for admin creation
        required_fields = ['email', 'first_name', 'last_name', 'password']
        for field in required_fields:
            if not request.data.get(field):
                return Response({
                    'detail': f'{field} is required'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Create admin user
            admin_data = {
                'email': request.data['email'],
                'first_name': request.data['first_name'],
                'last_name': request.data['last_name'],
                'phone_number': request.data.get('phone_number', ''),
                'role': 'admin',
                'is_staff': True,
                'is_approved': True,
                'email_verified': True,  # Skip email verification for admins
                'terms_accepted': True,
                'hipaa_privacy_acknowledged': True,
            }
            
            admin_user = User(**admin_data)
            admin_user.set_password(request.data['password'])
            admin_user.password_last_changed = timezone.now()
            admin_user.approved_by = request.user
            admin_user.approved_at = timezone.now()
            admin_user.save()
            
            # Create admin profile (basic user profile, no specific admin profile model needed)
            admin_user.profile_created = True
            admin_user.save()
            
            # Send credentials
            EmailService.send_admin_credentials(admin_user, request.data['password'])
            
            self.log_security_event(
                user=request.user,
                event_type="ADMIN_CREATED",
                description=f"Created admin user: {admin_user.email}",
                request=request
            )
            
            return Response({
                'detail': 'Admin user created successfully',
                'user': UserSerializer(admin_user).data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'detail': f'Failed to create admin user: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    @action(detail=False, methods=['get'])
    def check_status(self, request):
        """Check user account status without authentication."""
        email = request.query_params.get('email')
        if not email:
            return Response({
                'detail': 'Email parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            
            status_data = {
                'exists': True,
                'is_approved': user.is_approved,
                'email_verified': user.email_verified,
                'role': user.role,
                'account_locked': user.account_locked,
            }
            
            # Add specific status messages
            if not user.is_approved:
                status_data['message'] = 'Account pending administrator approval'
            elif not user.email_verified:
                status_data['message'] = 'Email verification required'
            elif user.account_locked:
                status_data['message'] = 'Account locked due to security reasons'
            else:
                status_data['message'] = 'Account active'
            
            return Response(status_data)
            
        except User.DoesNotExist:
            return Response({
                'exists': False,
                'message': 'No account found with this email'
            })

    @action(detail=False, methods=['post'])
    def verify_email(self, request):
        """Verify email address with token."""
        serializer = EmailVerificationConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        
        try:
            user = User.objects.get(
                email_verification_token=token,
                email_verification_sent_at__gt=timezone.now() - timezone.timedelta(days=7)
            )
            
            user.verify_email()
            
            self.log_security_event(
                user=user,
                event_type="EMAIL_VERIFIED",
                description="Email address verified",
                request=request
            )
            
            return Response({
                'detail': 'Email verified successfully',
                'user': UserSerializer(user).data
            })
            
        except User.DoesNotExist:
            return Response({
                'detail': 'Invalid or expired verification token'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def request_email_verification(self, request):
        """Request new email verification token."""
        if not request.user.is_authenticated:
            return Response({
                'detail': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        user = request.user
        
        if user.email_verified:
            return Response({
                'detail': 'Email is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate new token
        token = user.generate_email_verification_token()
        
        # Send verification email
        EmailService.send_email_verification_email(user, token)
        
        return Response({
            'detail': 'Verification email sent'
        })

    @action(detail=False, methods=['post'])
    def confirm_2fa(self, request):
        """Confirm 2FA setup."""
        serializer = TwoFactorSetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        
        try:
            device = TwoFactorDevice.objects.get(user=user, confirmed=False)
        except TwoFactorDevice.DoesNotExist:
            return Response({
                'detail': '2FA setup not initiated'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify the token
        totp = pyotp.TOTP(device.secret_key)
        if not totp.verify(serializer.validated_data['token']):
            return Response({
                'detail': 'Invalid verification code'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Confirm the device
        device.confirmed = True
        device.save()
        
        # Enable 2FA for user
        user.two_factor_enabled = True
        user.save()
        
        self.log_security_event(
            user=user,
            event_type="2FA_ENABLED",
            description="Two-factor authentication enabled",
            request=request
        )
        
        return Response({
            'detail': '2FA enabled successfully'
        })

    @action(detail=False, methods=['post'])
    def disable_2fa(self, request):
        """Disable 2FA for authenticated user."""
        serializer = TwoFactorDisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        
        # Verify password
        if not user.check_password(serializer.validated_data['password']):
            return Response({
                'detail': 'Invalid password'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Disable 2FA
        user.two_factor_enabled = False
        user.save()
        
        # Delete 2FA device
        TwoFactorDevice.objects.filter(user=user).delete()
        
        self.log_security_event(
            user=user,
            event_type="2FA_DISABLED", 
            description="Two-factor authentication disabled",
            request=request
        )
        
        return Response({
            'detail': '2FA disabled successfully'
        })

    @action(detail=False, methods=['post'])
    def verify_2fa(self, request):
        """Enhanced 2FA verification with JWT token management."""
        serializer = TwoFactorAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = User.objects.get(id=serializer.validated_data['user_id'])
            device = TwoFactorDevice.objects.get(user=user)
        except (User.DoesNotExist, TwoFactorDevice.DoesNotExist):
            return Response({
                'detail': 'Invalid user or 2FA not set up'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(device.secret_key)
        if not totp.verify(serializer.validated_data['token']):
            self.log_security_event(
                user=user,
                event_type="2FA_FAILURE",
                description="Invalid 2FA code",
                request=request
            )
            return Response({
                'detail': 'Invalid verification code'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        device.last_used_at = timezone.now()
        device.save()
        
        with transaction.atomic():
            # Create JWT session and tokens
            session = SessionManager.create_session(
                user=user,
                ip_address=self.get_client_ip(request),
                user_agent=self.get_user_agent(request),
                pharmaceutical_tenant=user.primary_pharmaceutical_tenant
            )
            
            # Generate JWT access token
            access_token = JWTAuthenticationManager.create_access_token(user, session)
            
            # Generate refresh token
            refresh_token = JWTAuthenticationManager.create_refresh_token(
                user, session, self.get_client_ip(request)
            )
        
        self.log_security_event(
            user=user,
            event_type="2FA_SUCCESS",
            description="Successful 2FA verification",
            request=request
        )
        
        return Response({
            'access_token': access_token,
            'refresh_token': refresh_token._raw_token,
            'token_type': 'Bearer',
            'expires_in': JWTAuthenticationManager.ACCESS_TOKEN_LIFETIME.total_seconds(),
            'user': UserSerializer(user).data,
            'session': {
                'session_id': str(session.session_id),
                'expires_at': session.expires_at.isoformat(),
            }
        })

    @action(detail=False, methods=['post'])
    def setup_2fa(self, request):
        """Setup 2FA for authenticated user."""
        user = request.user
        
        # Generate or get existing device
        device, created = TwoFactorDevice.objects.get_or_create(
            user=user,
            defaults={'secret_key': pyotp.random_base32()}
        )
        
        if not created and device.confirmed:
            return Response({
                'detail': '2FA is already set up'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(device.secret_key).provisioning_uri(
            name=user.email,
            issuer_name='Klararety Health'
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        
        return Response({
            'qr_code': f'data:image/png;base64,{qr_code}',
            'secret_key': device.secret_key
        })

    @action(detail=False, methods=['post'])
    def forgot_password(self, request):
        """Request password reset."""
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = user.generate_password_reset_token()
            EmailService.send_password_reset_email(user, token)
            
            self.log_security_event(
                user=user,
                event_type="PASSWORD_RESET_REQUEST",
                description="Password reset requested",
                request=request
            )
        except User.DoesNotExist:
            pass  # Don't reveal if email exists
        
        return Response({
            'detail': 'If your email is registered, you will receive a reset link.'
        })

    @action(detail=False, methods=['post'])
    def reset_password(self, request):
        """Reset password with token."""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        password = serializer.validated_data['password']
        
        try:
            user = User.objects.get(
                reset_password_token=token,
                reset_password_token_created_at__gt=timezone.now() - timezone.timedelta(hours=24)
            )
            
            user.set_password(password)
            user.password_last_changed = timezone.now()
            user.clear_password_reset_token()
            user.save()
            
            self.log_security_event(
                user=user,
                event_type="PASSWORD_RESET_SUCCESS",
                description="Password reset completed",
                request=request
            )
            
            return Response({'detail': 'Password reset successfully.'})
            
        except User.DoesNotExist:
            return Response({
                'detail': 'Invalid or expired token.'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def dashboard_stats(self, request):
        """Get dashboard statistics for admins."""
        if not (request.user.is_staff or request.user.role == 'admin'):
            return Response({
                'detail': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        stats = {
            'total_users': User.objects.count(),
            'pending_approvals': User.objects.filter(
                is_approved=False,
                is_staff=False
            ).exclude(role='admin').count(),
            'users_by_role': dict(
                User.objects.values('role').annotate(count=Count('role')).values_list('role', 'count')
            ),
            'pending_caregiver_requests': CaregiverRequest.objects.filter(status='PENDING').count(),
            'unreviewed_emergency_access': EmergencyAccess.objects.filter(reviewed=False).count(),
            'recent_registrations': User.objects.filter(
                date_joined__gte=timezone.now() - timezone.timedelta(days=7)
            ).count(),
            'unverified_patients': PatientProfile.objects.filter(
                identity_verified=False,
                first_login_date__isnull=False
            ).count(),
        }
        
        return Response(stats)

    @action(detail=False, methods=['post'])
    def bulk_approve(self, request):
        """Bulk approve users."""
        if not (request.user.is_staff or request.user.role == 'admin'):
            return Response({
                'detail': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        user_ids = request.data.get('user_ids', [])
        if not user_ids:
            return Response({
                'detail': 'No user IDs provided'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        users = User.objects.filter(
            id__in=user_ids,
            is_approved=False,
            is_staff=False
        ).exclude(role='admin')
        
        approved_count = 0
        errors = []
        
        for user in users:
            try:
                user.approve_user(request.user)
                EmailService.send_approval_email(user)
                approved_count += 1
            except Exception as e:
                errors.append(f"Failed to approve {user.email}: {str(e)}")
        
        response_data = {
            'approved_count': approved_count,
            'total_requested': len(user_ids)
        }
        
        if errors:
            response_data['errors'] = errors
        
        return Response(response_data)

    @action(detail=False, methods=['post'])
    def bulk_deny(self, request):
        """Bulk deny users."""
        if not (request.user.is_staff or request.user.role == 'admin'):
            return Response({
                'detail': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        user_ids = request.data.get('user_ids', [])
        reason = request.data.get('reason', 'Application denied by administrator')
        
        if not user_ids:
            return Response({
                'detail': 'No user IDs provided'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        users = User.objects.filter(
            id__in=user_ids,
            is_approved=False,
            is_staff=False
        ).exclude(role='admin')
        
        denied_count = 0
        for user in users:
            # Send denial email
            EmailService.send_denial_email(user, reason)
            # Delete the user account
            user.delete()
            denied_count += 1
        
        return Response({
            'denied_count': denied_count,
            'total_requested': len(user_ids)
        })

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def list_user_sessions(self, request):
        """
        List active sessions for the authenticated user.
        
        Industry standard implementation following:
        - REST API best practices
        - Security standards for session management
        - Django/DRF conventions
        - Pagination and filtering support
        """
        
        # Base queryset - only active sessions for the authenticated user
        queryset = UserSession.objects.filter(
            user=request.user,
            is_active=True,
            expires_at__gt=timezone.now()
        ).select_related('user', 'pharmaceutical_tenant').order_by('-last_activity')
        
        # Optional filtering
        include_inactive = request.query_params.get('include_inactive', 'false').lower() == 'true'
        if include_inactive:
            queryset = UserSession.objects.filter(user=request.user).order_by('-last_activity')
        
        # Apply pagination (industry standard)
        paginator = self.pagination_class()
        paginated_sessions = paginator.paginate_queryset(queryset, request)
        
        # Serialize with context
        serializer = UserSessionListSerializer(
            paginated_sessions, 
            many=True, 
            context={
                'request': request,
                'current_session_id': getattr(request, 'session_id', None)
            }
        )
        
        # Industry standard response format
        response_data = {
            'results': serializer.data,
            'count': paginator.page.paginator.count,
            'next': paginator.get_next_link(),
            'previous': paginator.get_previous_link(),
            'current_session_id': getattr(request, 'session_id', None),
            'active_sessions_count': UserSession.objects.filter(
                user=request.user,
                is_active=True,
                expires_at__gt=timezone.now()
            ).count()
        }
        
        return Response(response_data)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def terminate_session(self, request):
        """
        Terminate a specific session by ID.
        Industry standard session management endpoint.
        """
        session_id = request.data.get('session_id')
        
        if not session_id:
            return Response({
                'error': 'session_id is required',
                'code': 'MISSING_SESSION_ID'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Verify session belongs to user (security best practice)
            session = UserSession.objects.get(
                session_id=session_id,
                user=request.user,
                is_active=True
            )
            
            # Use session manager for proper cleanup
            success = SessionManager.terminate_session(
                session_id, 
                reason="Terminated by user via API"
            )
            
            if success:
                # Log security event
                self.log_security_event(
                    user=request.user,
                    event_type="SESSION_TERMINATED",
                    description=f"User terminated session {session_id}",
                    request=request
                )
                
                return Response({
                    'message': 'Session terminated successfully',
                    'session_id': session_id
                })
            else:
                return Response({
                    'error': 'Failed to terminate session',
                    'code': 'TERMINATION_FAILED'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except UserSession.DoesNotExist:
            return Response({
                'error': 'Session not found or access denied',
                'code': 'SESSION_NOT_FOUND'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def terminate_all_sessions(self, request):
        """
        Terminate all other sessions except current one.
        Industry standard security feature.
        """
        exclude_current = request.data.get('exclude_current', True)
        reason = request.data.get('reason', 'Terminated all sessions via API')
        
        current_session_id = getattr(request, 'session_id', None) if exclude_current else None
        
        # Get count before termination
        sessions_to_terminate = UserSession.objects.filter(
            user=request.user,
            is_active=True
        )
        
        if current_session_id:
            sessions_to_terminate = sessions_to_terminate.exclude(session_id=current_session_id)
        
        terminated_count = sessions_to_terminate.count()
        
        # Terminate sessions using session manager
        actual_terminated = SessionManager.terminate_all_user_sessions(
            user=request.user,
            reason=reason,
            exclude_session_id=current_session_id
        )
        
        # Log security event
        self.log_security_event(
            user=request.user,
            event_type="ALL_SESSIONS_TERMINATED",
            description=f"User terminated {actual_terminated} sessions",
            request=request
        )
        
        return Response({
            'message': f'Terminated {actual_terminated} sessions',
            'terminated_count': actual_terminated,
            'current_session_preserved': exclude_current and current_session_id is not None
        })

    @action(detail=False, methods=['get'])
    def list_tenants(self, request):
        """
        List pharmaceutical tenants available to the current user.
        """
        tenants = request.user.pharmaceutical_tenants.filter(is_active=True)
        serializer = PharmaceuticalTenantSerializer(tenants, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def security_invalidate_tokens(self, request):
        """
        Security action to invalidate all tokens for the current user.
        Used for password changes or security incidents.
        """
        reason = request.data.get('reason', 'Security action by user')
        
        # Invalidate all tokens except current session if specified
        exclude_current = request.data.get('exclude_current_session', True)
        current_session_id = request.session_id if hasattr(request, 'session_id') else None
        
        if exclude_current and current_session_id:
            # Terminate all other sessions
            terminated_count = SessionManager.terminate_all_user_sessions(
                request.user, 
                reason=reason, 
                exclude_session_id=current_session_id
            )
        else:
            # Invalidate all tokens including current session
            JWTAuthenticationManager.invalidate_user_tokens(request.user, reason)
            terminated_count = SessionManager.terminate_all_user_sessions(request.user, reason)
        
        return Response({
            'detail': f'All authentication tokens invalidated. {terminated_count} sessions terminated.',
            'terminated_sessions': terminated_count
        })

    @action(detail=False, methods=['get', 'post'])
    def list_research_consents(self, request):
        """
        List or create research consents for the current user.
        """
        if request.method == 'GET':
            consents = ResearchConsent.objects.filter(user=request.user)
            
            # Filter by pharmaceutical tenant if specified
            tenant_id = request.query_params.get('tenant_id')
            if tenant_id:
                consents = consents.filter(pharmaceutical_tenant_id=tenant_id)
            
            serializer = ResearchConsentSerializer(consents, many=True)
            return Response(serializer.data)
        
        elif request.method == 'POST':
            # Create new research consent
            serializer = ResearchConsentSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            # Automatically set user and pharmaceutical tenant
            serializer.save(
                user=request.user,
                pharmaceutical_tenant=request.user.primary_pharmaceutical_tenant
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def grant_research_consent(self, request):
        """
        Grant consent for specific research activities.
        """
        consent_data = request.data
        
        # Validate required fields
        required_fields = ['study_identifier', 'consent_type']
        for field in required_fields:
            if field not in consent_data:
                return Response({
                    'detail': f'{field} is required.'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create or update consent record
        consent, created = ResearchConsent.objects.update_or_create(
            user=request.user,
            pharmaceutical_tenant=request.user.primary_pharmaceutical_tenant,
            study_identifier=consent_data['study_identifier'],
            consent_type=consent_data['consent_type'],
            defaults={
                'consented': True,
                'consent_date': timezone.now(),
                'consent_version': consent_data.get('consent_version', '1.0'),
                'consent_document_url': consent_data.get('consent_document_url'),
            }
        )
        
        # Log consent action
        self.log_security_event(
            user=request.user,
            event_type="CONSENT_GRANTED",
            description=f"Research consent granted for {consent_data['consent_type']} in study {consent_data['study_identifier']}",
            request=request
        )
        
        serializer = ResearchConsentSerializer(consent)
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        
        return Response(serializer.data, status=status_code)

    @action(detail=False, methods=['patch'])
    def update_research_consent(self, request, consent_id):
        """
        Update an existing research consent.
        """
        try:
            consent = ResearchConsent.objects.get(
                id=consent_id, 
                user=request.user
            )
        except ResearchConsent.DoesNotExist:
            return Response({
                'detail': 'Research consent not found.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ResearchConsentSerializer(consent, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response(serializer.data)

    @action(detail=False, methods=['delete'])
    def withdraw_research_consent(self, request, consent_id):
        """
        Withdraw research consent.
        """
        try:
            consent = ResearchConsent.objects.get(
                id=consent_id, 
                user=request.user
            )
        except ResearchConsent.DoesNotExist:
            return Response({
                'detail': 'Research consent not found.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Mark as withdrawn
        consent.withdrawn = True
        consent.withdrawal_date = timezone.now()
        consent.withdrawal_reason = request.data.get('reason', 'Withdrawn by user')
        consent.save()
        
        # Log withdrawal
        self.log_security_event(
            user=request.user,
            event_type="CONSENT_WITHDRAWN",
            description=f"Research consent withdrawn for {consent.consent_type} in study {consent.study_identifier}",
            request=request
        )
        
        return Response({'detail': 'Research consent withdrawn successfully.'})

    @action(detail=False, methods=['get'])
    def list_audit_trails(self, request):
        """
        List audit trails for compliance reporting.
        Restricted to compliance officers and admins.
        """
        if request.user.role not in ['admin', 'superadmin', 'compliance']:
            return Response({
                'detail': 'Insufficient permissions for audit access.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Filter audit trails
        audit_trails = AuditTrail.objects.all().order_by('-timestamp')
        
        # Apply filters
        user_id = request.query_params.get('user_id')
        if user_id:
            audit_trails = audit_trails.filter(user_id=user_id)
        
        action_type = request.query_params.get('action_type')
        if action_type:
            audit_trails = audit_trails.filter(action_type=action_type)
        
        tenant_id = request.query_params.get('tenant_id')
        if tenant_id:
            audit_trails = audit_trails.filter(pharmaceutical_tenant_id=tenant_id)
        
        risk_level = request.query_params.get('risk_level')
        if risk_level:
            audit_trails = audit_trails.filter(risk_level=risk_level)
        
        # Date range filtering
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        if start_date:
            audit_trails = audit_trails.filter(timestamp__gte=start_date)
        if end_date:
            audit_trails = audit_trails.filter(timestamp__lte=end_date)
        
        # Paginate results
        paginator = PageNumberPagination()
        paginated_trails = paginator.paginate_queryset(audit_trails, request)
        
        serializer = AuditTrailSerializer(paginated_trails, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=False, methods=['get'])
    def compliance_report(self, request):
        """
        Generate comprehensive compliance report.
        For pharmaceutical research compliance requirements.
        """
        if request.user.role not in ['admin', 'superadmin', 'compliance']:
            return Response({
                'detail': 'Compliance officer access required.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get report parameters
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Generate comprehensive compliance metrics
        report = {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': timezone.now().isoformat(),
                'days': days
            },
            'authentication_metrics': {
                'total_logins': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='LOGIN'
                ).count(),
                'failed_logins': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='LOGIN',
                    response_status__in=['401', '403']
                ).count(),
                'emergency_access_events': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='EMERGENCY_ACCESS'
                ).count(),
            },
            'data_access_metrics': {
                'patient_data_access': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='PATIENT_ACCESS'
                ).count(),
                'research_data_access': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='RESEARCH_DATA_ACCESS'
                ).count(),
                'cross_tenant_access': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='CROSS_TENANT_ACCESS'
                ).count(),
            },
            'consent_metrics': {
                'consents_granted': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='CONSENT_GRANTED'
                ).count(),
                'consents_withdrawn': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='CONSENT_WITHDRAWN'
                ).count(),
            },
            'security_metrics': {
                'high_risk_events': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    risk_level='HIGH'
                ).count(),
                'critical_risk_events': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    risk_level='CRITICAL'
                ).count(),
                'security_violations': AuditTrail.objects.filter(
                    timestamp__gte=start_date,
                    action_type='SECURITY_EVENT'
                ).count(),
            },
            'pharmaceutical_tenant_activity': list(
                AuditTrail.objects.filter(timestamp__gte=start_date)
                .values('pharmaceutical_tenant__name')
                .annotate(activity_count=Count('id'))
                .order_by('-activity_count')
            ),
        }
        
        return Response(report)

    @action(detail=False, methods=['get'])
    def security_events(self, request):
        """
        List security events for monitoring dashboard.
        """
        if request.user.role not in ['admin', 'superadmin', 'compliance']:
            return Response({
                'detail': 'Security monitoring access required.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get recent security events
        security_events = AuditTrail.objects.filter(
            action_type__in=['SECURITY_EVENT', 'LOGIN_FAILED', 'EMERGENCY_ACCESS'],
            risk_level__in=['HIGH', 'CRITICAL']
        ).order_by('-timestamp')[:100]
        
        serializer = AuditTrailSerializer(security_events, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def request_phone_verification(self, request):
        """Request phone number verification via SMS."""
        if not request.user.is_authenticated:
            return Response({
                'detail': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        user = request.user
        phone_number = request.data.get('phone_number')
        
        if not phone_number:
            return Response({
                'detail': 'Phone number is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate verification code
        import random
        verification_code = str(random.randint(100000, 999999))
        
        # Store code temporarily (you might want to use cache or temporary model)
        # For now, we'll assume you have a way to store this
        
        # Send SMS (integrate with your SMS provider)
        # SMSService.send_verification_code(phone_number, verification_code)
        
        return Response({
            'detail': 'Verification code sent to your phone',
            'phone_number': phone_number  # Maybe mask this for security
        })

    @action(detail=False, methods=['post'])
    def verify_phone(self, request):
        """Verify phone number with verification code."""
        if not request.user.is_authenticated:
            return Response({
                'detail': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        user = request.user
        verification_code = request.data.get('verification_code')
        phone_number = request.data.get('phone_number')
        
        if not verification_code or not phone_number:
            return Response({
                'detail': 'Verification code and phone number are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify the code (implement your verification logic)
        # if not verify_code_matches(phone_number, verification_code):
        #     return Response({'detail': 'Invalid verification code'}, status=400)
        
        # Update user's phone number and mark as verified
        user.phone_number = phone_number
        # You might want to add a phone_verified field to your User model
        user.save()
        
        return Response({
            'detail': 'Phone number verified successfully',
            'phone_number': phone_number
        })

    @action(detail=True, methods=['post'])
    def reactivate_user(self, request, pk=None):
        """Reactivate a deactivated user account."""
        if not (request.user.is_staff or request.user.role == 'admin'):
            return Response({'detail': 'Admin access required'}, status=403)
        
        user = self.get_object()
        user.is_active = True
        user.account_locked = False
        user.account_locked_time = None
        user.save()
        
        return Response({'detail': 'User account reactivated'})


class PatientProfileViewSet(BaseViewSet):
    """ViewSet for patient profiles."""
    queryset = PatientProfile.objects.all()
    serializer_class = PatientProfileSerializer
    permission_classes = [IsAuthenticated, IsRoleOwnerOrReadOnly]
    
    def get_queryset(self):
            # Fix for Swagger schema generation
            if getattr(self, 'swagger_fake_view', False):
                return PatientProfile.objects.none()
            
            user = self.request.user
            
            # Check if user is authenticated and has role attribute
            if not user.is_authenticated or not hasattr(user, 'role'):
                return PatientProfile.objects.none()
            
            if user.role == 'patient':
                return PatientProfile.objects.filter(user=user)
            elif user.role == 'provider' or user.is_staff:
                return PatientProfile.objects.all()
            elif user.role == 'caregiver':
                return PatientProfile.objects.filter(
                    caregiver_authorizations__caregiver=user
                )
            elif user.role == 'pharmco':
                return PatientProfile.objects.filter(
                    medication_adherence_monitoring_consent=True
                )
            elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if user.researcher_profile.is_verified:
                    return PatientProfile.objects.filter(
                        research_participation_consent=True
                    )
            elif user.role == 'compliance':
                return PatientProfile.objects.all()
            
            return PatientProfile.objects.none()

    @action(detail=True, methods=['post'])
    def verify_identity(self, request, pk=None):
        """Verify patient identity (provider/admin only)."""
        if request.user.role not in ['provider', 'admin']:
            return Response({
                'detail': 'Only providers and admins can verify identity'
            }, status=status.HTTP_403_FORBIDDEN)
        
        profile = self.get_object()
        profile.verify_identity(method='PROVIDER_VERIFICATION')
        
        self.log_security_event(
            user=request.user,
            event_type="IDENTITY_VERIFIED",
            description=f"Verified identity for patient: {profile.user.email}",
            request=request
        )
        
        return Response({'detail': 'Identity verified successfully'})

    @action(detail=True, methods=['post'])
    def update_consent(self, request, pk=None):
        """Update patient consent preferences."""
        profile = self.get_object()
        
        # Ensure user can only update their own consent
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own consent preferences'
            }, status=status.HTTP_403_FORBIDDEN)
        
        consent_fields = [
            'medication_adherence_monitoring_consent',
            'vitals_monitoring_consent',
            'research_participation_consent'
        ]
        
        for field in consent_fields:
            if field in request.data:
                old_value = getattr(profile, field)
                new_value = request.data[field]
                
                if old_value != new_value:
                    setattr(profile, field, new_value)
                    setattr(profile, f"{field.replace('_consent', '')}_date", timezone.now())
                    
                    # Create consent record
                    consent_type_map = {
                        'medication_adherence_monitoring_consent': 'MEDICATION_MONITORING',
                        'vitals_monitoring_consent': 'VITALS_MONITORING',
                        'research_participation_consent': 'RESEARCH_PARTICIPATION'
                    }
                    
                    ConsentRecord.objects.create(
                        user=request.user,
                        consent_type=consent_type_map[field],
                        consented=new_value,
                        signature_ip=self.get_client_ip(request),
                        signature_user_agent=self.get_user_agent(request)
                    )
        
        profile.save()
        
        return Response({
            'detail': 'Consent preferences updated',
            'profile': PatientProfileSerializer(profile).data
        })
    
    @action(detail=True, methods=['post'])
    def complete_profile(self, request, pk=None):
        """Complete patient profile with additional information."""
        profile = self.get_object()
        
        # Ensure user can only update their own profile
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update profile fields
        allowed_fields = [
            'medical_id', 'blood_type', 'allergies',
            'emergency_contact_name', 'emergency_contact_phone', 
            'emergency_contact_relationship', 'primary_condition',
            'condition_diagnosis_date'
        ]
        
        for field in allowed_fields:
            if field in request.data:
                setattr(profile, field, request.data[field])
        
        profile.save()
        
        return Response({
            'detail': 'Profile updated successfully',
            'profile': PatientProfileSerializer(profile).data
        })
    
    @action(detail=True, methods=['post'])
    def initiate_verification(self, request, pk=None):
        """Initiate identity verification process."""
        profile = self.get_object()
        
        if profile.user != request.user:
            return Response({
                'detail': 'You can only initiate verification for your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        if profile.identity_verified:
            return Response({
                'detail': 'Identity is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        from .utils import IdentityVerificationManager
        
        method = request.data.get('method', 'E_SIGNATURE')
        success = IdentityVerificationManager.initiate_verification(request.user, method)
        
        if success:
            return Response({
                'detail': 'Identity verification initiated',
                'method': method
            })
        else:
            return Response({
                'detail': 'Failed to initiate verification'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def complete_verification(self, request, pk=None):
        """Complete identity verification process."""
        profile = self.get_object()
        
        if profile.user != request.user:
            return Response({
                'detail': 'You can only complete verification for your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        if profile.identity_verified:
            return Response({
                'detail': 'Identity is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        from .utils import IdentityVerificationManager
        
        method = request.data.get('method', 'E_SIGNATURE')
        success = IdentityVerificationManager.complete_verification(request.user, method)
        
        if success:
            return Response({
                'detail': 'Identity verification completed',
                'verified_at': profile.identity_verification_date
            })
        else:
            return Response({
                'detail': 'Failed to complete verification'
            }, status=status.HTTP_400_BAD_REQUEST)


class CaregiverRequestViewSet(BaseViewSet):
    """ViewSet for caregiver-patient relationship requests."""
    queryset = CaregiverRequest.objects.all()
    serializer_class = CaregiverRequestSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Fix for Swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return CaregiverRequest.objects.none()
        
        user = self.request.user
        
        # Check if user is authenticated and has role attribute
        if not user.is_authenticated or not hasattr(user, 'role'):
            return CaregiverRequest.objects.none()
        
        if user.role == 'patient':
            return CaregiverRequest.objects.filter(patient=user)
        elif user.role == 'caregiver':
            return CaregiverRequest.objects.filter(caregiver=user)
        elif user.is_staff:
            return CaregiverRequest.objects.all()
        
        return CaregiverRequest.objects.none()

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve caregiver request (patient only)."""
        caregiver_request = self.get_object()
        
        if request.user != caregiver_request.patient:
            return Response({
                'detail': 'Only the patient can approve this request'
            }, status=status.HTTP_403_FORBIDDEN)
        
        caregiver_request.approve()
        
        # Create consent record
        ConsentRecord.objects.create(
            user=request.user,
            consent_type='CAREGIVER_ACCESS',
            consented=True,
            signature_ip=self.get_client_ip(request),
            signature_user_agent=self.get_user_agent(request)
        )
        
        # Notify caregiver
        EmailService.send_caregiver_approval(caregiver_request.caregiver, request.user)
        
        return Response({'detail': 'Caregiver request approved'})

    @action(detail=True, methods=['post'])
    def deny(self, request, pk=None):
        """Deny caregiver request (patient only)."""
        caregiver_request = self.get_object()
        
        if request.user != caregiver_request.patient:
            return Response({
                'detail': 'Only the patient can deny this request'
            }, status=status.HTTP_403_FORBIDDEN)
        
        reason = request.data.get('reason', '')
        caregiver_request.deny(reason)
        
        # Notify caregiver
        EmailService.send_caregiver_denial(caregiver_request.caregiver, request.user, reason)
        
        return Response({'detail': 'Caregiver request denied'})


class EmergencyAccessViewSet(BaseViewSet):
    """ViewSet for emergency PHI access."""
    queryset = EmergencyAccess.objects.all()
    serializer_class = EmergencyAccessSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Fix for Swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return EmergencyAccess.objects.none()
        
        user = self.request.user
        
        # Check if user is authenticated and has role attribute
        if not user.is_authenticated or not hasattr(user, 'role'):
            return EmergencyAccess.objects.none()
        
        if user.is_staff or user.role in ['admin', 'compliance']:
            return EmergencyAccess.objects.all()
        elif user.role == 'provider':
            return EmergencyAccess.objects.filter(requester=user)
        
        return EmergencyAccess.objects.none()

    @action(detail=False, methods=['post'])
    def initiate(self, request):
        """Initiate emergency access."""
        if request.user.role not in ['provider', 'admin', 'compliance']:
            return Response({
                'detail': 'Only authorized personnel can initiate emergency access'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        emergency_access = serializer.save(
            requester=request.user,
            ip_address=self.get_client_ip(request),
            user_agent=self.get_user_agent(request)
        )
        
        # Send notifications
        EmailService.send_emergency_access_notification(emergency_access)
        
        self.log_security_event(
            user=request.user,
            event_type="EMERGENCY_ACCESS_INITIATED",
            description=f"Emergency access initiated: {emergency_access.reason}",
            request=request
        )
        
        return Response({
            'detail': 'Emergency access initiated',
            'access_id': emergency_access.id,
            'expires_in': '4 hours'
        })

    @action(detail=True, methods=['post'])
    def end_access(self, request, pk=None):
        """End emergency access."""
        emergency_access = self.get_object()
        
        if request.user != emergency_access.requester:
            return Response({
                'detail': 'Only the requester can end access'
            }, status=status.HTTP_403_FORBIDDEN)
        
        phi_summary = request.data.get('phi_accessed', '')
        emergency_access.end_access(phi_summary)
        
        self.log_security_event(
            user=request.user,
            event_type="EMERGENCY_ACCESS_ENDED",
            description=f"Emergency access ended",
            request=request
        )
        
        return Response({'detail': 'Emergency access ended'})

    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        """Review emergency access (compliance only)."""
        if request.user.role not in ['admin', 'compliance']:
            return Response({
                'detail': 'Only compliance officers can review emergency access'
            }, status=status.HTTP_403_FORBIDDEN)
        
        emergency_access = self.get_object()
        notes = request.data.get('notes', '')
        justified = request.data.get('justified')
        
        if justified is None:
            return Response({
                'detail': 'Please indicate if access was justified'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        emergency_access.review(request.user, notes, justified)
        
        return Response({'detail': 'Review completed'})
    
    @action(detail=False, methods=['get'])
    def compliance_summary(self, request):
        """Get compliance summary for emergency access."""
        if request.user.role not in ['admin', 'compliance']:
            return Response({
                'detail': 'Compliance officer access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        summary = {
            'total_requests': EmergencyAccess.objects.count(),
            'pending_review': EmergencyAccess.objects.filter(reviewed=False).count(),
            'recent_requests': EmergencyAccess.objects.filter(
                requested_at__gte=thirty_days_ago
            ).count(),
            'justified_access': EmergencyAccess.objects.filter(
                access_justified=True
            ).count(),
            'unjustified_access': EmergencyAccess.objects.filter(
                access_justified=False
            ).count(),
            'by_reason': dict(
                EmergencyAccess.objects.values('reason').annotate(
                    count=Count('reason')
                ).values_list('reason', 'count')
            ),
            'active_sessions': EmergencyAccess.objects.filter(
                access_ended_at__isnull=True
            ).count(),
        }
        
        return Response(summary)


class HIPAADocumentViewSet(BaseViewSet):
    """ViewSet for HIPAA compliance documents."""
    queryset = HIPAADocument.objects.all()
    serializer_class = HIPAADocumentSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'get_latest', 'sign']:
            return [IsAuthenticated()]
        return [IsAuthenticated(), permissions.IsAdminUser()]
    
    def get_queryset(self):
        if self.request.user.is_staff:
            return HIPAADocument.objects.all()
        return HIPAADocument.objects.filter(active=True)

    @action(detail=False, methods=['get'])
    def get_latest(self, request):
        """Get latest version of each document type."""
        latest_docs = []
        
        for doc_type, _ in HIPAADocument.DOCUMENT_TYPES:
            try:
                doc = HIPAADocument.objects.filter(
                    document_type=doc_type,
                    active=True
                ).latest('effective_date')
                latest_docs.append(doc)
            except HIPAADocument.DoesNotExist:
                pass
        
        serializer = self.get_serializer(latest_docs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def sign(self, request, pk=None):
        """E-sign a document."""
        document = self.get_object()
        
        # Check if already signed
        existing = ConsentRecord.objects.filter(
            user=request.user,
            consent_type=f'DOC_{document.document_type}',
            document_version=document.version,
            revoked=False
        ).first()
        
        if existing:
            return Response({
                'detail': 'You have already signed this document'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create consent record
        consent = ConsentRecord.objects.create(
            user=request.user,
            consent_type=f'DOC_{document.document_type}',
            consented=True,
            document_version=document.version,
            document_checksum=document.checksum,
            signature_ip=self.get_client_ip(request),
            signature_user_agent=self.get_user_agent(request)
        )
        
        # Update user acknowledgment flags
        if document.document_type == 'PRIVACY_NOTICE':
            request.user.hipaa_privacy_acknowledged = True
            request.user.hipaa_privacy_acknowledged_at = timezone.now()
        elif document.document_type == 'TERMS_OF_SERVICE':
            request.user.terms_accepted = True
        
        request.user.save()
        
        return Response({
            'detail': 'Document signed successfully',
            'consent_id': consent.id,
            'signed_at': consent.signature_timestamp
        })

class PatientViewSet(viewsets.ModelViewSet):
    """ViewSet for patient-specific operations."""

    @action(detail=False, methods=['get'], url_path='dashboard')
    def dashboard(self, request):
        """
        Enhanced patient dashboard endpoint with comprehensive rare disease monitoring.
        Returns structured data matching frontend interface requirements.
        """
        try:
            user = request.user
            
            # Get or create patient profile
            patient_profile, created = PatientProfile.objects.get_or_create(
                user=user,
                defaults={
                    'medical_record_number': f"MRN-{user.id:06d}",
                    'emergency_contact_name': '',
                    'emergency_contact_phone': '',
                    'emergency_contact_relationship': ''
                }
            )
            
            # Get or create medical record
            from healthcare.models import MedicalRecord
            medical_record = None
            try:
                medical_record = MedicalRecord.objects.filter(patient=user).first()
            except:
                pass
            
            # Build patient info matching frontend expectations
            patient_info = {
                "name": user.get_full_name() or user.username,
                "has_rare_condition": medical_record.has_rare_condition if medical_record else False,
                "verification_status": "verified" if patient_profile.identity_verified else "unverified",
                "days_until_verification": patient_profile.days_until_verification_required() or 30
            }
            
            # Add rare condition info if exists
            if medical_record and medical_record.has_rare_condition:
                rare_conditions = []
                try:
                    from healthcare.models import Condition
                    conditions = Condition.objects.filter(
                        medical_record=medical_record,
                        is_rare_condition=True,
                        status='active'
                    )
                    for condition in conditions:
                        rare_conditions.append({
                            "name": condition.name,
                            "diagnosed_date": condition.diagnosed_date.isoformat() if condition.diagnosed_date else None,
                            "severity": "moderate"  # You can add actual severity logic
                        })
                except:
                    pass
                
                if rare_conditions:
                    patient_info["rare_condition"] = rare_conditions[0]["name"]  # For backward compatibility
                    patient_info["rare_conditions"] = rare_conditions
            
            # Get alerts
            alerts = []
            
            # Add verification alert if needed
            if not patient_profile.identity_verified:
                days_until = patient_profile.days_until_verification_required() or 30
                if days_until <= 7:
                    alerts.append({
                        "id": 1,
                        "severity": "critical" if days_until <= 3 else "warning",
                        "message": f"Identity verification required within {days_until} days",
                        "type": "verification",
                        "acknowledged": False,
                        "created_at": timezone.now().isoformat()
                    })
            
            # Add medication adherence alerts
            try:
                from medication.models import Medication, AdherenceRecord
                active_meds = Medication.objects.filter(patient=user, active=True)
                
                for med in active_meds:
                    # Check recent adherence
                    recent_adherence = AdherenceRecord.objects.filter(
                        medication=med,
                        period_end__gte=timezone.now().date() - timedelta(days=7)
                    ).first()
                    
                    if recent_adherence and recent_adherence.adherence_rate < 80:
                        alerts.append({
                            "id": 100 + med.id,
                            "severity": "warning",
                            "message": f"Low adherence for {med.name}: {recent_adherence.adherence_rate}%",
                            "type": "medication",
                            "acknowledged": False,
                            "created_at": timezone.now().isoformat()
                        })
            except:
                pass
            
            # Get appointments
            appointments = []
            try:
                from telemedicine.models import Appointment
                upcoming_appointments = Appointment.objects.filter(
                    patient=user,
                    scheduled_time__gte=timezone.now(),
                    status__in=['scheduled', 'confirmed']
                ).order_by('scheduled_time')[:5]
                
                for apt in upcoming_appointments:
                    appointments.append({
                        "id": apt.id,
                        "provider": apt.provider.get_full_name() if apt.provider else "Unknown",
                        "date": apt.scheduled_time.date().isoformat(),
                        "time": apt.scheduled_time.time().isoformat(),
                        "type": apt.appointment_type,
                        "status": apt.status
                    })
            except:
                pass
            
            # Get medications data
            medications = {
                "active_medications": [],
                "total_medications": 0,
                "adherence_rate": 0,
                "next_dose": None
            }
            
            try:
                from medication.models import Medication, MedicationIntake
                active_meds = Medication.objects.filter(patient=user, active=True)
                medications["total_medications"] = active_meds.count()
                
                # Calculate overall adherence
                total_adherence = 0
                adherence_count = 0
                
                for med in active_meds:
                    med_data = {
                        "id": med.id,
                        "name": med.name,
                        "dosage": med.dosage,
                        "frequency": med.frequency,
                        "for_rare_condition": med.for_rare_condition
                    }
                    
                    # Get recent adherence
                    recent_adherence = AdherenceRecord.objects.filter(
                        medication=med,
                        period_end__gte=timezone.now().date() - timedelta(days=30)
                    ).first()
                    
                    if recent_adherence:
                        med_data["adherence_rate"] = recent_adherence.adherence_rate
                        total_adherence += recent_adherence.adherence_rate
                        adherence_count += 1
                    
                    medications["active_medications"].append(med_data)
                
                if adherence_count > 0:
                    medications["adherence_rate"] = round(total_adherence / adherence_count, 1)
                
                # Get next dose
                next_intake = MedicationIntake.objects.filter(
                    patient=user,
                    scheduled_time__gte=timezone.now(),
                    status='pending'
                ).order_by('scheduled_time').first()
                
                if next_intake:
                    medications["next_dose"] = {
                        "medication": next_intake.medication.name,
                        "time": next_intake.scheduled_time.isoformat()
                    }
            except:
                pass

            # Get vitals
            vitals = []
            try:
                from healthcare.models import VitalSign
                if medical_record:
                    recent_vitals = VitalSign.objects.filter(
                        medical_record=medical_record
                    ).order_by('-measured_at')[:10]
                    
                    for vital in recent_vitals:
                        vitals.append({
                            "type": vital.measurement_type,
                            "value": vital.value,
                            "unit": vital.unit,
                            "measured_at": vital.measured_at.isoformat(),
                            "is_abnormal": vital.is_abnormal,
                            "source": vital.source
                        })
            except:
                pass

            # Get care team
            care_team = []
            try:
                # Primary physician
                if medical_record and medical_record.primary_physician:
                    care_team.append({
                        "id": medical_record.primary_physician.id,
                        "name": medical_record.primary_physician.get_full_name(),
                        "role": "Primary Physician",
                        "specialty": getattr(medical_record.primary_physician.provider_profile, 'specialty', 'General Practice') if hasattr(medical_record.primary_physician, 'provider_profile') else 'General Practice'
                    })
                
                # Authorized caregivers
                from users.models import PatientAuthorizedCaregiver
                authorized_caregivers = PatientAuthorizedCaregiver.objects.filter(
                    patient=patient_profile,
                    is_active=True
                )
                
                for auth_caregiver in authorized_caregivers:
                    care_team.append({
                        "id": auth_caregiver.caregiver.id,
                        "name": auth_caregiver.caregiver.get_full_name(),
                        "role": "Caregiver",
                        "relationship": auth_caregiver.relationship
                    })
            except:
                pass
            
            # Get research participation
            research_participation = []
            try:
                from users.models import ResearchConsent
                # Get active research consents
                research_consents = ResearchConsent.objects.filter(
                    user=user,
                    consented=True,
                    withdrawn=False
                ).select_related('pharmaceutical_tenant')
                
                for consent in research_consents:
                    research_participation.append({
                        "study_id": str(consent.id),
                        "study_name": f"{consent.consent_type.replace('_', ' ').title()} - {consent.study_identifier}",
                        "enrolled_date": consent.consent_date.isoformat() if consent.consent_date else None,
                        "status": "active" if not consent.withdrawn else "withdrawn",
                        "pharmaceutical_company": consent.pharmaceutical_tenant.name if consent.pharmaceutical_tenant else None
                    })
            except Exception as e:
                logger.error(f"Error getting research participation: {str(e)}")
                pass

            # Get community groups (chat groups)
            community_groups = []
            # TODO: Implement when chat/community system is added

            # Build final response matching frontend expectations
            dashboard_data = {
                "patient_info": patient_info,
                "health_summary": {  # Changed from just returning alerts
                    "overall_status": "good",  # Calculate based on conditions
                    "last_checkup": appointments[0]["scheduled_datetime"] if appointments else None,
                    "next_appointment": appointments[0]["scheduled_datetime"] if appointments else None,
                    "identity_verified": patient_info.get("verification_status") == "verified",
                    "days_until_verification_required": patient_info.get("days_until_verification", 30)
                },
                "medications": medications,
                "vitals": {
                    "current": vitals[-1] if vitals else {},  # Latest vitals
                    "trends": {
                        "improving": [],
                        "stable": [],
                        "concerning": []
                    },
                    "last_recorded": vitals[-1]["recorded_at"] if vitals else None
                },
                "wearable_data": {
                    "connected_devices": [],
                    "recent_data": {},
                    "sync_status": "disconnected"
                },
                "appointments": appointments,
                "care_team": care_team,
                "research_participation": research_participation,
                "community_groups": community_groups,
                "alerts": alerts,
                "quick_actions": [
                    {
                        "id": "log_medication",
                        "title": "Log Medication",
                        "description": "Record medication taken",
                        "icon": "pill",
                        "href": "/patient/medications/log",
                        "priority": "high"
                    },
                    {
                        "id": "record_vitals", 
                        "title": "Record Vitals",
                        "description": "Log vital signs",
                        "icon": "heart",
                        "href": "/patient/vitals/record", 
                        "priority": "medium"
                    }
                ]
            }

            return Response(dashboard_data)

        except Exception as e:
            logger.error(f"Error generating patient dashboard for user {request.user.id}: {str(e)}")
            
            # Return minimal valid response structure
            return Response({
                "patient_info": {
                    "name": request.user.get_full_name() or request.user.username,
                    "has_rare_condition": False,
                    "verification_status": "unverified",
                    "days_until_verification": 30
                },
                "alerts": [],
                "appointments": [],
                "medications": {
                    "active_medications": [],
                    "total_medications": 0,
                    "adherence_rate": 0,
                    "next_dose": None
                },
                "vitals": [],
                "care_team": [],
                "research_participation": [],
                "community_groups": []
            })

    def _get_medication_data(self, user):
        """Get comprehensive medication adherence data."""
        try:
            from healthcare.models import Medication
            # Get active medications
            medications_queryset = Medication.objects.filter(
                medical_record__patient=user,
                active=True,
            ).select_related(
            'prescriber',
            'medical_record',
            'created_by'
            )
            
            medications_list = []
            overall_adherence = 0
            missed_today = 0
            
            for med in medications_queryset[:10]:  # Limit to prevent performance issues
                adherence_records = AdherenceRecord.objects.filter(
                    medication=med,
                    date_taken__gte=timezone.now().date() - timedelta(days=30)
                )
                
                expected_doses = 30 * (med.doses_per_day or 1)
                actual_doses = adherence_records.filter(taken=True).count()
                adherence_rate = (actual_doses / expected_doses * 100) if expected_doses > 0 else 0
                
                # Check missed doses today
                today_expected = med.doses_per_day or 1
                today_taken = adherence_records.filter(
                    date_taken=timezone.now().date(),
                    taken=True
                ).count()
                missed_today += max(0, today_expected - today_taken)
                
                medications_list.append({
                    "id": med.id,
                    "name": med.name,
                    "dosage": f"{med.dosage} {med.dosage_unit}",
                    "frequency": med.frequency,
                    "next_dose_time": self._calculate_next_dose_time(med).isoformat(),
                    "adherence_rate": int(adherence_rate),
                    "supply_days_left": med.supply_days_remaining or 30
                })
                
                overall_adherence += adherence_rate
            
            # Calculate summary metrics
            adherence_summary = {
                "overall_rate": int(overall_adherence / len(medications_list)) if medications_list else 100,
                "last_7_days": self._calculate_7_day_adherence(user),
                "missed_doses_today": missed_today,
                "on_time_rate": self._calculate_on_time_rate(user)
            }
            
            # Get upcoming refills
            upcoming_refills = []
            for med in medications_queryset:
                if med.supply_days_remaining and med.supply_days_remaining <= 14:
                    upcoming_refills.append({
                        "medication": med.name,
                        "days_remaining": med.supply_days_remaining,
                        "auto_refill_enabled": getattr(med, 'auto_refill_enabled', False)
                    })
            
            return {
                "active_medications": medications_list,
                "adherence_summary": adherence_summary,
                "upcoming_refills": upcoming_refills
            }
            
        except Exception as e:
            logger.error(f"Error getting medication data for user {user.id}: {str(e)}")
            return {
                "active_medications": [],
                "adherence_summary": {
                    "overall_rate": 0,
                    "last_7_days": 0,
                    "missed_doses_today": 0,
                    "on_time_rate": 0
                },
                "upcoming_refills": []
            }

    def _get_vitals_data(self, user, medical_record):
        """Get current vitals and trends data."""
        try:
            from healthcare.models import VitalSign
            # Get most recent vitals
            vitals_queryset = VitalSign.objects.filter(
                medical_record=medical_record
            ).order_by('-measured_at').first() if medical_record else None
            
            current_vitals = {}
            if vitals_queryset:
                current_vitals = {
                    "blood_pressure": f"{vitals_queryset.systolic_bp}/{vitals_queryset.diastolic_bp}" if vitals_queryset.systolic_bp else None,
                    "heart_rate": vitals_queryset.heart_rate,
                    "temperature": float(vitals_queryset.temperature) if vitals_queryset.temperature else None,
                    "weight": float(vitals_queryset.weight) if vitals_queryset.weight else None,
                    "oxygen_saturation": vitals_queryset.oxygen_saturation,
                    "pain_level": vitals_queryset.pain_level
                }
                # Remove None values
                current_vitals = {k: v for k, v in current_vitals.items() if v is not None}
            
            # Analyze trends (simplified - in production, use proper trend analysis)
            trends = self._analyze_vital_trends(user, medical_record)
            
            return {
                "current": current_vitals,
                "trends": trends,
                "last_recorded": vitals_queryset.recorded_at.isoformat() if vitals_queryset else timezone.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting vitals data for user {user.id}: {str(e)}")
            return {
                "current": {},
                "trends": {"improving": [], "stable": [], "concerning": []},
                "last_recorded": timezone.now().isoformat()
            }

    def _get_wearable_data(self, user):
        """Get smart watch and wearable device data."""
        try:
            # Get connected devices
            connected_devices = []
            wearable_integrations = WearableIntegration.objects.filter(
                user=user,
                status='connected'
            )
            
            for integration in wearable_integrations:
                connected_devices.append({
                    "id": integration.id,
                    "type": integration.device_type.lower(),
                    "name": integration.device_name or f"{integration.device_type} Device",
                    "last_sync": integration.last_sync.isoformat() if integration.last_sync else timezone.now().isoformat(),
                    "battery_level": getattr(integration, 'battery_level', None)
                })
            
            # Get today's summary from wearable measurements
            today = timezone.now().date()
            today_measurements = WearableMeasurement.objects.filter(
                user=user,
                #measurement_date=today
            ).order_by('-measured_at')[:10]
            
            today_summary = {
                "steps": 0,
                "heart_rate_avg": 0,
                "sleep_hours": 0,
                "active_minutes": 0
            }
            
            # Aggregate today's data
            for measurement in today_measurements:
                if measurement.measurement_type == 'steps':
                    today_summary["steps"] += int(measurement.value or 0)
                elif measurement.measurement_type == 'heart_rate':
                    today_summary["heart_rate_avg"] = int(measurement.value or 0)
                elif measurement.measurement_type == 'sleep':
                    today_summary["sleep_hours"] = round(float(measurement.value or 0) / 60, 1)  # Convert minutes to hours
                elif measurement.measurement_type == 'activity':
                    today_summary["active_minutes"] += int(measurement.value or 0)
            
            # Calculate medication reminders sent (simplified)
            medication_reminders_sent = self._get_medication_reminders_count(user, today)
            
            return {
                "connected_devices": connected_devices,
                "today_summary": today_summary,
                "medication_reminders_sent": medication_reminders_sent
            }
            
        except Exception as e:
            logger.error(f"Error getting wearable data for user {user.id}: {str(e)}")
            return {
                "connected_devices": [],
                "today_summary": {
                    "steps": 0,
                    "heart_rate_avg": 0,
                    "sleep_hours": 0,
                    "active_minutes": 0
                },
                "medication_reminders_sent": 0
            }

    def _get_appointments_data(self, user):
        """Get appointment data including upcoming and recent appointments."""
        days = 7  # Default to next 7 days for upcoming appointments
        
        try:
            from telemedicine.models import Appointment  
            now = timezone.now()
            
            # Get upcoming appointments
            upcoming_appointments = Appointment.objects.filter(
                patient=user,
                scheduled_time__gte=now,
                scheduled_time__date__lte=now.date() + timedelta(days=days),
                status__in=['scheduled', 'confirmed']
            ).order_by('scheduled_time')[:5]
            
            upcoming_list = []
            for apt in upcoming_appointments:
                upcoming_list.append({
                    "id": apt.id,
                    "date": apt.scheduled_time.date().isoformat(),
                    "time": apt.scheduled_time.time().isoformat(),
                    "provider_name": apt.provider.get_full_name() if apt.provider else "TBD",
                    "appointment_type": getattr(apt, 'appointment_type', 'Consultation'),
                    "reason": getattr(apt, 'reason', 'General consultation'),
                    "is_telemedicine": getattr(apt, 'is_telemedicine', False),
                })
            
            # Get recent appointments
            recent_appointments = Appointment.objects.filter(
                patient=user,
                scheduled_time__lt=now,
                scheduled_time__date__gte=now.date() - timedelta(days=30),
                status='completed'
            ).order_by('-scheduled_time')[:3]
            
            recent_list = []
            for apt in recent_appointments:
                recent_list.append({
                    "date": apt.scheduled_time.date().isoformat(),
                    "provider": apt.provider.get_full_name() if apt.provider else "Unknown",
                    "summary": getattr(apt, 'notes', None) or f"{getattr(apt, 'appointment_type', 'Appointment')} completed",
                    "follow_up_required": getattr(apt, 'follow_up_required', False)
                })
            
            # Get next single appointment for summary
            next_appointment = upcoming_appointments.first() if upcoming_appointments else None
            next_appointment_data = None
            if next_appointment:
                next_appointment_data = {
                    'provider': next_appointment.provider.get_full_name() if next_appointment.provider else 'Unknown',
                    'date': next_appointment.scheduled_time.date().isoformat(),
                    'time': next_appointment.scheduled_time.time().isoformat()
                }
            
            return {
                "upcoming": upcoming_list,
                "recent": recent_list,
                "next_appointment": next_appointment_data
            }
            
        except Exception as e:
            logger.error(f"Error getting appointments data for user {user.id}: {str(e)}")
            return {
                "upcoming": [],
                "recent": [],
                "next_appointment": None
            }

    def _get_care_team_data(self, user, medical_record):
        """Get care team information."""
        try:
            care_team = []
            
            # Add primary physician
            if medical_record and medical_record.primary_physician:
                provider = medical_record.primary_physician
                care_team.append({
                    "id": provider.id,
                    "name": provider.get_full_name(),
                    "role": "Primary Physician",
                    "specialty": getattr(provider.provider_profile, 'specialty', None) if hasattr(provider, 'provider_profile') else None,
                    "contact_method": "Portal Message",
                    "last_contact": self._get_last_contact_date(user, provider),
                    "next_scheduled_contact": self._get_next_scheduled_contact(user, provider)
                })
            
            # Add other care team members (caregivers, specialists, etc.)
            from users.models import CaregiverRequest
            approved_caregivers = CaregiverRequest.objects.filter(
                patient=user,
                status='approved'
            ).select_related('caregiver')
            
            for caregiver_request in approved_caregivers:
                caregiver = caregiver_request.caregiver
                care_team.append({
                    "id": caregiver.id,
                    "name": caregiver.get_full_name(),
                    "role": "Caregiver",
                    "specialty": caregiver_request.care_type,
                    "contact_method": "Phone/Portal",
                    "last_contact": self._get_last_contact_date(user, caregiver),
                    "next_scheduled_contact": None
                })
            
            return care_team
            
        except Exception as e:
            logger.error(f"Error getting care team data for user {user.id}: {str(e)}")
            return []

    def _get_research_participation_data(self, user):
        """Get research study participation data."""
        try:
            from users.models import ResearchConsent
            
            # Get enrolled studies (simplified - in production, query actual research studies)
            enrolled_studies = []
            research_consents = ResearchConsent.objects.filter(
                user=user,
                consented=True,
                withdrawn=False
            )
            
            for consent in research_consents:
                enrolled_studies.append({
                    "id": consent.id,
                    "title": consent.study_title or "Rare Disease Research Study",
                    "phase": "Phase II",  # This should come from actual study data
                    "enrollment_date": consent.consent_date.isoformat(),
                    "next_visit_date": None,  # This should come from study schedule
                    "compensation_earned": 0  # This should come from actual compensation tracking
                })
            
            # Get available studies (mock data - in production, query available studies)
            available_studies = [
                {
                    "id": 1,
                    "title": "Long-term Medication Adherence Study",
                    "description": "Study tracking medication adherence in rare disease patients",
                    "estimated_time_commitment": "30 minutes monthly",
                    "compensation": "$50/month",
                    "eligibility_match": 95
                },
                {
                    "id": 2,
                    "title": "Wearable Device Health Monitoring",
                    "description": "Research on continuous health monitoring using wearable devices",
                    "estimated_time_commitment": "Passive monitoring",
                    "compensation": "$100 enrollment bonus",
                    "eligibility_match": 87
                }
            ]
            
            # Get data contributions
            data_contributions = {
                "total_surveys_completed": self._get_completed_surveys_count(user),
                "wearable_data_shared_days": self._get_wearable_data_sharing_days(user),
                "clinical_visits_completed": self._get_completed_clinical_visits(user)
            }
            
            return {
                "enrolled_studies": enrolled_studies,
                "available_studies": available_studies,
                "data_contributions": data_contributions
            }
            
        except Exception as e:
            logger.error(f"Error getting research participation data for user {user.id}: {str(e)}")
            return {
                "enrolled_studies": [],
                "available_studies": [],
                "data_contributions": {
                    "total_surveys_completed": 0,
                    "wearable_data_shared_days": 0,
                    "clinical_visits_completed": 0
                }
            }

    def _get_health_alerts(self, user, patient_profile, medical_record):
        """Generate health alerts based on patient data."""
        alerts = []
        alert_id = 1
        
        try:
            # Identity verification alert
            if not patient_profile.identity_verified:
                days_remaining = patient_profile.days_until_verification_required()
                severity = 'critical' if days_remaining and days_remaining <= 7 else 'high'
                
                alerts.append({
                    "id": alert_id,
                    "type": "system",
                    "severity": severity,
                    "title": "Identity Verification Required",
                    "message": f"Please complete identity verification. {days_remaining} days remaining." if days_remaining else "Please complete identity verification.",
                    "created_at": timezone.now().isoformat(),
                    "acknowledged": False,
                    "action_required": True,
                    "action_url": "/patient/profile/verify-identity"
                })
                alert_id += 1
            
            # Medication adherence alerts
            missed_doses = self._get_missed_doses_today(user)
            if missed_doses > 0:
                alerts.append({
                    "id": alert_id,
                    "type": "medication",
                    "severity": "high" if missed_doses > 2 else "medium",
                    "title": "Missed Medication Doses",
                    "message": f"You have {missed_doses} missed medication dose(s) today. Please take your medications as prescribed.",
                    "created_at": timezone.now().isoformat(),
                    "acknowledged": False,
                    "action_required": True,
                    "action_url": "/patient/medications"
                })
                alert_id += 1
            
            # Upcoming appointment reminders
            next_appointment = self._get_next_appointment_within_days(user, 2)
            if next_appointment:
                alerts.append({
                    "id": alert_id,
                    "type": "appointment",
                    "severity": "medium",
                    "title": "Upcoming Appointment",
                    "message": f"You have an appointment with {next_appointment['provider']} on {next_appointment['date']}.",
                    "created_at": timezone.now().isoformat(),
                    "acknowledged": False,
                    "action_required": False,
                    "action_url": "/patient/appointments"
                })
                alert_id += 1
            
            # Vital signs alerts (if concerning trends detected)
            concerning_vitals = self._get_concerning_vital_trends(user, medical_record)
            if concerning_vitals:
                alerts.append({
                    "id": alert_id,
                    "type": "health",
                    "severity": "high",
                    "title": "Concerning Vital Signs Trend",
                    "message": f"Your {', '.join(concerning_vitals)} show concerning trends. Please contact your healthcare provider.",
                    "created_at": timezone.now().isoformat(),
                    "acknowledged": False,
                    "action_required": True,
                    "action_url": "/patient/vitals"
                })
                alert_id += 1
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error generating health alerts for user {user.id}: {str(e)}")
            return []

    def _get_quick_actions(self, user, patient_profile):
        """Get quick action items for the dashboard."""
        actions = [
            {
                "id": "schedule-appointment",
                "title": "Schedule Appointment",
                "description": "Book a visit with your healthcare provider",
                "icon": "calendar",
                "href": "/patient/appointments/schedule",
                "priority": "high",
                "requires_verification": True
            },
            {
                "id": "record-vitals",
                "title": "Record Vital Signs",
                "description": "Log your current vital signs and symptoms",
                "icon": "activity",
                "href": "/patient/vitals/record",
                "priority": "medium",
                "requires_verification": False
            },
            {
                "id": "medication-log",
                "title": "Log Medication",
                "description": "Record medication taken and adherence",
                "icon": "pill",
                "href": "/patient/medications/log",
                "priority": "high",
                "requires_verification": False
            },
            {
                "id": "health-records",
                "title": "View Health Records",
                "description": "Access your medical records and test results",
                "icon": "file-medical",
                "href": "/patient/health-records",
                "priority": "medium",
                "requires_verification": True
            },
            {
                "id": "connect-device",
                "title": "Connect Smart Watch",
                "description": "Connect your wearable device for health monitoring",
                "icon": "device",
                "href": "/patient/devices/connect",
                "priority": "medium",
                "requires_verification": False
            },
            {
                "id": "research-studies",
                "title": "Research Studies",
                "description": "Explore available research opportunities",
                "icon": "research",
                "href": "/patient/research/studies",
                "priority": "low",
                "requires_verification": True
            }
        ]
        
        return actions

    # Helper methods for calculations
    def _calculate_overall_health_status(self, user, patient_profile, medical_record):
        """Calculate overall health status based on multiple factors."""
        # Simplified calculation - in production, use comprehensive health scoring
        score = 100
        
        # Penalize for missed medications
        missed_doses = self._get_missed_doses_today(user)
        score -= missed_doses * 10
        
        # Penalize for unverified identity
        if not patient_profile.identity_verified:
            score -= 20
        
        # Penalize for concerning vital trends
        concerning_vitals = self._get_concerning_vital_trends(user, medical_record)
        score -= len(concerning_vitals) * 15
        
        # Determine status based on score
        if score >= 90:
            return 'excellent'
        elif score >= 75:
            return 'good'
        elif score >= 60:
            return 'fair'
        elif score >= 40:
            return 'poor'
        else:
            return 'critical'

    def _calculate_next_dose_time(self, medication):
        """Calculate when the next dose of medication should be taken."""
        from datetime import timedelta
        
        now = timezone.now()
        
        # Simplified calculation - in production, use proper medication scheduling
        if medication.frequency == 'once_daily':
            # Assume morning dose at 8 AM
            next_dose = now.replace(hour=8, minute=0, second=0, microsecond=0)
            if next_dose <= now:
                next_dose += timedelta(days=1)
        elif medication.frequency == 'twice_daily':
            # Assume 8 AM and 8 PM
            morning = now.replace(hour=8, minute=0, second=0, microsecond=0)
            evening = now.replace(hour=20, minute=0, second=0, microsecond=0)
            
            if now < morning:
                next_dose = morning
            elif now < evening:
                next_dose = evening
            else:
                next_dose = morning + timedelta(days=1)
        else:
            # Default to next hour for other frequencies
            next_dose = now + timedelta(hours=1)
        
        return next_dose

    def _calculate_7_day_adherence(self, user):
        """Calculate medication adherence rate for the last 7 days."""
        # Simplified calculation - implement proper adherence calculation
        return 85  # Mock value

    def _calculate_on_time_rate(self, user):
        """Calculate on-time medication taking rate."""
        # Simplified calculation - implement proper on-time rate calculation
        return 78  # Mock value

    def _analyze_vital_trends(self, user, medical_record):
        """Analyze vital signs trends."""
        # Simplified trend analysis - implement proper trend detection
        return {
            "improving": ["Blood Pressure", "Weight"],
            "stable": ["Heart Rate"],
            "concerning": []
        }

    def _get_medication_reminders_count(self, user, date):
        """Get count of medication reminders sent today."""
        # Implement actual reminder counting logic
        return 3

    def _get_last_checkup_date(self, user):
        """Get the date of the last medical checkup."""
        try:
            from telemedicine.models import Appointment
            last_checkup = Appointment.objects.filter(
                patient=user,
                status='completed',
                appointment_type__in=['checkup', 'follow_up', 'consultation']
            ).order_by('-scheduled_time').first()
            
            if last_checkup:
                return last_checkup.scheduled_time.date().isoformat()
        except:
            pass
        
        return timezone.now().date().isoformat()

    def _get_next_appointment_date(self, user):
        """Get the date of the next scheduled appointment."""
        try:
            from healthcare.models import Appointment
            next_appointment = Appointment.objects.filter(
                patient=user,
                appointment_date__gte=timezone.now().date(),
                status__in=['scheduled', 'confirmed']
            ).order_by('scheduled_time').first()
            
            if next_appointment:
                return next_appointment.scheduled_time.date().isoformat()
        except:
            pass
        
        return None

    def _get_missed_doses_today(self, user):
        """Get count of missed medication doses today."""
        # Implement actual missed dose counting
        return 0

    def _get_concerning_vital_trends(self, user, medical_record):
        """Get list of concerning vital signs trends."""
        # Implement actual trend analysis
        return []

    def _get_last_contact_date(self, user, provider):
        """Get the last contact date with a provider."""
        return timezone.now().date().isoformat()

    def _get_next_scheduled_contact(self, user, provider):
        """Get the next scheduled contact with a provider."""
        return None

    def _get_completed_surveys_count(self, user):
        """Get count of completed research surveys."""
        return 12

    def _get_wearable_data_sharing_days(self, user):
        """Get number of days of wearable data shared for research."""
        return 45

    def _get_completed_clinical_visits(self, user):
        """Get count of completed clinical research visits."""
        return 3

    def _get_next_appointment_within_days(self, user, days):
        """Get next appointment within specified days."""
        try:
            from healthcare.models import Appointment
            
            appointment = Appointment.objects.filter(
                patient=user,
                appointment_date__gte=timezone.now().date(),
                appointment_date__lte=timezone.now().date() + timedelta(days=days),
                status__in=['scheduled', 'confirmed']
            ).order_by('scheduled_time').first()
            
            if appointment:
                return {
                    'provider': appointment.provider.get_full_name() if appointment.provider else 'Unknown',
                    'date': appointment.scheduled_time.date().isoformat()
                }
        except:
            pass
        
        return None

class ProviderProfileViewSet(BaseViewSet):
    queryset = ProviderProfile.objects.all()
    serializer_class = ProviderProfileSerializer
    permission_classes = [IsAuthenticated, IsRoleOwnerOrReadOnly]
    
    @action(detail=False, methods=['get'], url_path='dashboard')
    def dashboard(self, request):
        """Get provider dashboard with patient summaries and schedule overview."""
        user = request.user
        
        if user.role != 'provider':
            return Response(
                {"error": "Only providers can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            provider_profile = user.provider_profile
        except:
            return Response(
                {"error": "Provider profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Build provider-specific dashboard context
        dashboard_data = {
            "practice_summary": {
                "specialty": provider_profile.get_specialty_display(),
                "accepting_patients": provider_profile.accepting_new_patients,
                "telemedicine_available": provider_profile.telemedicine_available,
                "years_experience": provider_profile.years_of_experience,
            },
            "patient_overview": {
                # In a real implementation, you'd query patient relationships
                "total_patients": 0,  # Query actual patient count
                "active_treatments": 0,  # Query active treatment plans
                "pending_consultations": 0,  # Query upcoming appointments
            },
            "quick_actions": [
                {
                    "id": "schedule-appointment",
                    "title": "Schedule Appointment", 
                    "description": "Schedule a new patient appointment",
                    "icon": "calendar-plus",
                    "href": "/provider/appointments/new",
                    "priority": "high"
                },
                {
                    "id": "patient-records",
                    "title": "Patient Records",
                    "description": "Access patient medical records",
                    "icon": "file-medical",
                    "href": "/provider/patients",
                    "priority": "high"
                },
                {
                    "id": "emergency-access",
                    "title": "Emergency Access",
                    "description": "Initiate emergency patient access",
                    "icon": "exclamation-triangle",
                    "href": "/provider/emergency",
                    "priority": "critical"
                }
            ],
            "compliance_status": {
                "license_status": "active",  # Check license expiration
                "continuing_education": "up_to_date",  # Track CE requirements
                "malpractice_insurance": "current",  # Insurance status
            }
        }
        
        return Response(dashboard_data)

    @action(detail=True, methods=['post'])
    def complete_profile(self, request, pk=None):
        """Complete provider profile with additional information."""
        profile = self.get_object()
        
        # Ensure user can only update their own profile
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update profile fields
        allowed_fields = [
            'years_of_experience', 'rare_condition_specialties',
            'telemedicine_available'
        ]
        
        for field in allowed_fields:
            if field in request.data:
                setattr(profile, field, request.data[field])
        
        profile.save()
        
        return Response({
            'detail': 'Profile updated successfully',
            'profile': ProviderProfileSerializer(profile).data
        })


class PharmcoProfileViewSet(BaseViewSet):
    queryset = PharmcoProfile.objects.all()
    serializer_class = PharmcoProfileSerializer
    permission_classes = [IsAuthenticated, IsRoleOwnerOrReadOnly]
    
    @action(detail=False, methods=['get'], url_path='dashboard')
    def dashboard(self, request):
        """Get pharmaceutical company dashboard with research metrics and compliance status."""
        user = request.user
        
        if user.role != 'pharmco':
            return Response(
                {"error": "Only pharmaceutical company users can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            pharmco_profile = user.pharmco_profile
        except:
            return Response(
                {"error": "Pharmaceutical company profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Build pharma-specific dashboard context
        dashboard_data = {
            "company_overview": {
                "company_name": pharmco_profile.company_name,
                "regulatory_id": pharmco_profile.regulatory_id,
                "research_focus": pharmco_profile.get_primary_research_focus_display(),
                "role": pharmco_profile.get_role_at_company_display(),
            },
            "research_metrics": {
                # These would connect to your research consent and data systems
                "active_studies": 0,  # Count of active research studies
                "consented_patients": 0,  # Patients who've consented to research
                "data_collections": 0,  # Recent data collection events
                "pending_approvals": 0,  # Regulatory approvals pending
            },
            "compliance_dashboard": {
                "consent_compliance": "excellent",  # Based on consent tracking
                "data_governance": "compliant",  # Based on data handling
                "regulatory_status": "up_to_date",  # Regulatory filing status
                "audit_score": 95,  # Compliance audit score
            },
            "quick_actions": [
                {
                    "id": "view-research-data",
                    "title": "Research Data",
                    "description": "Access consented patient research data",
                    "icon": "chart-line",
                    "href": "/pharmco/research",
                    "priority": "high"
                },
                {
                    "id": "consent-management",
                    "title": "Consent Management",
                    "description": "Manage patient research consents",
                    "icon": "user-check",
                    "href": "/pharmco/consents",
                    "priority": "medium"
                },
                {
                    "id": "compliance-reports",
                    "title": "Compliance Reports",
                    "description": "Generate regulatory compliance reports",
                    "icon": "file-chart",
                    "href": "/pharmco/compliance",
                    "priority": "medium"
                }
            ]
        }
        
        return Response(dashboard_data)

    @action(detail=True, methods=['post'])
    def complete_profile(self, request, pk=None):
        """Complete pharmaceutical company profile with additional information."""
        profile = self.get_object()
        
        # Ensure user can only update their own profile
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update profile fields
        allowed_fields = [
            'company_address', 'monitored_medications'
        ]
        
        for field in allowed_fields:
            if field in request.data:
                setattr(profile, field, request.data[field])
        
        profile.save()
        
        return Response({
            'detail': 'Profile updated successfully',
            'profile': PharmcoProfileSerializer(profile).data
        })


class CaregiverProfileViewSet(BaseViewSet):
    queryset = CaregiverProfile.objects.all()
    serializer_class = CaregiverProfileSerializer
    permission_classes = [IsAuthenticated, IsRoleOwnerOrReadOnly]
    
    @action(detail=True, methods=['post'])
    def complete_profile(self, request, pk=None):
        """Complete caregiver profile with additional information."""
        profile = self.get_object()
        
        # Ensure user can only update their own profile
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update profile fields
        allowed_fields = [
            'authorization_documentation', 'notes'
        ]
        
        for field in allowed_fields:
            if field in request.data:
                setattr(profile, field, request.data[field])
        
        profile.save()
        
        return Response({
            'detail': 'Profile updated successfully',
            'profile': CaregiverProfileSerializer(profile).data
        })


class ResearcherProfileViewSet(BaseViewSet):
    queryset = ResearcherProfile.objects.all()
    serializer_class = ResearcherProfileSerializer
    permission_classes = [IsAuthenticated, IsRoleOwnerOrReadOnly]
    
    @action(detail=True, methods=['post'])
    def complete_profile(self, request, pk=None):
        """Complete researcher profile with additional information."""
        profile = self.get_object()
        
        # Ensure user can only update their own profile
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update profile fields
        allowed_fields = [
            'active_studies'
        ]
        
        for field in allowed_fields:
            if field in request.data:
                setattr(profile, field, request.data[field])
        
        profile.save()
        
        return Response({
            'detail': 'Profile updated successfully',
            'profile': ResearcherProfileSerializer(profile).data
        })
            
    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Verify researcher (admin only)."""
        if not request.user.is_staff:
            return Response({
                'detail': 'Only administrators can verify researchers'
            }, status=status.HTTP_403_FORBIDDEN)
        
        profile = self.get_object()
        profile.is_verified = True
        profile.verified_at = timezone.now()
        profile.verified_by = request.user
        profile.save()
        
        return Response({'detail': 'Researcher verified successfully'})


class ComplianceProfileViewSet(BaseViewSet):
    queryset = ComplianceProfile.objects.all()
    serializer_class = ComplianceProfileSerializer
    permission_classes = [IsAuthenticated, IsComplianceOfficer]
    
    @action(detail=True, methods=['post'])
    def complete_profile(self, request, pk=None):
        """Complete compliance officer profile with additional information."""
        profile = self.get_object()
        
        # Ensure user can only update their own profile
        if profile.user != request.user:
            return Response({
                'detail': 'You can only update your own profile'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update profile fields
        allowed_fields = [
            'certification_number', 'certification_expiry'
        ]
        
        for field in allowed_fields:
            if field in request.data:
                setattr(profile, field, request.data[field])
        
        profile.save()
        
        return Response({
            'detail': 'Profile updated successfully',
            'profile': ComplianceProfileSerializer(profile).data
        })


class ConsentRecordViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing consent records."""
    queryset = ConsentRecord.objects.all()
    serializer_class = ConsentRecordSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Fix for Swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return ConsentRecord.objects.none()
        
        user = self.request.user
        
        # Check if user is authenticated and has role attribute
        if not user.is_authenticated or not hasattr(user, 'role'):
            return ConsentRecord.objects.none()
        
        if user.is_staff or user.role in ['admin', 'compliance']:
            return ConsentRecord.objects.all()
        else:
            return ConsentRecord.objects.filter(user=user)
    
    @action(detail=False, methods=['get'])
    def audit_trail(self, request):
        """Get audit trail for compliance (compliance officers only)."""
        if request.user.role not in ['admin', 'compliance']:
            return Response({
                'detail': 'Compliance officer access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get date range from query params
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Get consent records for the period
        consent_records = ConsentRecord.objects.filter(
            signature_timestamp__gte=start_date
        ).order_by('-signature_timestamp')
        
        # Get summary statistics
        summary = {
            'total_records': consent_records.count(),
            'by_type': dict(
                consent_records.values('consent_type').annotate(
                    count=Count('consent_type')
                ).values_list('consent_type', 'count')
            ),
            'by_user_role': dict(
                consent_records.values('user__role').annotate(
                    count=Count('user__role')
                ).values_list('user__role', 'count')
            ),
            'revoked_count': consent_records.filter(revoked=True).count(),
        }
        
        # Paginate results
        paginator = PageNumberPagination()
        paginated_records = paginator.paginate_queryset(consent_records, request)
        
        serializer = self.get_serializer(paginated_records, many=True)
        
        return Response({
            'summary': summary,
            'records': serializer.data,
            'pagination': {
                'count': paginator.page.paginator.count,
                'next': paginator.get_next_link(),
                'previous': paginator.get_previous_link(),
            }
        })

class AdminViewSet(viewsets.ViewSet):
    """Admin-specific endpoints."""
    
    @action(detail=False, methods=['get'], url_path='dashboard-overview')
    def dashboard_overview(self, request):
        """Get admin dashboard overview data."""
        user = request.user
        
        # Check admin permissions
        if user.role not in ['admin', 'superadmin']:
            return Response(
                {"error": "Admin access required"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        today = timezone.now().date()
        
        user_stats = {
            "total_users": User.objects.filter(is_active=True).count(),
            "pending_approvals": User.objects.filter(
                is_approved=False,
                is_active=True
            ).count(),
            "active_sessions": User.objects.filter(
                last_login__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            "new_users_today": User.objects.filter(
                date_joined__date=today
            ).count()
        }
        
        # Get recent activities (you can customize this based on your audit log)
        recent_activities = []
        
        # Example activities - replace with actual audit log queries
        recent_users = User.objects.order_by('-date_joined')[:5]
        for user in recent_users:
            recent_activities.append({
                "id": user.id,
                "type": "user_registration",
                "description": f"New {user.role} user registered",
                "timestamp": user.date_joined.isoformat(),
                "user_email": user.email,
                "severity": "low"
            })
        
        # System status (simplified example)
        system_status = {
            "overall_health": "healthy",
            "uptime_percentage": 99.9,
            "response_time": 150,  # milliseconds
            "active_sessions": user_stats["active_sessions"]
        }
        
        return Response({
            "user_stats": user_stats,
            "recent_activities": recent_activities,
            "system_status": system_status
        })

    @action(detail=False, methods=['get'], url_path='admin-dashboard-stats')
    def dashboard_stats(self, request):
        """Get detailed admin statistics."""
        user = request.user
        
        if user.role not in ['admin', 'superadmin']:
            return Response(
                {"error": "Admin access required"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Add more detailed statistics here
        
        # User breakdown by role
        role_breakdown = User.objects.values('role').annotate(
            count=Count('id')
        ).order_by('role')
        
        # Registration trends (last 30 days)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        registration_trend = User.objects.filter(
            date_joined__gte=thirty_days_ago
        ).extra(
            select={'day': 'date(date_joined)'}
        ).values('day').annotate(
            count=Count('id')
        ).order_by('day')
        
        return Response({
            "role_breakdown": list(role_breakdown),
            "registration_trend": list(registration_trend),
            "total_active_users": User.objects.filter(is_active=True).count(),
            "total_verified_users": User.objects.filter(email_verified=True).count(),
            "total_approved_users": User.objects.filter(is_approved=True).count(),
        })
        
    @action(detail=False, methods=['get'])
    def admin_notification_summary(self, request):
        """Get summary of items requiring admin attention."""
        if not (request.user.is_staff or request.user.role == 'admin'):
            return Response({'detail': 'Admin access required'}, status=403)
        
        summary = {
            'pending_approvals': User.objects.filter(
                is_approved=False, 
                is_staff=False
            ).exclude(role='admin').count(),
            'recent_registrations': User.objects.filter(
                date_joined__gte=timezone.now() - timedelta(hours=24)
            ).count(),
            'locked_accounts': User.objects.filter(
                account_locked=True
            ).count(),
        }
        return Response(summary)
