import uuid
import json
import logging
import traceback
import qrcode
import io
import base64
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.shortcuts import redirect
from django.db import transaction
from django.db.models import Count, Min, Max, Avg
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import (
    WearableIntegration, WearableMeasurement, 
    WithingsProfile, WithingsMeasurement, SyncLog
)
from .serializers import (
    WearableIntegrationSerializer, WearableMeasurementSerializer,
    WithingsProfileSerializer, WithingsMeasurementSerializer,
    SyncLogSerializer, IntegrationConnectSerializer,
    IntegrationCallbackSerializer, IntegrationConnectionStatusSerializer,
    IntegrationDataFetchSerializer, MeasurementSummarySerializer,
    HealthDataConsentSerializer
)
from .services import (
    withings_service, apple_health_service, google_fit_service,
    samsung_health_service, fitbit_service
)
from healthcare.models import VitalSign

# Configure logging
logger = logging.getLogger(__name__)


class WearableIntegrationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing wearable device integrations."""
    queryset = WearableIntegration.objects.all()
    serializer_class = WearableIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter integrations to only show the user's own integrations."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        
        # Admins can see all integrations
        if user.is_staff or user.role == 'admin':
            return self.queryset
            
        # Providers can see integrations for their patients
        if user.role == 'provider':
            patient_ids = user.primary_patients.values_list('id', flat=True)
            return self.queryset.filter(user__in=patient_ids)
            
        # Patients can only see their own integrations
        return self.queryset.filter(user=user)
    
    def perform_create(self, serializer):
        """Set the user when creating a new integration."""
        serializer.save(user=self.request.user)
    
    @swagger_auto_schema(
        request_body=HealthDataConsentSerializer,
        responses={200: WearableIntegrationSerializer}
    )
    @action(detail=True, methods=['post'])
    def update_consent(self, request, pk=None):
        """Update consent and data collection preferences for a wearable integration."""
        integration = self.get_object()
        
        # Ensure user can only update their own integrations
        if integration.user != request.user and not (request.user.is_staff or request.user.role == 'admin'):
            return Response(
                {'detail': 'You do not have permission to update this integration'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        serializer = HealthDataConsentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Update consent and preferences
        integration.consent_granted = serializer.validated_data['consent_granted']
        
        if integration.consent_granted:
            integration.consent_date = timezone.now()
            
        # Update data collection preferences
        for field in [
            'collect_steps', 'collect_heart_rate', 'collect_weight', 
            'collect_sleep', 'collect_blood_pressure', 'collect_oxygen',
            'collect_blood_glucose', 'collect_activity', 'collect_temperature'
        ]:
            if field in serializer.validated_data:
                setattr(integration, field, serializer.validated_data[field])
        
        # Update sync frequency if provided
        if 'sync_frequency' in serializer.validated_data:
            integration.sync_frequency = serializer.validated_data['sync_frequency']
        
        integration.save()
        
        # Log consent change
        try:
            from healthcare.models import HealthDataConsent
            
            HealthDataConsent.objects.update_or_create(
                patient=request.user,
                consent_type='wearable_integration',
                authorized_entity=None,
                defaults={
                    'consented': integration.consent_granted,
                    'ip_address': self._get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
        except Exception as e:
            logger.warning(f"Failed to log consent: {str(e)}")
        
        return Response(WearableIntegrationSerializer(integration).data)
    
    @swagger_auto_schema(responses={200: IntegrationConnectionStatusSerializer})
    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """Get the current status of a wearable integration."""
        integration = self.get_object()
        
        # Update the status based on current state
        integration.update_status()
        
        # Get measurements count
        measurements_count = WearableMeasurement.objects.filter(
            user=integration.user, 
            integration_type=integration.integration_type
        ).count()
        
        # Calculate next sync
        next_sync_due = None
        if integration.last_sync and integration.sync_frequency:
            next_sync_due = integration.last_sync + timedelta(hours=integration.sync_frequency)
        
        # Build response
        response_data = {
            'is_connected': integration.is_connected(),
            'status': integration.status,
            'status_display': integration.get_status_display(),
            'last_sync': integration.last_sync,
            'next_sync_due': next_sync_due,
            'measurements_count': measurements_count,
            'message': self._get_status_message(integration)
        }
        
        serializer = IntegrationConnectionStatusSerializer(response_data)
        return Response(serializer.data)
    
    def _get_status_message(self, integration):
        """Get a user-friendly status message based on integration state."""
        if not integration.access_token:
            return "Not connected. Please connect your device."
            
        if integration.status == WearableIntegration.ConnectionStatus.EXPIRED:
            return "Your connection has expired. Please reconnect."
            
        if integration.status == WearableIntegration.ConnectionStatus.ERROR:
            return "There was an error with your connection. Please reconnect."
            
        if not integration.consent_granted:
            return "Connected, but you haven't granted consent to collect data."
            
        if not integration.last_sync:
            return "Connected, but no data has been synced yet."
            
        days_since_sync = (timezone.now() - integration.last_sync).days
        if days_since_sync > 7:
            return f"Last synced {days_since_sync} days ago. Consider syncing again."
            
        return "Connected and syncing normally."
    
    def _get_client_ip(self, request):
        """Get client IP safely accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class WearableMeasurementViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for accessing wearable measurements."""
    queryset = WearableMeasurement.objects.all()
    serializer_class = WearableMeasurementSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['measurement_type', 'integration_type']
    
    def get_queryset(self):
        """Filter measurements to only show the user's own data."""
        # Check if this is a schema generation request
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
                
        user = self.request.user
        
        # Admins can see all measurements
        if user.is_staff or user.role == 'admin':
            return self.queryset
            
        # Providers can see measurements for their patients
        if user.role == 'provider':
            patient_ids = user.primary_patients.values_list('id', flat=True)
            return self.queryset.filter(user__in=patient_ids)
            
        # Caregivers can see measurements for patients they're authorized for
        if user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            patient_ids = user.caregiver_patients.values_list('id', flat=True)
            return self.queryset.filter(user__in=patient_ids)
            
        # Patients can only see their own measurements
        return self.queryset.filter(user=user)
    
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'start_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                format=openapi.FORMAT_DATE, description="Start date (YYYY-MM-DD)"
            ),
            openapi.Parameter(
                'end_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                format=openapi.FORMAT_DATE, description="End date (YYYY-MM-DD)"
            ),
            openapi.Parameter(
                'measurement_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                description="Filter by measurement type"
            ),
            openapi.Parameter(
                'integration_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                description="Filter by integration type"
            ),
        ],
        responses={200: MeasurementSummarySerializer(many=True)}
    )
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get a summary of measurements by type."""
        queryset = self.get_queryset()
        
        # Apply filters from query parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        measurement_type = request.query_params.get('measurement_type')
        integration_type = request.query_params.get('integration_type')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                start_date = timezone.make_aware(start_date)
                queryset = queryset.filter(measured_at__gte=start_date)
            except ValueError:
                return Response(
                    {'detail': 'Invalid start_date format. Use YYYY-MM-DD'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = timezone.make_aware(end_date.replace(hour=23, minute=59, second=59))
                queryset = queryset.filter(measured_at__lte=end_date)
            except ValueError:
                return Response(
                    {'detail': 'Invalid end_date format. Use YYYY-MM-DD'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if measurement_type:
            queryset = queryset.filter(measurement_type=measurement_type)
            
        if integration_type:
            queryset = queryset.filter(integration_type=integration_type)
        
        # Group by measurement type and calculate stats
        summary_data = []
        measurement_types = queryset.values('measurement_type').annotate(count=Count('id')).order_by('measurement_type')
        
        for item in measurement_types:
            type_measurements = queryset.filter(measurement_type=item['measurement_type'])
            latest = type_measurements.order_by('-measured_at').first()
            
            # Get aggregate statistics
            stats = type_measurements.aggregate(
                min_value=Min('value'),
                max_value=Max('value'),
                avg_value=Avg('value')
            )
            
            # Get readable display name for measurement type
            measurement_type_display = dict(WearableMeasurement.MeasurementType.choices).get(
                item['measurement_type'], item['measurement_type']
            )
            
            summary_data.append({
                'measurement_type': item['measurement_type'],
                'measurement_type_display': measurement_type_display,
                'count': item['count'],
                'latest_value': latest.value if latest else None,
                'latest_unit': latest.unit if latest else None,
                'latest_date': latest.measured_at if latest else None,
                'min_value': stats['min_value'],
                'max_value': stats['max_value'],
                'avg_value': stats['avg_value']
            })
        
        serializer = MeasurementSummarySerializer(summary_data, many=True)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'start_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                format=openapi.FORMAT_DATE, description="Start date (YYYY-MM-DD)"
            ),
            openapi.Parameter(
                'end_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                format=openapi.FORMAT_DATE, description="End date (YYYY-MM-DD)"
            ),
            openapi.Parameter(
                'measurement_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                required=True, description="Measurement type to trend"
            ),
        ],
        responses={200: WearableMeasurementSerializer(many=True)}
    )
    @action(detail=False, methods=['get'])
    def trend(self, request):
        """Get trend data for a specific measurement type."""
        queryset = self.get_queryset()
        
        # Measurement type is required
        measurement_type = request.query_params.get('measurement_type')
        if not measurement_type:
            return Response(
                {'detail': 'measurement_type parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        queryset = queryset.filter(measurement_type=measurement_type)
        
        # Apply date filters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                start_date = timezone.make_aware(start_date)
                queryset = queryset.filter(measured_at__gte=start_date)
            except ValueError:
                return Response(
                    {'detail': 'Invalid start_date format. Use YYYY-MM-DD'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = timezone.make_aware(end_date.replace(hour=23, minute=59, second=59))
                queryset = queryset.filter(measured_at__lte=end_date)
            except ValueError:
                return Response(
                    {'detail': 'Invalid end_date format. Use YYYY-MM-DD'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Order by date and return data
        queryset = queryset.order_by('measured_at')
        serializer = WearableMeasurementSerializer(queryset, many=True)
        
        return Response(serializer.data)


class WearableConnectViewSet(viewsets.ViewSet):
    """ViewSet for connecting with wearable devices."""
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'integration_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                required=True, description="Type of integration to connect"
            ),
        ],
        responses={200: IntegrationConnectSerializer}
    )
    @action(detail=False, methods=['get'])
    def connect(self, request):
        """Generate authorization URL or connection instructions for a wearable device."""
        integration_type = request.query_params.get('integration_type')
        
        if not integration_type:
            return Response(
                {'detail': 'integration_type parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if integration_type not in dict(WearableIntegration.IntegrationType.choices).keys():
            return Response(
                {'detail': f'Invalid integration_type. Must be one of: {", ".join(dict(WearableIntegration.IntegrationType.choices).keys())}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate a state token for CSRF protection
        state = str(uuid.uuid4())
        
        # Store state in session for verification later
        request.session[f'wearable_state_{integration_type}'] = state
        
        # Different connection flows for different integration types
        if integration_type == 'withings':
            return self._connect_withings(request, state)
        elif integration_type == 'fitbit':
            return self._connect_fitbit(request, state)
        elif integration_type == 'google_fit':
            return self._connect_google_fit(request, state)
        elif integration_type == 'apple_health':
            return self._connect_apple_health(request)
        elif integration_type == 'samsung_health':
            return self._connect_samsung_health(request)
        else:
            # Generic connection response for other types
            return Response(
                {
                    'integration_type': integration_type,
                    'message': f"Connection for {integration_type} is not implemented yet.",
                    'status': 'not_implemented'
                },
                status=status.HTTP_501_NOT_IMPLEMENTED
            )
    
    def _connect_withings(self, request, state):
        """Generate authorization URL for Withings OAuth."""
        # Build authorization URL
        auth_url = (
            'https://account.withings.com/oauth2_user/authorize2'
            f'?response_type=code'
            f'&client_id={settings.WITHINGS_CLIENT_ID}'
            f'&state={state}'
            f'&scope=user.metrics,user.activity'
            f'&redirect_uri={settings.WITHINGS_CALLBACK_URL}'
        )
        
        serializer = IntegrationConnectSerializer({
            'authorize_url': auth_url,
            'integration_type': 'withings',
            'status': 'ready',
            'message': 'Click the link to authorize access to your Withings account.'
        })
        return Response(serializer.data)
    
    def _connect_fitbit(self, request, state):
        """Generate authorization URL for Fitbit OAuth."""
        # Check if FITBIT_CLIENT_ID is set in settings
        if not hasattr(settings, 'FITBIT_CLIENT_ID') or not settings.FITBIT_CLIENT_ID:
            return Response(
                {
                    'integration_type': 'fitbit',
                    'message': "Fitbit integration is not configured.",
                    'status': 'not_configured'
                },
                status=status.HTTP_501_NOT_IMPLEMENTED
            )
            
        # Build authorization URL
        auth_url = (
            'https://www.fitbit.com/oauth2/authorize'
            f'?response_type=code'
            f'&client_id={settings.FITBIT_CLIENT_ID}'
            f'&state={state}'
            f'&scope=activity+heartrate+location+nutrition+profile+settings+sleep+social+weight'
            f'&redirect_uri={settings.BASE_URL}/api/wearables/callback/fitbit/'
        )
        
        serializer = IntegrationConnectSerializer({
            'authorize_url': auth_url,
            'integration_type': 'fitbit',
            'status': 'ready',
            'message': 'Click the link to authorize access to your Fitbit account.'
        })
        return Response(serializer.data)
    
    def _connect_google_fit(self, request, state):
        """Generate authorization URL for Google Fit OAuth."""
        # Check if GOOGLE_FIT_CLIENT_ID is set in settings
        if not hasattr(settings, 'GOOGLE_FIT_CLIENT_ID') or not settings.GOOGLE_FIT_CLIENT_ID:
            return Response(
                {
                    'integration_type': 'google_fit',
                    'message': "Google Fit integration is not configured.",
                    'status': 'not_configured'
                },
                status=status.HTTP_501_NOT_IMPLEMENTED
            )
            
        # Build authorization URL
        auth_url = (
            'https://accounts.google.com/o/oauth2/auth'
            f'?response_type=code'
            f'&client_id={settings.GOOGLE_FIT_CLIENT_ID}'
            f'&state={state}'
            f'&scope=https://www.googleapis.com/auth/fitness.activity.read+https://www.googleapis.com/auth/fitness.body.read+https://www.googleapis.com/auth/fitness.heart_rate.read+https://www.googleapis.com/auth/fitness.sleep.read'
            f'&redirect_uri={settings.BASE_URL}/api/wearables/callback/google_fit/'
            f'&access_type=offline'
            f'&prompt=consent'
        )
        
        serializer = IntegrationConnectSerializer({
            'authorize_url': auth_url,
            'integration_type': 'google_fit',
            'status': 'ready',
            'message': 'Click the link to authorize access to your Google Fit account.'
        })
        return Response(serializer.data)
    
    def _connect_apple_health(self, request):
        """Provide instructions for Apple Health connection."""
        # Apple Health requires app integration, can't use OAuth flow
        
        # Generate a QR code for deep linking (if mobile app is available)
        qr_code = None
        deep_link = f"klararety://connect/apple_health"
        
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(deep_link)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_code = f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"
        except Exception as e:
            logger.warning(f"Failed to generate QR code: {str(e)}")
        
        serializer = IntegrationConnectSerializer({
            'integration_type': 'apple_health',
            'connection_instructions': 'To connect Apple Health, you need to use the Klararety mobile app. Download it from the App Store and follow the instructions to connect.',
            'deep_link': deep_link,
            'qr_code': qr_code,
            'mobile_instructions': '1. Open the Klararety app\n2. Go to Settings > Connect Devices\n3. Select Apple Health\n4. Allow access to health data',
            'status': 'requires_mobile',
            'message': 'Apple Health connection requires the mobile app.'
        })
        return Response(serializer.data)
    
    def _connect_samsung_health(self, request):
        """Provide instructions for Samsung Health connection."""
        # Samsung Health requires app integration, can't use OAuth flow
        
        # Generate a QR code for deep linking (if mobile app is available)
        qr_code = None
        deep_link = f"klararety://connect/samsung_health"
        
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(deep_link)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_code = f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"
        except Exception as e:
            logger.warning(f"Failed to generate QR code: {str(e)}")
        
        serializer = IntegrationConnectSerializer({
            'integration_type': 'samsung_health',
            'connection_instructions': 'To connect Samsung Health, you need to use the Klararety mobile app. Download it from the Google Play Store and follow the instructions to connect.',
            'deep_link': deep_link,
            'qr_code': qr_code,
            'mobile_instructions': '1. Open the Klararety app\n2. Go to Settings > Connect Devices\n3. Select Samsung Health\n4. Allow access to health data',
            'status': 'requires_mobile',
            'message': 'Samsung Health connection requires the mobile app.'
        })
        return Response(serializer.data)
    
    @swagger_auto_schema(
        request_body=IntegrationCallbackSerializer,
        responses={200: WearableIntegrationSerializer}
    )
    @action(detail=False, methods=['post'])
    def callback(self, request):
        """Handle OAuth callback from wearable services."""
        serializer = IntegrationCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        integration_type = serializer.validated_data.get('integration_type')
        code = serializer.validated_data.get('code')
        state = serializer.validated_data.get('state')
        error = serializer.validated_data.get('error')
        
        # Check for errors
        if error:
            return Response(
                {'detail': f'Error from provider: {error}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify state token to prevent CSRF
        session_state = request.session.get(f'wearable_state_{integration_type}')
        if not session_state or session_state != state:
            return Response(
                {'detail': 'Invalid state parameter'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Process based on integration type
        if integration_type == 'withings':
            return self._process_withings_callback(request, code)
        elif integration_type == 'fitbit':
            return self._process_fitbit_callback(request, code)
        elif integration_type == 'google_fit':
            return self._process_google_fit_callback(request, code)
        else:
            return Response(
                {'detail': f'Callback handling for {integration_type} is not implemented'},
                status=status.HTTP_501_NOT_IMPLEMENTED
            )
    
    def _process_withings_callback(self, request, code):
        """Process callback from Withings OAuth."""
        try:
            # Exchange authorization code for tokens
            token_response = withings_service.exchange_code(code)
            
            if not token_response or 'access_token' not in token_response:
                return Response(
                    {'detail': 'Failed to exchange authorization code for tokens'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create or update the integration
            with transaction.atomic():
                integration, created = WearableIntegration.objects.update_or_create(
                    user=request.user,
                    integration_type='withings',
                    defaults={
                        'access_token': token_response.get('access_token'),
                        'refresh_token': token_response.get('refresh_token'),
                        'token_expiry': timezone.now() + timedelta(seconds=token_response.get('expires_in', 3600)),
                        'platform_user_id': token_response.get('userid', ''),
                        'status': WearableIntegration.ConnectionStatus.CONNECTED,
                        'settings': {'scopes': 'user.metrics,user.activity'}
                    }
                )
                
                # For backward compatibility, also update legacy WithingsProfile model
                WithingsProfile.objects.update_or_create(
                    user=request.user,
                    defaults={
                        'withings_user_id': token_response.get('userid', ''),
                        'access_token': token_response.get('access_token'),
                        'refresh_token': token_response.get('refresh_token'),
                        'token_expiry': timezone.now() + timedelta(seconds=token_response.get('expires_in', 3600))
                    }
                )
            
            # Return the updated integration
            serializer = WearableIntegrationSerializer(integration)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error processing Withings callback: {str(e)}")
            return Response(
                {'detail': f'Error processing Withings callback: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _process_fitbit_callback(self, request, code):
        """Process callback from Fitbit OAuth."""
        try:
            # Check if the service is configured
            if not hasattr(settings, 'FITBIT_CLIENT_ID') or not settings.FITBIT_CLIENT_ID:
                return Response(
                    {'detail': 'Fitbit integration is not configured'},
                    status=status.HTTP_501_NOT_IMPLEMENTED
                )
                
            # Exchange authorization code for tokens
            token_response = fitbit_service.exchange_code(code)
            
            if not token_response or 'access_token' not in token_response:
                return Response(
                    {'detail': 'Failed to exchange authorization code for tokens'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create or update the integration
            integration, created = WearableIntegration.objects.update_or_create(
                user=request.user,
                integration_type='fitbit',
                defaults={
                    'access_token': token_response.get('access_token'),
                    'refresh_token': token_response.get('refresh_token'),
                    'token_expiry': timezone.now() + timedelta(seconds=token_response.get('expires_in', 3600)),
                    'platform_user_id': token_response.get('user_id', ''),
                    'status': WearableIntegration.ConnectionStatus.CONNECTED,
                    'settings': {'scopes': token_response.get('scope', '')}
                }
            )
            
            # Return the updated integration
            serializer = WearableIntegrationSerializer(integration)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error processing Fitbit callback: {str(e)}")
            return Response(
                {'detail': f'Error processing Fitbit callback: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _process_google_fit_callback(self, request, code):
        """Process callback from Google Fit OAuth."""
        try:
            # Check if the service is configured
            if not hasattr(settings, 'GOOGLE_FIT_CLIENT_ID') or not settings.GOOGLE_FIT_CLIENT_ID:
                return Response(
                    {'detail': 'Google Fit integration is not configured'},
                    status=status.HTTP_501_NOT_IMPLEMENTED
                )
                
            # Exchange authorization code for tokens
            token_response = google_fit_service.exchange_code(code)
            
            if not token_response or 'access_token' not in token_response:
                return Response(
                    {'detail': 'Failed to exchange authorization code for tokens'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create or update the integration
            integration, created = WearableIntegration.objects.update_or_create(
                user=request.user,
                integration_type='google_fit',
                defaults={
                    'access_token': token_response.get('access_token'),
                    'refresh_token': token_response.get('refresh_token'),
                    'token_expiry': timezone.now() + timedelta(seconds=token_response.get('expires_in', 3600)),
                    'platform_user_id': token_response.get('user_id', ''),
                    'status': WearableIntegration.ConnectionStatus.CONNECTED,
                    'settings': {'scopes': token_response.get('scope', '')}
                }
            )
            
            # Return the updated integration
            serializer = WearableIntegrationSerializer(integration)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error processing Google Fit callback: {str(e)}")
            return Response(
                {'detail': f'Error processing Google Fit callback: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DataSyncViewSet(viewsets.ViewSet):
    """ViewSet for syncing data from wearable devices."""
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'integration_type', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                required=True, description="Type of integration to fetch data from"
            ),
            openapi.Parameter(
                'start_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                format=openapi.FORMAT_DATE, description="Start date (YYYY-MM-DD)"
            ),
            openapi.Parameter(
                'end_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, 
                format=openapi.FORMAT_DATE, description="End date (YYYY-MM-DD)"
            ),
        ],
        responses={200: IntegrationDataFetchSerializer}
    )
    @action(detail=False, methods=['post'])
    def fetch_data(self, request):
        """Fetch data from a wearable integration."""
        integration_type = request.query_params.get('integration_type')
        
        if not integration_type:
            return Response(
                {'detail': 'integration_type parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Get the integration
        try:
            integration = WearableIntegration.objects.get(
                user=request.user,
                integration_type=integration_type
            )
        except WearableIntegration.DoesNotExist:
            return Response(
                {'detail': f'{integration_type} integration not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if connected
        if not integration.is_connected():
            return Response(
                {'detail': f'{integration_type} integration is not connected'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Check for consent
        if not integration.consent_granted:
            return Response(
                {'detail': 'You need to grant consent before syncing data'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Parse date parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            except ValueError:
                return Response(
                    {'detail': 'Invalid start_date format. Use YYYY-MM-DD'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # Default to 30 days ago
            start_date = timezone.now() - timedelta(days=30)
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date.replace(hour=23, minute=59, second=59)
            except ValueError:
                return Response(
                    {'detail': 'Invalid end_date format. Use YYYY-MM-DD'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # Default to now
            end_date = timezone.now()
        
        # Make timezone-aware if needed
        if timezone.is_naive(start_date):
            start_date = timezone.make_aware(start_date)
        if timezone.is_naive(end_date):
            end_date = timezone.make_aware(end_date)
        
        # Start sync operation
        sync_start_time = timezone.now()
        sync_log = SyncLog.objects.create(
            user=request.user,
            integration_type=integration_type,
            status=SyncLog.SyncStatus.FAILED,  # Default to failed, update on success
            start_time=sync_start_time,
            end_time=sync_start_time,  # Will update when complete
            data_start_date=start_date,
            data_end_date=end_date,
        )
        
        measurements_synced = 0
        data_types_synced = []
        
        try:
            # Call the appropriate service based on integration type
            if integration_type == 'withings':
                results = self._sync_withings_data(integration, start_date, end_date)
            elif integration_type == 'fitbit':
                results = self._sync_fitbit_data(integration, start_date, end_date)
            elif integration_type == 'google_fit':
                results = self._sync_google_fit_data(integration, start_date, end_date)
            elif integration_type == 'apple_health':
                return Response(
                    {'detail': 'Apple Health sync is only available through the mobile app'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif integration_type == 'samsung_health':
                return Response(
                    {'detail': 'Samsung Health sync is only available through the mobile app'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {'detail': f'Sync for {integration_type} is not implemented'},
                    status=status.HTTP_501_NOT_IMPLEMENTED
                )
            
            # Update counters from results
            measurements_synced = results.get('measurements_synced', 0)
            data_types_synced = results.get('data_types_synced', [])
            
            # Update integration last_sync timestamp
            integration.last_sync = timezone.now()
            integration.save()
            
            # Update sync log
            sync_log.status = SyncLog.SyncStatus.SUCCESS if measurements_synced > 0 else SyncLog.SyncStatus.PARTIAL
            sync_log.measurements_synced = measurements_synced
            sync_log.details = {
                'data_types': data_types_synced,
                'success': True,
                'message': results.get('message', '')
            }
            
        except Exception as e:
            # Log the error
            logger.error(f"Error syncing {integration_type} data: {str(e)}")
            
            # Update sync log with error
            sync_log.status = SyncLog.SyncStatus.FAILED
            sync_log.error_message = str(e)
            sync_log.details = {
                'error': str(e),
                'traceback': traceback.format_exc(),
                'success': False
            }
        
        finally:
            # Complete the sync log
            sync_log.end_time = timezone.now()
            sync_log.save()
        
        # Return the results
        return Response({
            'integration_type': integration_type,
            'status': sync_log.status,
            'measurements_synced': measurements_synced,
            'data_types_synced': data_types_synced,
            'sync_started': sync_log.start_time,
            'sync_completed': sync_log.end_time,
            'duration_seconds': (sync_log.end_time - sync_log.start_time).total_seconds(),
            'message': f"Synced {measurements_synced} measurements from {integration_type}."
        })
    
    @action(detail=False, methods=['post'])
    def apple_health_sync(self, request):
        """Handle data sync from Apple Health via the mobile app."""
        # Process the incoming data using the Apple Health service
        results = apple_health_service.process_incoming_data(request.user, request.data)
        
        if results.get('success', False):
            # Update the integration's last_sync timestamp
            integration, _ = WearableIntegration.objects.get_or_create(
                user=request.user,
                integration_type='apple_health',
                defaults={
                    'status': WearableIntegration.ConnectionStatus.CONNECTED,
                    'consent_granted': True,
                    'consent_date': timezone.now()
                }
            )
            
            integration.last_sync = timezone.now()
            integration.save(update_fields=['last_sync'])
            
            # Create a sync log
            SyncLog.objects.create(
                user=request.user,
                integration_type='apple_health',
                status=SyncLog.SyncStatus.SUCCESS,
                start_time=timezone.now() - timedelta(seconds=10),  # Approximate
                end_time=timezone.now(),
                measurements_synced=results.get('records_processed', 0),
                data_start_date=timezone.now() - timedelta(days=30),  # Approximate
                data_end_date=timezone.now(),
                details={'message': results.get('message', '')}
            )
            
            return Response({
                'success': True,
                'message': results.get('message', ''),
                'records_processed': results.get('records_processed', 0)
            })
        else:
            return Response({
                'success': False,
                'message': results.get('message', 'Unknown error'),
                'records_processed': 0
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def apple_health_config(self, request):
        """Get Apple Health configuration for the mobile app."""
        config = apple_health_service.generate_mobile_config()
        return Response(config)
    
    @action(detail=False, methods=['post'])
    def samsung_health_sync(self, request):
        """Handle data sync from Samsung Health via the mobile app."""
        # Process the incoming data using the Samsung Health service
        results = samsung_health_service.process_incoming_data(request.user, request.data)
        
        if results.get('success', False):
            # Update the integration's last_sync timestamp
            integration, _ = WearableIntegration.objects.get_or_create(
                user=request.user,
                integration_type='samsung_health',
                defaults={
                    'status': WearableIntegration.ConnectionStatus.CONNECTED,
                    'consent_granted': True,
                    'consent_date': timezone.now()
                }
            )
            
            integration.last_sync = timezone.now()
            integration.save(update_fields=['last_sync'])
            
            # Create a sync log
            SyncLog.objects.create(
                user=request.user,
                integration_type='samsung_health',
                status=SyncLog.SyncStatus.SUCCESS,
                start_time=timezone.now() - timedelta(seconds=10),  # Approximate
                end_time=timezone.now(),
                measurements_synced=results.get('records_processed', 0),
                data_start_date=timezone.now() - timedelta(days=30),  # Approximate
                data_end_date=timezone.now(),
                details={'message': results.get('message', '')}
            )
            
            return Response({
                'success': True,
                'message': results.get('message', ''),
                'records_processed': results.get('records_processed', 0)
            })
        else:
            return Response({
                'success': False,
                'message': results.get('message', 'Unknown error'),
                'records_processed': 0
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def samsung_health_config(self, request):
        """Get Samsung Health configuration for the mobile app."""
        config = samsung_health_service.generate_mobile_config()
        return Response(config)
    
    def _sync_withings_data(self, integration, start_date, end_date):
        """Sync data from Withings."""
        import traceback
        measurements_synced = 0
        data_types_synced = set()
        
        # Convert dates to timestamps for Withings API
        start_timestamp = int(start_date.timestamp())
        end_timestamp = int(end_date.timestamp())
        
        # Check if token is expired and refresh if needed
        if integration.token_expiry <= timezone.now():
            success = withings_service.refresh_token(integration)
            if not success:
                raise Exception("Failed to refresh Withings token")
        
        # Collect data based on user preferences
        message = "Data sync completed"
        
        # Sync weight if enabled
        if integration.collect_weight:
            try:
                weight_data = withings_service.fetch_measure(
                    integration, 
                    'getmeas', 
                    {'meastype': 1},  # 1 = Weight
                    start_timestamp, 
                    end_timestamp
                )
                
                if weight_data and 'measuregrps' in weight_data:
                    for group in weight_data['measuregrps']:
                        for measure in group.get('measures', []):
                            if measure.get('type') == 1:  # Weight
                                # Convert to kg (Withings uses kg * 1000)
                                value = measure.get('value', 0) * (10 ** measure.get('unit', 0))
                                
                                # Save to WearableMeasurement model
                                measurement_id = f"withings_weight_{group.get('grpid')}"
                                measurement, created = WearableMeasurement.objects.update_or_create(
                                    user=integration.user,
                                    integration_type='withings',
                                    external_measurement_id=measurement_id,
                                    defaults={
                                        'measurement_type': WearableMeasurement.MeasurementType.WEIGHT,
                                        'value': value,
                                        'unit': 'kg',
                                        'measured_at': timezone.make_aware(datetime.fromtimestamp(group.get('date'))),
                                        'device_id': str(group.get('deviceid', '')),
                                        'device_model': 'Withings Scale'
                                    }
                                )
                                
                                # Save to VitalSign if not already synced
                                if not measurement.synced_to_healthcare:
                                    vital_sign, created = VitalSign.objects.update_or_create(
                                        source='withings',
                                        source_device_id=str(group.get('deviceid', '')),
                                        measured_at=timezone.make_aware(datetime.fromtimestamp(group.get('date'))),
                                        defaults={
                                            'measurement_type': 'weight',
                                            'value': str(value),
                                            'unit': 'kg',
                                            'created_by': integration.user
                                        }
                                    )
                                    
                                    # Update the measurement to mark as synced
                                    measurement.synced_to_healthcare = True
                                    measurement.healthcare_record_id = vital_sign.id
                                    measurement.save(update_fields=['synced_to_healthcare', 'healthcare_record_id'])
                                
                                if created:
                                    measurements_synced += 1
                                    
                    data_types_synced.add('weight')
            except Exception as e:
                # Log but continue with other data types
                logger.error(f"Error syncing Withings weight data: {str(e)}")
                message = f"Partial data sync: Error with weight data: {str(e)}"
        
        # Sync blood pressure if enabled
        if integration.collect_blood_pressure:
            try:
                bp_data = withings_service.fetch_measure(
                    integration, 
                    'getmeas', 
                    {'meastype': 9},  # 9 = Blood Pressure
                    start_timestamp, 
                    end_timestamp
                )
                
                if bp_data and 'measuregrps' in bp_data:
                    for group in bp_data['measuregrps']:
                        systolic = None
                        diastolic = None
                        
                        for measure in group.get('measures', []):
                            value = measure.get('value', 0) * (10 ** measure.get('unit', 0))
                            
                            if measure.get('type') == 9:  # Diastolic
                                diastolic = value
                            elif measure.get('type') == 10:  # Systolic
                                systolic = value
                        
                        if systolic and diastolic:
                            # Save to WearableMeasurement model
                            measurement_id = f"withings_bp_{group.get('grpid')}"
                            measurement, created = WearableMeasurement.objects.update_or_create(
                                user=integration.user,
                                integration_type='withings',
                                external_measurement_id=measurement_id,
                                defaults={
                                    'measurement_type': WearableMeasurement.MeasurementType.BLOOD_PRESSURE,
                                    'value': systolic,  # Store systolic as main value
                                    'unit': 'mmHg',
                                    'measured_at': timezone.make_aware(datetime.fromtimestamp(group.get('date'))),
                                    'device_id': str(group.get('deviceid', '')),
                                    'device_model': 'Withings BP Monitor',
                                    'systolic': systolic,
                                    'diastolic': diastolic,
                                    'additional_data': {
                                        'systolic': systolic,
                                        'diastolic': diastolic
                                    }
                                }
                            )
                            
                            # Save to VitalSign if not already synced
                            if not measurement.synced_to_healthcare:
                                vital_sign, created = VitalSign.objects.update_or_create(
                                    source='withings',
                                    source_device_id=str(group.get('deviceid', '')),
                                    measured_at=timezone.make_aware(datetime.fromtimestamp(group.get('date'))),
                                    defaults={
                                        'measurement_type': 'blood_pressure',
                                        'value': f"{systolic}/{diastolic}",
                                        'unit': 'mmHg',
                                        'blood_pressure': f"{systolic}/{diastolic}",
                                        'created_by': integration.user
                                    }
                                )
                                
                                # Update the measurement to mark as synced
                                measurement.synced_to_healthcare = True
                                measurement.healthcare_record_id = vital_sign.id
                                measurement.save(update_fields=['synced_to_healthcare', 'healthcare_record_id'])
                            
                            if created:
                                measurements_synced += 1
                                
                    data_types_synced.add('blood_pressure')
            except Exception as e:
                # Log but continue with other data types
                logger.error(f"Error syncing Withings blood pressure data: {str(e)}")
                message = f"Partial data sync: Error with blood pressure data: {str(e)}"
        
        # Sync heart rate if enabled
        if integration.collect_heart_rate:
            try:
                hr_data = withings_service.fetch_measure(
                    integration, 
                    'getmeas', 
                    {'meastype': 11},  # 11 = Heart Rate
                    start_timestamp, 
                    end_timestamp
                )
                
                if hr_data and 'measuregrps' in hr_data:
                    for group in hr_data['measuregrps']:
                        for measure in group.get('measures', []):
                            if measure.get('type') == 11:  # Heart Rate
                                value = measure.get('value', 0) * (10 ** measure.get('unit', 0))
                                
                                # Save to WearableMeasurement model
                                measurement_id = f"withings_hr_{group.get('grpid')}"
                                measurement, created = WearableMeasurement.objects.update_or_create(
                                    user=integration.user,
                                    integration_type='withings',
                                    external_measurement_id=measurement_id,
                                    defaults={
                                        'measurement_type': WearableMeasurement.MeasurementType.HEART_RATE,
                                        'value': value,
                                        'unit': 'bpm',
                                        'measured_at': timezone.make_aware(datetime.fromtimestamp(group.get('date'))),
                                        'device_id': str(group.get('deviceid', '')),
                                        'device_model': 'Withings Device'
                                    }
                                )
                                
                                # Save to VitalSign if not already synced
                                if not measurement.synced_to_healthcare:
                                    vital_sign, created = VitalSign.objects.update_or_create(
                                        source='withings',
                                        source_device_id=str(group.get('deviceid', '')),
                                        measured_at=timezone.make_aware(datetime.fromtimestamp(group.get('date'))),
                                        defaults={
                                            'measurement_type': 'heart_rate',
                                            'value': str(int(value)),
                                            'unit': 'bpm',
                                            'heart_rate': int(value),
                                            'created_by': integration.user
                                        }
                                    )
                                    
                                    # Update the measurement to mark as synced
                                    measurement.synced_to_healthcare = True
                                    measurement.healthcare_record_id = vital_sign.id
                                    measurement.save(update_fields=['synced_to_healthcare', 'healthcare_record_id'])
                                
                                if created:
                                    measurements_synced += 1
                                    
                    data_types_synced.add('heart_rate')
            except Exception as e:
                # Log but continue with other data types
                logger.error(f"Error syncing Withings heart rate data: {str(e)}")
                message = f"Partial data sync: Error with heart rate data: {str(e)}"
        
        # Sync sleep data if enabled
        if integration.collect_sleep:
            try:
                sleep_data = withings_service.fetch_sleep(integration, start_timestamp, end_timestamp)
                
                if sleep_data and 'series' in sleep_data:
                    for day in sleep_data.get('series', []):
                        date = timezone.make_aware(datetime.fromtimestamp(day.get('startdate')))
                        total_sleep_duration = day.get('data', {}).get('total_sleep_duration', 0)
                        
                        if total_sleep_duration > 0:
                            # Save to WearableMeasurement model
                            measurement_id = f"withings_sleep_{day.get('startdate')}"
                            measurement, created = WearableMeasurement.objects.update_or_create(
                                user=integration.user,
                                integration_type='withings',
                                external_measurement_id=measurement_id,
                                defaults={
                                    'measurement_type': WearableMeasurement.MeasurementType.SLEEP,
                                    'value': total_sleep_duration / 60,  # Convert to minutes
                                    'unit': 'min',
                                    'measured_at': date,
                                    'device_id': 'sleep_tracker',
                                    'device_model': 'Withings Sleep',
                                    'additional_data': day.get('data', {})
                                }
                            )
                            
                            # Save to VitalSign if not already synced
                            if not measurement.synced_to_healthcare:
                                vital_sign, created = VitalSign.objects.update_or_create(
                                    source='withings',
                                    source_device_id='sleep_tracker',
                                    measured_at=date,
                                    defaults={
                                        'measurement_type': 'sleep',
                                        'value': str(int(total_sleep_duration / 60)),
                                        'unit': 'min',
                                        'created_by': integration.user
                                    }
                                )
                                
                                # Update the measurement to mark as synced
                                measurement.synced_to_healthcare = True
                                measurement.healthcare_record_id = vital_sign.id
                                measurement.save(update_fields=['synced_to_healthcare', 'healthcare_record_id'])
                            
                            if created:
                                measurements_synced += 1
                                
                    data_types_synced.add('sleep')
            except Exception as e:
                # Log but continue with other data types
                logger.error(f"Error syncing Withings sleep data: {str(e)}")
                message = f"Partial data sync: Error with sleep data: {str(e)}"
        
        # Sync activity data (steps) if enabled
        if integration.collect_steps:
            try:
                activity_data = withings_service.fetch_activity(integration, start_timestamp, end_timestamp)
                
                if activity_data and 'activities' in activity_data:
                    for activity in activity_data.get('activities', []):
                        date = timezone.make_aware(datetime.fromtimestamp(activity.get('date')))
                        steps = activity.get('steps', 0)
                        
                        if steps > 0:
                            # Save to WearableMeasurement model
                            measurement_id = f"withings_steps_{activity.get('date')}"
                            measurement, created = WearableMeasurement.objects.update_or_create(
                                user=integration.user,
                                integration_type='withings',
                                external_measurement_id=measurement_id,
                                defaults={
                                    'measurement_type': WearableMeasurement.MeasurementType.STEPS,
                                    'value': steps,
                                    'unit': 'steps',
                                    'measured_at': date,
                                    'device_id': 'activity_tracker',
                                    'device_model': 'Withings Activity Tracker',
                                    'additional_data': {
                                        'calories': activity.get('calories', 0),
                                        'distance': activity.get('distance', 0),
                                        'elevation': activity.get('elevation', 0),
                                        'active_calories': activity.get('active_calories', 0)
                                    }
                                }
                            )
                            
                            # Save to VitalSign if not already synced
                            if not measurement.synced_to_healthcare:
                                vital_sign, created = VitalSign.objects.update_or_create(
                                    source='withings',
                                    source_device_id='activity_tracker',
                                    measured_at=date,
                                    defaults={
                                        'measurement_type': 'steps',
                                        'value': str(steps),
                                        'unit': 'steps',
                                        'created_by': integration.user
                                    }
                                )
                                
                                # Update the measurement to mark as synced
                                measurement.synced_to_healthcare = True
                                measurement.healthcare_record_id = vital_sign.id
                                measurement.save(update_fields=['synced_to_healthcare', 'healthcare_record_id'])
                            
                            if created:
                                measurements_synced += 1
                                
                    data_types_synced.add('steps')
            except Exception as e:
                # Log but continue with other data types
                logger.error(f"Error syncing Withings activity data: {str(e)}")
                message = f"Partial data sync: Error with activity data: {str(e)}"
        
        return {
            'measurements_synced': measurements_synced,
            'data_types_synced': list(data_types_synced),
            'message': message
        }
    
    def _sync_fitbit_data(self, integration, start_date, end_date):
        """Sync data from Fitbit."""
        # This would be implemented similar to the Withings sync above
        # but using the Fitbit API endpoints and data formats
        
        # For now, return a placeholder
        return {
            'measurements_synced': 0,
            'data_types_synced': [],
            'message': 'Fitbit data sync not implemented'
        }
    
    def _sync_google_fit_data(self, integration, start_date, end_date):
        """Sync data from Google Fit."""
        # This would be implemented similar to the Withings sync above
        # but using the Google Fit API endpoints and data formats
        
        # For now, return a placeholder
        return {
            'measurements_synced': 0,
            'data_types_synced': [],
            'message': 'Google Fit data sync not implemented'
        }

class LegacyWithingsViewSet(viewsets.ViewSet):
    """Legacy ViewSet for Withings integration."""
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(operation_summary="Get Withings profile", responses={200: WithingsProfileSerializer})
    @action(detail=False, methods=['get'])
    def profile(self, request):
        """Get Withings profile for the current user."""
        try:
            profile = WithingsProfile.objects.get(user=request.user)
            serializer = WithingsProfileSerializer(profile)
            return Response(serializer.data)
        except WithingsProfile.DoesNotExist:
            return Response(
                {'detail': 'Withings profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @swagger_auto_schema(
        operation_summary="Generate Withings authorization URL",
        responses={200: IntegrationConnectSerializer}
    )
    @action(detail=False, methods=['get'])
    def connect(self, request):
        """Generate authorization URL for Withings OAuth."""
        # Forward to new connect endpoint
        connect_viewset = WearableConnectViewSet()
        connect_viewset.request = request
        
        # Generate state token for CSRF protection
        state = str(uuid.uuid4())
        request.session['wearable_state_withings'] = state
        
        return connect_viewset._connect_withings(request, state)
    
    @swagger_auto_schema(
        operation_summary="Process Withings callback",
        request_body=IntegrationCallbackSerializer,
        responses={200: WithingsProfileSerializer}
    )
    @action(detail=False, methods=['post'])
    def callback(self, request):
        """Legacy handler for Withings OAuth callback."""
        # Forward to new callback endpoint with appropriate data
        connect_viewset = WearableConnectViewSet()
        connect_viewset.request = request
        
        # Extract callback data
        code = request.data.get('code')
        state = request.data.get('state')
        
        # Verify state token
        session_state = request.session.get('wearable_state_withings')
        if not session_state or session_state != state:
            return Response(
                {'detail': 'Invalid state parameter'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Process the callback
        response = connect_viewset._process_withings_callback(request, code)
        
        # If successful, return legacy format
        if response.status_code == 200:
            try:
                # Get the legacy profile
                profile = WithingsProfile.objects.get(user=request.user)
                serializer = WithingsProfileSerializer(profile)
                return Response(serializer.data)
            except WithingsProfile.DoesNotExist:
                return Response(response.data)
        
        return response
    
    @swagger_auto_schema(
        operation_summary="Fetch Withings data",
        responses={200: IntegrationDataFetchSerializer}
    )
    @action(detail=False, methods=['get'])
    def fetch_data(self, request):
        """Legacy endpoint to fetch Withings data."""
        # Forward to new fetch data endpoint
        sync_viewset = DataSyncViewSet()
        sync_viewset.request = request
        
        # Check if profile exists
        try:
            profile = WithingsProfile.objects.get(user=request.user)
        except WithingsProfile.DoesNotExist:
            return Response(
                {'detail': 'Withings profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if integration exists, if not create it
        try:
            integration = WearableIntegration.objects.get(
                user=request.user,
                integration_type='withings'
            )
        except WearableIntegration.DoesNotExist:
            # Migrate legacy profile to new integration
            integration = WearableIntegration.objects.create(
                user=request.user,
                integration_type='withings',
                access_token=profile.access_token,
                refresh_token=profile.refresh_token,
                token_expiry=profile.token_expiry,
                platform_user_id=profile.withings_user_id,
                status=WearableIntegration.ConnectionStatus.CONNECTED if profile.is_connected() 
                        else WearableIntegration.ConnectionStatus.EXPIRED,
                consent_granted=True,
                consent_date=profile.created_at,
                last_sync=profile.updated_at
            )
        
        # Set query parameters for the fetch_data method
        request.query_params = {
            'integration_type': 'withings'
        }
        
        # Call the fetch_data method
        return sync_viewset.fetch_data(request)
