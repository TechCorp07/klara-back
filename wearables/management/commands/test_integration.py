import logging
import json
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from wearables.models import WearableIntegration
from wearables.services import (
    withings_service, apple_health_service, google_fit_service,
    samsung_health_service, fitbit_service
)

User = get_user_model()
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Test wearable integration connections and API endpoints'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user_id',
            type=int,
            help='Test integration only for the specified user ID',
        )
        
        parser.add_argument(
            '--username',
            type=str,
            help='Test integration only for the specified username',
        )
        
        parser.add_argument(
            '--integration_type',
            type=str,
            choices=dict(WearableIntegration.IntegrationType.choices).keys(),
            help='Test only the specified integration type',
        )
        
        parser.add_argument(
            '--debug',
            action='store_true',
            help='Show detailed API responses for debugging',
        )

    def handle(self, *args, **options):
        user_id = options.get('user_id')
        username = options.get('username')
        integration_type = options.get('integration_type')
        debug = options.get('debug', False)
        
        # Build queryset for integrations
        integrations = WearableIntegration.objects.filter(
            status=WearableIntegration.ConnectionStatus.CONNECTED
        )
        
        # Apply filters if provided
        if user_id:
            integrations = integrations.filter(user_id=user_id)
            
        if username:
            integrations = integrations.filter(user__username=username)
            
        if integration_type:
            integrations = integrations.filter(integration_type=integration_type)
        
        if not integrations.exists():
            self.stdout.write(self.style.WARNING('No matching wearable integrations found.'))
            return
        
        self.stdout.write(f"Testing {integrations.count()} wearable integrations.")
        
        # Test each integration
        for integration in integrations:
            integration_name = f"{integration.get_integration_type_display()} for {integration.user.username}"
            self.stdout.write(f"\n==== Testing {integration_name} ====")
            
            # Check connection status
            is_connected = integration.is_connected()
            if is_connected:
                self.stdout.write(self.style.SUCCESS(f"✓ Connection status: Connected"))
            else:
                self.stdout.write(self.style.ERROR(f"✗ Connection status: Not connected"))
                continue
            
            # Check token expiry
            if integration.token_expiry:
                if integration.token_expiry > timezone.now():
                    time_left = integration.token_expiry - timezone.now()
                    self.stdout.write(self.style.SUCCESS(
                        f"✓ Token valid for {time_left.total_seconds() / 3600:.1f} more hours"
                    ))
                else:
                    self.stdout.write(self.style.ERROR(f"✗ Token expired"))
                    
                    # Try refreshing token
                    self.stdout.write("Attempting to refresh token...")
                    try:
                        if integration.integration_type == 'withings':
                            success = withings_service.refresh_token(integration)
                        elif integration.integration_type == 'fitbit':
                            success = fitbit_service.refresh_token(integration)
                        elif integration.integration_type == 'google_fit':
                            success = google_fit_service.refresh_token(integration)
                        else:
                            self.stdout.write(self.style.WARNING(
                                f"Token refresh not implemented for {integration.integration_type}"
                            ))
                            continue
                            
                        if success:
                            self.stdout.write(self.style.SUCCESS(f"✓ Token refreshed successfully"))
                        else:
                            self.stdout.write(self.style.ERROR(f"✗ Failed to refresh token"))
                            continue
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"✗ Error refreshing token: {str(e)}"))
                        continue
            
            # Test API endpoints based on integration type
            if integration.integration_type == 'withings':
                self._test_withings_api(integration, debug)
            elif integration.integration_type == 'fitbit':
                self._test_fitbit_api(integration, debug)
            elif integration.integration_type == 'google_fit':
                self._test_google_fit_api(integration, debug)
            else:
                self.stdout.write(self.style.WARNING(
                    f"API testing not implemented for {integration.integration_type}"
                ))
    
    def _test_withings_api(self, integration, debug):
        """Test Withings API endpoints"""
        self.stdout.write("\nTesting Withings API endpoints:")
        
        # Test measure endpoint (weight)
        self.stdout.write("1. Testing weight measurement endpoint...")
        try:
            # Get last 7 days of weight data
            start_date = int((timezone.now() - timezone.timedelta(days=7)).timestamp())
            end_date = int(timezone.now().timestamp())
            
            weight_data = withings_service.fetch_measure(
                integration, 
                'getmeas', 
                {'meastype': 1},  # 1 = Weight
                start_date, 
                end_date
            )
            
            if weight_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched weight data"))
                if debug:
                    self.stdout.write(json.dumps(weight_data, indent=2))
                
                measurement_count = len(weight_data.get('measuregrps', []))
                self.stdout.write(f"  Found {measurement_count} weight measurements")
            else:
                self.stdout.write(self.style.WARNING(f"! No weight data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching weight data: {str(e)}"))
        
        # Test sleep endpoint
        self.stdout.write("\n2. Testing sleep endpoint...")
        try:
            # Get last 7 days of sleep data
            start_date = int((timezone.now() - timezone.timedelta(days=7)).timestamp())
            end_date = int(timezone.now().timestamp())
            
            sleep_data = withings_service.fetch_sleep(integration, start_date, end_date)
            
            if sleep_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched sleep data"))
                if debug:
                    self.stdout.write(json.dumps(sleep_data, indent=2))
                
                sleep_records = len(sleep_data.get('series', []))
                self.stdout.write(f"  Found {sleep_records} sleep records")
            else:
                self.stdout.write(self.style.WARNING(f"! No sleep data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching sleep data: {str(e)}"))
        
        # Test activity endpoint
        self.stdout.write("\n3. Testing activity endpoint...")
        try:
            # Get last 7 days of activity data
            start_date = int((timezone.now() - timezone.timedelta(days=7)).timestamp())
            end_date = int(timezone.now().timestamp())
            
            activity_data = withings_service.fetch_activity(integration, start_date, end_date)
            
            if activity_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched activity data"))
                if debug:
                    self.stdout.write(json.dumps(activity_data, indent=2))
                
                activity_records = len(activity_data.get('activities', []))
                self.stdout.write(f"  Found {activity_records} activity records")
            else:
                self.stdout.write(self.style.WARNING(f"! No activity data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching activity data: {str(e)}"))
    
    def _test_fitbit_api(self, integration, debug):
        """Test Fitbit API endpoints"""
        self.stdout.write("\nTesting Fitbit API endpoints:")
        
        # Test profile endpoint
        self.stdout.write("1. Testing profile endpoint...")
        try:
            profile_data = fitbit_service.fetch_profile(integration)
            
            if profile_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched profile data"))
                if debug:
                    self.stdout.write(json.dumps(profile_data, indent=2))
                
                self.stdout.write(f"  User: {profile_data.get('fullName', 'N/A')}")
            else:
                self.stdout.write(self.style.WARNING(f"! No profile data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching profile data: {str(e)}"))
        
        # Test activities endpoint
        self.stdout.write("\n2. Testing activities endpoint...")
        try:
            # Get today's activity data
            today = timezone.now().date()
            
            activities_data = fitbit_service.fetch_activities(integration, today)
            
            if activities_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched activities data"))
                if debug:
                    self.stdout.write(json.dumps(activities_data, indent=2))
                
                steps = activities_data.get('summary', {}).get('steps', 0)
                self.stdout.write(f"  Steps today: {steps}")
            else:
                self.stdout.write(self.style.WARNING(f"! No activities data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching activities data: {str(e)}"))
        
        # Test heart rate endpoint
        self.stdout.write("\n3. Testing heart rate endpoint...")
        try:
            # Get today's heart rate data
            today = timezone.now().date()
            
            hr_data = fitbit_service.fetch_heart_rate(integration, today)
            
            if hr_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched heart rate data"))
                if debug:
                    self.stdout.write(json.dumps(hr_data, indent=2))
                
                hr_zones = hr_data.get('activities-heart', [{}])[0].get('value', {}).get('heartRateZones', [])
                zone_info = ", ".join([f"{z.get('name')}: {z.get('minutes', 0)}min" for z in hr_zones])
                self.stdout.write(f"  Heart rate zones: {zone_info}")
            else:
                self.stdout.write(self.style.WARNING(f"! No heart rate data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching heart rate data: {str(e)}"))
    
    def _test_google_fit_api(self, integration, debug):
        """Test Google Fit API endpoints"""
        self.stdout.write("\nTesting Google Fit API endpoints:")
        
        # Test steps endpoint
        self.stdout.write("1. Testing steps endpoint...")
        try:
            # Get last 7 days of step data
            start_time = timezone.now() - timezone.timedelta(days=7)
            end_time = timezone.now()
            
            steps_data = google_fit_service.fetch_steps(integration, start_time, end_time)
            
            if steps_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched steps data"))
                if debug:
                    self.stdout.write(json.dumps(steps_data, indent=2))
                
                buckets = steps_data.get('bucket', [])
                self.stdout.write(f"  Found {len(buckets)} days of step data")
            else:
                self.stdout.write(self.style.WARNING(f"! No steps data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching steps data: {str(e)}"))
        
        # Test heart rate endpoint
        self.stdout.write("\n2. Testing heart rate endpoint...")
        try:
            # Get last 7 days of heart rate data
            start_time = timezone.now() - timezone.timedelta(days=7)
            end_time = timezone.now()
            
            hr_data = google_fit_service.fetch_heart_rate(integration, start_time, end_time)
            
            if hr_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched heart rate data"))
                if debug:
                    self.stdout.write(json.dumps(hr_data, indent=2))
                
                buckets = hr_data.get('bucket', [])
                self.stdout.write(f"  Found {len(buckets)} buckets of heart rate data")
            else:
                self.stdout.write(self.style.WARNING(f"! No heart rate data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching heart rate data: {str(e)}"))
        
        # Test weight endpoint
        self.stdout.write("\n3. Testing weight endpoint...")
        try:
            # Get last 30 days of weight data
            start_time = timezone.now() - timezone.timedelta(days=30)
            end_time = timezone.now()
            
            weight_data = google_fit_service.fetch_weight(integration, start_time, end_time)
            
            if weight_data:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully fetched weight data"))
                if debug:
                    self.stdout.write(json.dumps(weight_data, indent=2))
                
                buckets = weight_data.get('bucket', [])
                self.stdout.write(f"  Found {len(buckets)} weight records")
            else:
                self.stdout.write(self.style.WARNING(f"! No weight data returned"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error fetching weight data: {str(e)}"))
