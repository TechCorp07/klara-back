from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from wearables.models import WearableIntegration
from wearables.services.notification_service import WearableNotificationService

User = get_user_model()

class Command(BaseCommand):
    help = 'Test smartwatch notifications'

    def add_arguments(self, parser):
        parser.add_argument('--user-id', type=int, default=2, help='User ID to test')

    def handle(self, *args, **options):
        user_id = options['user_id']
        
        try:
            user = User.objects.get(id=user_id)
            self.stdout.write(f"Testing smartwatch notifications for: {user.email}")
            
            # Check for wearable integrations using correct field names
            integrations = WearableIntegration.objects.filter(
                user=user, 
                status='connected'  # Use status instead of is_active
            )
            self.stdout.write(f"Found {integrations.count()} active wearable integrations")
            
            for integration in integrations:
                device_name = integration.settings.get('device_name', 'Unknown Device')
                self.stdout.write(f"- {integration.integration_type}: {device_name}")
            
            # Test appointment reminder via smartwatch
            if integrations.exists():
                success = WearableNotificationService.send_appointment_reminder(
                    user=user,
                    title="Test Appointment Reminder",
                    message="This is a test appointment reminder sent to your smartwatch",
                    appointment_id=1,
                    scheduled_time="2025-08-08T07:12:00Z"
                )
                
                if success:
                    self.stdout.write(self.style.SUCCESS('✅ Smartwatch notification test passed'))
                else:
                    self.stdout.write(self.style.WARNING('⚠️ Smartwatch notification test failed'))
            else:
                self.stdout.write(self.style.WARNING('⚠️ No active smartwatch integrations found'))
            
            # Test medication reminder via smartwatch (for rare disease patients)
            if integrations.exists():
                med_success = WearableNotificationService.send_medication_reminder(
                    user=user,
                    title="Test Medication Reminder",
                    message="Time to take your rare disease medication",
                    medication_id=1,
                    is_critical=True
                )
                
                if med_success:
                    self.stdout.write(self.style.SUCCESS('✅ Medication smartwatch notification test passed'))
                else:
                    self.stdout.write(self.style.WARNING('⚠️ Medication smartwatch notification test failed'))
            
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User {user_id} not found'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Test failed: {str(e)}'))
            import traceback
            self.stdout.write(traceback.format_exc())
