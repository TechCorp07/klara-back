from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from wearables.models import WearableIntegration

User = get_user_model()

class Command(BaseCommand):
    help = 'Create sample wearable integration for testing'

    def handle(self, *args, **options):
        try:
            # Get the patient user
            patient = User.objects.get(id=2, role='patient')
            
            # Create sample Apple Watch integration
            apple_watch, created = WearableIntegration.objects.get_or_create(
                user=patient,
                integration_type='apple_watch',
                defaults={
                    'device_name': 'Apple Watch Series 9',
                    'platform_user_id': 'test_device_token_123',
                    'is_active': True,
                    'sync_enabled': True,
                    'notification_enabled': True,
                }
            )
            
            if created:
                self.stdout.write(self.style.SUCCESS(f'✅ Created Apple Watch integration for {patient.email}'))
            else:
                self.stdout.write(f'Apple Watch integration already exists for {patient.email}')
            
            # Update patient profile to enable smartwatch integration
            if hasattr(patient, 'patient_profile'):
                patient.patient_profile.smartwatch_integration_active = True
                patient.patient_profile.save()
                self.stdout.write(self.style.SUCCESS('✅ Enabled smartwatch integration in patient profile'))
            
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR('Patient user not found'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
