from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from telemedicine.models import Appointment

User = get_user_model()

class Command(BaseCommand):
    help = 'Create sample appointments for testing'

    def handle(self, *args, **options):
        # Get the patient user (ID=2 from your logs)
        try:
            patient = User.objects.get(id=2, role='patient')
            self.stdout.write(f"Found patient: {patient.email}")
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR('Patient with ID=2 not found'))
            return

        # Get or create a provider
        provider, created = User.objects.get_or_create(
            email='provider@example.com',
            defaults={
                'role': 'provider',
                'first_name': 'Dr. Sarah',
                'last_name': 'Johnson',
                'is_approved': True
            }
        )
        
        if created:
            self.stdout.write(f"Created provider: {provider.email}")
        else:
            self.stdout.write(f"Found provider: {provider.email}")

        # Create sample appointments
        appointments_data = [
            {
                'scheduled_time': timezone.now() + timedelta(days=7, hours=10),
                'end_time': timezone.now() + timedelta(days=7, hours=10, minutes=30),
                'appointment_type': 'video_consultation',
                'status': 'scheduled',
                'reason': 'Follow-up consultation for rare disease management',
                'priority': 'routine'
            },
            {
                'scheduled_time': timezone.now() + timedelta(days=14, hours=14),
                'end_time': timezone.now() + timedelta(days=14, hours=14, minutes=45),
                'appointment_type': 'initial_consultation',
                'status': 'confirmed',
                'reason': 'Initial assessment for NMOSD symptoms',
                'priority': 'urgent'
            },
            {
                'scheduled_time': timezone.now() + timedelta(days=21, hours=9),
                'end_time': timezone.now() + timedelta(days=21, hours=9, minutes=30),
                'appointment_type': 'follow_up',
                'status': 'scheduled',
                'reason': 'Medication effectiveness review',
                'priority': 'routine'
            }
        ]

        created_count = 0
        for apt_data in appointments_data:
            appointment, created = Appointment.objects.get_or_create(
                patient=patient,
                provider=provider,
                scheduled_time=apt_data['scheduled_time'],
                defaults=apt_data
            )
            
            if created:
                created_count += 1
                self.stdout.write(f"Created appointment: {appointment}")

        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {created_count} sample appointments')
        )
