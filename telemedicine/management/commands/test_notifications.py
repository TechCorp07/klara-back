from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from telemedicine.models import Appointment
from telemedicine.services.notifications_service import telemedicine_notifications
from communication.services import NotificationService

User = get_user_model()

class Command(BaseCommand):
    help = 'Test appointment notifications'

    def add_arguments(self, parser):
        parser.add_argument('--appointment-id', type=int, help='Specific appointment ID to test')
        parser.add_argument('--user-id', type=int, help='User ID to test notifications for')

    def handle(self, *args, **options):
        appointment_id = options.get('appointment_id')
        user_id = options.get('user_id')

        if appointment_id:
            # Test specific appointment
            try:
                appointment = Appointment.objects.get(id=appointment_id)
                self.stdout.write(f"Testing notifications for appointment: {appointment}")
                
                # Test confirmation notification
                success = telemedicine_notifications.send_appointment_confirmation(appointment)
                if success:
                    self.stdout.write(self.style.SUCCESS('✅ Confirmation notification sent'))
                else:
                    self.stdout.write(self.style.ERROR('❌ Confirmation notification failed'))
                
                # Test reminder notification
                reminder_success = telemedicine_notifications.send_appointment_reminder(appointment)
                if reminder_success:
                    self.stdout.write(self.style.SUCCESS('✅ Reminder notification sent'))
                else:
                    self.stdout.write(self.style.ERROR('❌ Reminder notification failed'))
                    
            except Appointment.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Appointment {appointment_id} not found'))
        
        elif user_id:
            # Test all appointments for user
            try:
                user = User.objects.get(id=user_id)
                appointments = Appointment.objects.filter(patient=user)
                
                self.stdout.write(f"Found {appointments.count()} appointments for {user.email}")
                
                for appointment in appointments:
                    self.stdout.write(f"Testing appointment {appointment.id}: {appointment}")
                    success = telemedicine_notifications.send_appointment_reminder(appointment)
                    if success:
                        self.stdout.write(self.style.SUCCESS(f'✅ Reminder sent for appointment {appointment.id}'))
                    else:
                        self.stdout.write(self.style.ERROR(f'❌ Reminder failed for appointment {appointment.id}'))
                        
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'User {user_id} not found'))
        
        else:
            # Test with latest appointment
            latest_appointment = Appointment.objects.filter(status='scheduled').first()
            if latest_appointment:
                self.stdout.write(f"Testing with latest appointment: {latest_appointment}")
                success = telemedicine_notifications.send_appointment_reminder(latest_appointment)
                if success:
                    self.stdout.write(self.style.SUCCESS('✅ Test reminder sent'))
                else:
                    self.stdout.write(self.style.ERROR('❌ Test reminder failed'))
            else:
                self.stdout.write(self.style.WARNING('No scheduled appointments found'))

        # Test basic notification service
        self.stdout.write("\n🔍 Testing basic notification service...")
        try:
            notification_service = NotificationService()
            patient = User.objects.get(role='patient', email='patient@example.com')
            
            # Test push notification
            push_success = notification_service.send_push_notification(
                user=patient,
                title="Test Notification",
                message="This is a test notification from the appointment system",
                data={'type': 'test', 'timestamp': 'now'}
            )
            
            if push_success:
                self.stdout.write(self.style.SUCCESS('✅ Push notification test passed'))
            else:
                self.stdout.write(self.style.WARNING('⚠️ Push notification test returned False (might be expected if no push service configured)'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Notification service test failed: {str(e)}'))
