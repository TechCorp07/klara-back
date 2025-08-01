from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from telemedicine.models import Appointment
from telemedicine.services.notifications_service import telemedicine_notifications
from communication.services.notification_service import NotificationService, send_email_notification

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
            
            # Test in-app notification creation
            notification = notification_service.create_notification(
                user=patient,
                title="Test Notification",
                message="This is a test notification from the appointment system",
                notification_type='test',
                related_object_id='test',  
                related_object_type='system'
            )
            
            if notification:
                self.stdout.write(self.style.SUCCESS('✅ In-app notification test passed'))
            else:
                self.stdout.write(self.style.ERROR('❌ In-app notification test failed'))
            
            # Test email notification
            try:
                send_email_notification(
                    user=patient,
                    title="Test Email Notification",
                    message="This is a test email notification",
                    notification_type='test'
                )
                self.stdout.write(self.style.SUCCESS('✅ Email notification test passed'))
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'⚠️ Email notification test failed: {str(e)} (might be expected if email not configured)'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Notification service test failed: {str(e)}'))
