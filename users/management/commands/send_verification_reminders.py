from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from users.models import PatientProfile
from users.utils import EmailService

class Command(BaseCommand):
    help = 'Send identity verification reminders to patients'
    
    def handle(self, *args, **options):
        # Find patients who need verification reminders
        reminder_date = timezone.now() - timedelta(days=25)  # 5 days before deadline
        
        patients_to_remind = PatientProfile.objects.filter(
            identity_verified=False,
            first_login_date__isnull=False,
            first_login_date__lte=reminder_date,
            verification_deadline_notified=False
        )
        
        count = 0
        for patient in patients_to_remind:
            try:
                EmailService.send_identity_verification_reminder(patient)
                patient.verification_deadline_notified = True
                patient.save()
                count += 1
            except Exception as e:
                self.stderr.write(f'Failed to send reminder to {patient.user.email}: {str(e)}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Sent {count} verification reminders')
        )

