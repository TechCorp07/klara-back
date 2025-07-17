from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from users.models import TemporaryRegistrationData, EmergencyAccess

class Command(BaseCommand):
    help = 'Clean up expired temporary data'
    
    def handle(self, *args, **options):
        # Clean up temporary registration data older than 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        
        deleted_temp_data = TemporaryRegistrationData.objects.filter(
            created_at__lt=cutoff_date
        ).count()
        
        TemporaryRegistrationData.objects.filter(
            created_at__lt=cutoff_date
        ).delete()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Cleaned up {deleted_temp_data} expired temporary registration records'
            )
        )
