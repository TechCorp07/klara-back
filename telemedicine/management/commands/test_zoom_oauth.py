from django.core.management.base import BaseCommand
from telemedicine.services.zoom_service import test_zoom_connection, create_zoom_meeting
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Test Zoom OAuth integration'

    def handle(self, *args, **options):
        # Test connection
        self.stdout.write("Testing Zoom OAuth connection...")
        result = test_zoom_connection()
        
        if result['status'] == 'success':
            self.stdout.write(
                self.style.SUCCESS(f"✅ Connection successful: {result['zoom_user']}")
            )
            
            # Test meeting creation
            try:
                self.stdout.write("Testing meeting creation...")
                meeting_data = create_zoom_meeting(
                    topic="Test Healthcare Meeting",
                    start_time=timezone.now() + timedelta(hours=1),
                    duration_minutes=30
                )
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✅ Meeting created successfully!\n"
                        f"Meeting ID: {meeting_data['meeting_id']}\n"
                        f"Join URL: {meeting_data['join_url']}"
                    )
                )
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"❌ Meeting creation failed: {str(e)}")
                )
        else:
            self.stdout.write(
                self.style.ERROR(f"❌ Connection failed: {result['message']}")
            )
