from django.utils import timezone
from datetime import datetime, timedelta
from medication.models import Medication, MedicationReminder
from users.models import User

class MedicationNotificationService:
    """Service for handling medication reminder notifications."""
    
    @classmethod
    def create_medication_reminders(cls, medication_id: str, patient_id: str):
        """Create reminders for a medication."""
        try:
            medication = Medication.objects.get(id=medication_id, medical_record__patient_id=patient_id)
            
            # Parse medication timing
            if medication.specific_times:
                times = medication.specific_times
            else:
                # Default times based on frequency
                if medication.times_per_frequency == 1:
                    times = ["08:00"]
                elif medication.times_per_frequency == 2:
                    times = ["08:00", "20:00"]
                elif medication.times_per_frequency == 3:
                    times = ["08:00", "14:00", "20:00"]
                else:
                    times = ["08:00"]
            
            # Create reminders for each time
            for time_str in times:
                MedicationReminder.objects.create(
                    medication=medication,
                    patient=medication.medical_record.patient,
                    reminder_time=time_str,
                    is_active=True,
                    notification_methods=['email', 'sms']  # Configure as needed
                )
                
            return True
        except Exception as e:
            print(f"Error creating medication reminders: {e}")
            return False
